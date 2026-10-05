"""Desired state: loading it, validating it, and comparing it to a console.

Ownership model. `site.yaml` carries a `managed:` block naming, per resource
type, the objects this tool is allowed to write. An object's presence in a
YAML file is *not* sufficient -- it must also be listed as managed. The
duplication is deliberate. This tool can sever the path it is administered
over, so requiring a second, explicit signature on "yes, you may write this"
is cheap next to what a typo in a name field would otherwise buy: a silent
create of a near-duplicate firewall policy.

Everything on the console outside the managed set is read, reported, and left
alone.
"""

from __future__ import annotations

import json
import os

import yaml

from . import diff as diffmod
from . import resources as res

SCHEMA_DIR = os.path.join(os.path.dirname(__file__), "schema")


class ConfigError(RuntimeError):
    """The YAML is wrong in a way we can name."""


# ---- loading -------------------------------------------------------------


def load_yaml(path):
    with open(path) as handle:
        data = yaml.safe_load(handle)
    return data if data is not None else {}


def load_site(config_dir):
    """Read site.yaml plus every per-resource file that exists.

    A missing resource file means "nothing declared for this type", not an
    error -- a site can adopt resource types one at a time, and a type with no
    file should report the console's objects as unmanaged rather than refuse
    to run.
    """
    site_path = os.path.join(config_dir, "site.yaml")
    if not os.path.exists(site_path):
        raise ConfigError(f"No site.yaml in {config_dir}")

    site = load_yaml(site_path)
    for required in ("console", "managed"):
        if required not in site:
            raise ConfigError(f"site.yaml is missing the '{required}' block")

    unknown = set(site["managed"]) - set(res.all_keys())
    if unknown:
        raise ConfigError(
            f"site.yaml managed: names unknown resource types: "
            f"{', '.join(sorted(unknown))}. Known: {', '.join(res.all_keys())}"
        )

    desired = {}
    for key in res.all_keys():
        resource = res.get(key)
        path = os.path.join(config_dir, resource.yaml_file)
        if not os.path.exists(path):
            desired[key] = []
            continue
        data = load_yaml(path)
        items = data.get(key, data.get(resource.path, []))
        if not isinstance(items, list):
            raise ConfigError(
                f"{resource.yaml_file}: expected a top-level '{key}:' list"
            )
        desired[key] = items

    return site, desired


#: Keys the tool understands that are not part of any API body. Stripped before
#: comparison and before any write, the same way underscore keys are.
#:
#: `placement` says which side of a zone-pair's system-defined policy a user
#: policy is evaluated on. It drives the ordering endpoint, which is a separate
#: call, so sending it inside a policy body would at best be ignored and at
#: worst rejected.
TOOL_ONLY_KEYS = {"placement"}


def strip_comments(value):
    """Drop underscore-prefixed keys and tool-only keys, recursively.

    `_comment` lets the YAML carry a note for a reader without the tool
    trying to PUT it. Zones and networks have no description field in the API,
    so an unstripped comment would be sent and rejected -- or worse, accepted
    and silently ignored, which would make it show as permanent drift.
    """
    if isinstance(value, list):
        return [strip_comments(v) for v in value]
    if isinstance(value, dict):
        return {
            k: strip_comments(v)
            for k, v in value.items()
            if not k.startswith("_") and k not in TOOL_ONLY_KEYS
        }
    return value


def validate(desired, strict=True):
    """Validate each resource list against its JSON Schema, when one exists.

    Schemas are the contract every site's YAML is held to, which is why they
    live with the tool rather than with any one site's state.
    """
    try:
        import jsonschema
    except ImportError:
        if strict:
            raise ConfigError(
                "jsonschema is not installed; pip install jsonschema"
            ) from None
        return []

    problems = []
    for key, items in desired.items():
        schema_path = os.path.join(SCHEMA_DIR, f"{key}.schema.json")
        if not os.path.exists(schema_path) or not items:
            continue
        with open(schema_path) as handle:
            schema = json.load(handle)
        validator = jsonschema.Draft202012Validator(schema)
        for item in items:
            for error in sorted(validator.iter_errors(item), key=str):
                where = ".".join(str(p) for p in error.absolute_path) or "(root)"
                name = item.get("name") or item.get("domain") or "?"
                problems.append(f"{key}[{name}].{where}: {error.message}")
    return problems


# ---- reading the console -------------------------------------------------


def read_console(client, site_id, keys=None):
    """GET current state for each resource type, keyed by type.

    Networks are fetched twice on purpose: once as a collection to learn the
    ids, then individually because the collection response is a projection
    that omits the subnet, the DHCP block, isolation and internet access. See
    Resource.detail_get.
    """
    actual = {}
    for key in keys or res.all_keys():
        resource = res.get(key)
        items = client.get_all(resource.collection_path(site_id))
        if resource.detail_get:
            items = [
                client.get(resource.item_path(site_id, item["id"])) for item in items
            ]
        actual[key] = items
    return actual


class Resolver:
    """Turns names in YAML into the UUIDs this console uses.

    Built from console state, so it can only resolve objects that already
    exist. A reference to an object being created in the same run is a real
    limitation and reported as such rather than silently dropped -- the fix is
    to apply in dependency order (zones before networks before policies), which
    is the order the registry declares.
    """

    #: Only these types are ever referenced by name from another object, so
    #: only these need a name->id index. Firewall policies emphatically do not:
    #: the controller generates one implicit policy per zone pair and calls
    #: every blocking one "Block All Traffic". Indexing those would be both
    #: useless and a guaranteed duplicate-name collision.
    TARGET_TYPES = tuple({t for t, _ in res.REFERENCE_KEYS.values()})

    #: Marker for a reference to an object that desired state declares but the
    #: console does not have yet. Lets a dry run show the whole plan instead of
    #: refusing at the first forward reference; apply refuses on these instead,
    #: because a placeholder must never reach a console.
    PENDING_PREFIX = "<pending:"

    def __init__(self, actual, pending=None):
        self._index = {}
        self._pending = {k: set(v) for k, v in (pending or {}).items()}
        self.pending_refs = []
        for key in self.TARGET_TYPES:
            items = actual.get(key)
            if items is None:
                continue
            resource = res.get(key)
            table = {}
            for item in items:
                identity = resource.identify(item)
                if identity is None:
                    continue
                if identity in table:
                    raise ConfigError(
                        f"Two {resource.label}s on the console share the "
                        f"{resource.identity} '{identity}'. This type is "
                        "referenced by name from other objects, so the name "
                        "has to be unique; rename one in the UI."
                    )
                table[identity] = item["id"]
            self._index[key] = table

    def lookup(self, resource_key, name):
        table = self._index.get(resource_key, {})
        if name in table:
            return table[name]
        if name in self._pending.get(resource_key, set()):
            ref = (resource_key, name)
            if ref not in self.pending_refs:
                self.pending_refs.append(ref)
            return f"{self.PENDING_PREFIX}{name}>"
        known = ", ".join(sorted(table)) or "(none)"
        pending = ", ".join(sorted(self._pending.get(resource_key, set())))
        hint = f" Declared but not yet created: {pending}." if pending else ""
        raise ConfigError(
            f"No {res.get(resource_key).label} named '{name}' on the "
            f"console. Known: {known}.{hint}"
        )

    def resolve(self, value):
        """Recursively rewrite name references into id fields.

        Depth-agnostic on purpose: it is the same mechanism for a zone's
        top-level `networks:` list and for a policy's
        `destination.trafficFilter.portFilter.matchingList`.
        """
        if isinstance(value, list):
            return [self.resolve(v) for v in value]
        if not isinstance(value, dict):
            return value

        out = {}
        for key, val in value.items():
            if key in res.REFERENCE_KEYS:
                target, api_field = res.REFERENCE_KEYS[key]
                if isinstance(val, list):
                    out[api_field] = [self.lookup(target, n) for n in val]
                else:
                    out[api_field] = self.lookup(target, val)
            else:
                out[key] = self.resolve(val)
        return out


# ---- building the plan ---------------------------------------------------

#: Fields the console reports that desired state never sets. Excluded from the
#: "undeclared fields" report so it shows genuinely unclaimed configuration
#: rather than identifiers and controller bookkeeping.
_NEVER_DECLARED = {"id", "metadata", "index", "default", "management"}


def build_plan(client, site_cfg, desired, site_id, version, keys=None):
    keys = keys or res.all_keys()
    # Reference targets are always read, whatever --only says. `--only policies`
    # still has to turn `zone: Gateway` into an id, and reading only the
    # policies used to leave every zone looking undeclared-on-the-console --
    # an outright error for system zones and a false <pending:...> for ours.
    read_keys = [
        k for k in res.all_keys() if k in keys or k in Resolver.TARGET_TYPES
    ]
    actual = read_console(client, site_id, read_keys)
    # Names desired state declares, so forward references resolve to a
    # placeholder in a dry run rather than aborting the whole plan.
    pending = {}
    for key in res.all_keys():
        resource = res.get(key)
        live = {resource.identify(o) for o in actual.get(key, [])}
        declared = {
            item.get(resource.identity)
            for item in desired.get(key, [])
            if item.get(resource.identity)
        }
        missing = declared - live
        if missing:
            pending[key] = missing
    resolver = Resolver(actual, pending=pending)
    managed_cfg = site_cfg.get("managed", {})

    plan = diffmod.Plan(site_cfg["console"].get("name", "unnamed"), version)

    for key in keys:
        resource = res.get(key)
        rd = diffmod.ResourceDiff(resource)
        managed = managed_cfg.get(key) or []
        if not isinstance(managed, list):
            raise ConfigError(f"site.yaml managed.{key} must be a list")
        managed_set = set(managed)

        # Group rather than overwrite. Names are unique among USER_DEFINED
        # objects, which is all the tool writes, but the controller's own
        # objects collide freely -- one console had 52 policies named "Block
        # All Traffic". A dict comprehension would silently keep the last one.
        grouped = {}
        for obj in actual[key]:
            grouped.setdefault(resource.identify(obj), []).append(obj)

        by_identity = {}
        for identity, matches in grouped.items():
            if len(matches) == 1:
                by_identity[identity] = matches[0]
                continue
            owned = [m for m in matches if not resource.is_system_defined(m)]
            if len(owned) > 1:
                raise ConfigError(
                    f"{len(owned)} user-defined {resource.label}s share the "
                    f"{resource.identity} '{identity}'. Names are this tool's "
                    "identity for the objects it writes; rename one in the UI."
                )
            if owned:
                by_identity[identity] = owned[0]
            elif identity in managed_set:
                # Declared as managed but every match is controller-owned. Let
                # it through so the loop below raises the specific error.
                by_identity[identity] = matches[0]
            else:
                # A group of controller-owned objects sharing a name. Nothing to
                # reconcile. Reported here, collapsed to one line with a count,
                # and deliberately kept out of by_identity so the orphan pass
                # below does not report it a second time.
                rd.unmanaged.append(
                    (f"{identity} ({len(matches)}x)", resource.origin(matches[0]))
                )
        declared = {}
        for item in desired[key]:
            identity = item.get(resource.identity)
            if identity is None:
                raise ConfigError(
                    f"{resource.yaml_file}: every entry needs a "
                    f"'{resource.identity}'"
                )
            if identity not in managed_set:
                raise ConfigError(
                    f"{resource.yaml_file} declares {resource.label} "
                    f"'{identity}' but site.yaml does not list it under "
                    f"managed.{key}. Add it there to confirm the tool may "
                    "write it."
                )
            declared[identity] = item

        for identity, item in declared.items():
            body = resolver.resolve(strip_comments(item))
            live = by_identity.get(identity)
            if live is None:
                body = {**resource.create_defaults, **body}
                rd.add(diffmod.ObjectDiff(resource, identity, diffmod.CREATE,
                                          desired=body))
                continue
            writability = resource.writability(live)
            if writability == res.NONE:
                meta = live.get("metadata") or {}
                raise ConfigError(
                    f"{resource.yaml_file} declares {resource.label} "
                    f"'{identity}', but on the console that object is "
                    f"{meta.get('origin')}"
                    + (" and not configurable" if meta.get("origin") ==
                       "SYSTEM_DEFINED" else "")
                    + ". The tool does not write these. DERIVED objects in "
                    "particular are generated from other settings -- express "
                    "them by their cause (a network's isolationEnabled) rather "
                    "than by the policies the controller derives from it."
                )
            changes = diffmod.compare_fields(
                body, live, unordered_fields=resource.unordered_fields
            )
            undeclared = sorted(
                set(live) - set(body) - _NEVER_DECLARED
            )
            obj = diffmod.ObjectDiff(
                resource,
                identity,
                diffmod.UPDATE if changes else diffmod.UNCHANGED,
                desired=body,
                actual=live,
                changes=changes,
                undeclared=undeclared,
            )
            obj.writability = writability
            rd.add(obj)

        foreign = []
        for identity, live in by_identity.items():
            if identity in declared:
                continue
            if identity in managed_set and resource.writability(live) == res.FULL:
                rd.add(
                    diffmod.ObjectDiff(resource, identity, diffmod.ORPHAN,
                                       actual=live)
                )
            else:
                rd.unmanaged.append((identity, resource.origin(live)))
                if resource.writability(live) == res.FULL:
                    foreign.append((identity, live))

        for obj in rd.objects:
            if obj.kind == diffmod.CREATE:
                obj.rename_suspects = _rename_suspects(resource, obj.desired,
                                                       foreign)

        if resource.ordered and key == "policies":
            rd.ordering = plan_policy_ordering(
                client, site_id, desired[key], resolver, actual[key]
            )

        plan.add(rd)

    plan.pending_refs = resolver.pending_refs
    return plan, actual


# ---- UI renames ----------------------------------------------------------

_ABSENT = object()


def _dotted(body, path):
    value = body
    for part in path.split("."):
        if not isinstance(value, dict) or part not in value:
            return _ABSENT
        value = value[part]
    return value


def _rename_suspects(resource, desired, foreign):
    """Names of unmanaged user-defined objects that look like `desired`.

    Names are this tool's identity, and the tool keeps no record of which
    console id it wrote last time -- deliberately, see decisions.md. So a
    rename in the UI arrives looking like two unrelated facts: the managed name
    is gone (a CREATE) and an unknown user-defined object has appeared
    (unmanaged). Applied as-is, that creates a duplicate: a second allow beside
    the renamed one, or a network create that fails on a VLAN collision after
    earlier writes have already landed.

    This joins the two facts back up. It is a heuristic and says so in the
    output; apply refuses while any suspect stands, and
    --allow-suspected-renames is the override for a genuine coincidence.
    """
    suspects = []
    for identity, live in foreign:
        if resource.match_fields:
            wanted = [(f, _dotted(desired, f)) for f in resource.match_fields]
            if any(v is _ABSENT for _, v in wanted):
                continue
            if all(
                diffmod.normalize(v) == diffmod.normalize(_dotted(live, f))
                for f, v in wanted
            ):
                suspects.append(identity)
        else:
            body = {k: v for k, v in desired.items() if k != resource.identity}
            if body and not diffmod.compare_fields(
                body, live, unordered_fields=resource.unordered_fields
            ):
                suspects.append(identity)
    return suspects


# ---- policy ordering -----------------------------------------------------


def policy_cells(desired_policies):
    """Group declared policies by zone-pair cell and placement, in YAML order.

    Returns {(source, destination): {"BEFORE_SYSTEM": [...], "AFTER_SYSTEM":
    [...]}} of policy names. Reads the raw YAML, because `placement` is a
    tool-only key and is stripped from the resolved body.
    """
    cells = {}
    for item in desired_policies:
        source = (item.get("source") or {}).get("zone")
        dest = (item.get("destination") or {}).get("zone")
        if not source or not dest:
            continue
        placement = item.get("placement", "BEFORE_SYSTEM")
        buckets = cells.setdefault(
            (source, dest), {p: [] for p, _, _ in diffmod.BUCKETS}
        )
        if placement not in buckets:
            raise ConfigError(
                f"policies.yaml: '{item.get('name')}' has placement "
                f"'{placement}'; expected BEFORE_SYSTEM or AFTER_SYSTEM"
            )
        buckets[placement].append(item["name"])
    return cells


def plan_policy_ordering(client, site_id, desired_policies, resolver,
                         live_policies):
    """Compare each declared cell's policy order with the console's.

    Order is not a field on any policy, so the field-level diff cannot see it:
    a policy dragged below its Block All in the UI used to produce an empty
    diff, and an apply with nothing else to do exited before reaching the
    ordering step. This makes order a first-class part of the plan.

    Only cells that desired state mentions are read. A cell with no declared
    policies is left alone, which is also what apply does with it.
    """
    resource = res.get("policies")
    names_by_id = {
        p["id"]: resource.identify(p)
        for p in live_policies
        if resource.writability(p) == res.FULL
    }
    changes = []
    for (source, dest), want in policy_cells(desired_policies).items():
        source_id = resolver.lookup("zones", source)
        dest_id = resolver.lookup("zones", dest)
        declared = {n for bucket in want.values() for n in bucket}

        live = {p: [] for p, _, _ in diffmod.BUCKETS}
        foreign = []
        if not any(
            str(z).startswith(Resolver.PENDING_PREFIX) for z in (source_id, dest_id)
        ):
            body = client.get(
                resource.ordering_path(site_id),
                params={
                    "sourceFirewallZoneId": source_id,
                    "destinationFirewallZoneId": dest_id,
                },
            ) or {}
            ordered = body.get("orderedFirewallPolicyIds") or {}
            for placement, api_key, _ in diffmod.BUCKETS:
                for policy_id in ordered.get(api_key) or []:
                    name = names_by_id.get(policy_id, policy_id)
                    if name in declared:
                        live[placement].append(name)
                    else:
                        foreign.append(name)

        if live != want:
            changes.append(
                diffmod.OrderingChange(source, dest, source_id, dest_id,
                                       want, live, foreign)
            )
    return changes


# ---- zone membership -----------------------------------------------------


def membership_changes(plan):
    """[(type, name)] for every planned write that moves a network into a zone.

    Membership is the one write that makes zone policy start applying, so it is
    the one that has to land after the policies it depends on. A zone created
    with an empty network list is not membership; a network created straight
    into a zone is.
    """
    moves = []
    for rd in plan.resources:
        field = rd.resource.membership_field
        if not field:
            continue
        for obj in rd.changed:
            if obj.kind == diffmod.CREATE and (obj.desired or {}).get(field):
                moves.append((rd.resource.key, obj.identity))
            elif obj.kind == diffmod.UPDATE and any(
                path == field for path, _, _ in obj.changes
            ):
                moves.append((rd.resource.key, obj.identity))
    return moves


def pending_policy_work(rd):
    """Creates, updates and reorders outstanding in a policies ResourceDiff.

    Orphans are excluded: a managed policy dropped from YAML stays planned until
    --allow-delete removes it, and that should not block zone membership.
    """
    writes = [
        o.identity for o in rd.changed
        if o.kind in (diffmod.CREATE, diffmod.UPDATE)
    ]
    return writes, [c.cell for c in rd.ordering]
