"""Comparison and rendering.

The central decision here is that **the diff compares only what the YAML
declares.** A field absent from desired state is not drift; it is unclaimed.

That is not laziness, it is the only semantics that works against this API.
`connectionStateFilter` is documented as "if null, matches all connection
states", so a policy that matches all states has no such field in its GET
body -- there is no value to write down. The same holds for a dozen other
optional fields the controller fills in or leaves out at its discretion.
A whole-object comparison would therefore report permanent, un-resolvable
drift on every object, the diff would never be empty, and the one thing a
diff has to be is trustworthy when it says "no changes".

The cost is real and worth stating plainly: a field nobody declared can be
changed in the UI and this tool will not notice. Coverage is what the YAML
says it is. That is why the reported output separates declared fields from
undeclared ones rather than hiding the difference.
"""

from __future__ import annotations

import json

CREATE = "create"
UPDATE = "update"
ORPHAN = "orphan"
UNCHANGED = "unchanged"

# ANSI, suppressed when not writing to a terminal.
_COLORS = {
    "red": "\033[31m",
    "green": "\033[32m",
    "yellow": "\033[33m",
    "cyan": "\033[36m",
    "dim": "\033[2m",
    "bold": "\033[1m",
    "reset": "\033[0m",
}


class Palette:
    def __init__(self, enabled):
        self.enabled = enabled

    def __call__(self, text, color):
        if not self.enabled or color not in _COLORS:
            return text
        return f"{_COLORS[color]}{text}{_COLORS['reset']}"


def normalize(value, unordered=False):
    """Make two representations of the same value compare equal.

    Only the narrow cases the API actually produces:
    - lists whose order is not semantic (a zone's networkIds, a WLAN's bands)
    - integer-valued floats, because YAML 5 and JSON 5.0 are the same band
    """
    if isinstance(value, dict):
        return {k: normalize(v) for k, v in value.items()}
    if isinstance(value, list):
        items = [normalize(v) for v in value]
        if unordered:
            return sorted(items, key=_sort_key)
        return items
    if isinstance(value, float) and value.is_integer():
        return int(value)
    return value


def _sort_key(value):
    return json.dumps(value, sort_keys=True, default=str)


def compare_fields(desired, actual, unordered_fields=()):
    """Walk declared keys and return [(dotted_path, desired, actual), ...].

    Recurses into dicts so a change to one DHCP field reports as
    `ipv4Configuration.dhcpConfiguration.leaseTimeSeconds` rather than
    redisplaying the whole nested object and making the reader find it.
    """
    changes = []
    _compare_into(changes, desired, actual, "", set(unordered_fields))
    return changes


_MISSING = object()


def _compare_into(changes, desired, actual, prefix, unordered_fields):
    for key, want in desired.items():
        path = f"{prefix}{key}"
        have = (actual or {}).get(key, _MISSING)

        if isinstance(want, dict) and isinstance(have, dict):
            _compare_into(changes, want, have, f"{path}.", unordered_fields)
            continue

        unordered = key in unordered_fields
        want_n = normalize(want, unordered=unordered)
        have_n = (
            _MISSING if have is _MISSING else normalize(have, unordered=unordered)
        )
        if want_n != have_n:
            changes.append((path, want, None if have is _MISSING else have))


class ObjectDiff:
    #: Set by state.build_plan for existing objects: how far the tool may go.
    writability = None

    def __init__(self, resource, identity, kind, desired=None, actual=None,
                 changes=(), undeclared=()):
        self.resource = resource
        self.identity = identity
        self.kind = kind
        self.desired = desired
        self.actual = actual
        self.changes = list(changes)
        self.undeclared = list(undeclared)
        #: For a CREATE: names of unmanaged user-defined objects that look like
        #: this one under another name. See state._rename_suspects.
        self.rename_suspects = []

    @property
    def object_id(self):
        return (self.actual or {}).get("id")


#: The two buckets of a zone-pair cell, in the ordering endpoint's own terms.
BUCKETS = (
    ("BEFORE_SYSTEM", "beforeSystemDefined", "before system"),
    ("AFTER_SYSTEM", "afterSystemDefined", "after system"),
)


class OrderingChange:
    """One zone-pair cell whose policy order differs from desired state.

    `desired` and `live` map placement -> [policy name]. `live` is filtered to
    the policies declared for this cell, so the comparison is about the order
    of what the tool owns. `foreign` names any other user-defined policies the
    controller reports in the cell: the ordering PUT lists only declared
    policies, and what the controller does with ids left out of it is untested,
    so apply refuses to write a cell that has any.
    """

    def __init__(self, source, destination, source_id, destination_id,
                 desired, live, foreign=()):
        self.source = source
        self.destination = destination
        self.source_id = source_id
        self.destination_id = destination_id
        self.desired = desired
        self.live = live
        self.foreign = list(foreign)

    @property
    def cell(self):
        return f"{self.source} -> {self.destination}"


class ResourceDiff:
    def __init__(self, resource):
        self.resource = resource
        self.objects = []
        self.unmanaged = []
        #: [OrderingChange], one per zone-pair cell that needs reordering.
        self.ordering = []

    def add(self, object_diff):
        self.objects.append(object_diff)

    @property
    def changed(self):
        return [o for o in self.objects if o.kind != UNCHANGED]

    @property
    def empty(self):
        return not self.changed and not self.ordering


class Plan:
    """The whole comparison, across every resource type."""

    def __init__(self, site_name, version):
        self.site_name = site_name
        self.version = version
        self.resources = []
        #: [(resource_key, name)] references to objects not on the console yet.
        self.pending_refs = []

    def add(self, resource_diff):
        self.resources.append(resource_diff)

    @property
    def empty(self):
        return all(r.empty for r in self.resources)

    def counts(self):
        tally = {CREATE: 0, UPDATE: 0, ORPHAN: 0, "reorder": 0}
        for rd in self.resources:
            for obj in rd.changed:
                tally[obj.kind] = tally.get(obj.kind, 0) + 1
            tally["reorder"] += len(rd.ordering)
        return tally

    def get(self, key):
        """The ResourceDiff for one type, or None if it was not planned."""
        for rd in self.resources:
            if rd.resource.key == key:
                return rd
        return None

    @property
    def rename_suspects(self):
        return [
            (rd.resource.key, obj.identity, obj.rename_suspects)
            for rd in self.resources
            for obj in rd.changed
            if obj.rename_suspects
        ]


# ---- rendering -----------------------------------------------------------

_SYMBOL = {CREATE: "+", UPDATE: "~", ORPHAN: "-", UNCHANGED: " "}
_COLOR = {CREATE: "green", UPDATE: "yellow", ORPHAN: "red", UNCHANGED: "dim"}


def render(plan, color=True, show_unmanaged=True, show_undeclared=False):
    c = Palette(color)
    out = []
    out.append(
        c(f"site {plan.site_name}", "bold") + c(f"  (Network {plan.version})", "dim")
    )
    out.append("")

    for rd in plan.resources:
        changed = rd.changed
        header = f"{rd.resource.key}"
        has_undeclared = show_undeclared and any(o.undeclared for o in rd.objects)
        if rd.empty and not (show_unmanaged and rd.unmanaged) and not has_undeclared:
            out.append(f"  {c(header, 'dim')} {c('no changes', 'dim')}")
            continue

        out.append(f"  {c(header, 'bold')}")
        for obj in changed:
            sym = _SYMBOL[obj.kind]
            out.append(
                f"    {c(sym + ' ' + str(obj.identity), _COLOR[obj.kind])}"
                + c(f"  ({obj.kind})", "dim")
            )
            if obj.kind == CREATE:
                for suspect in obj.rename_suspects:
                    note = (f"possible UI rename: '{suspect}' is user-defined, "
                            "outside the managed set, and matches this object")
                    out.append(f"        {c('! ' + note, 'cyan')}")
                for line in _render_body(obj.desired):
                    out.append(f"        {c(line, 'green')}")
            elif obj.kind == UPDATE:
                for path, want, have in obj.changes:
                    out.append(
                        f"        {path}: "
                        + c(_fmt(have, path), "red")
                        + " -> "
                        + c(_fmt(want, path), "green")
                    )
            elif obj.kind == ORPHAN:
                note = ("in the managed set but absent from YAML; "
                        "requires --allow-delete")
                out.append(f"        {c(note, 'dim')}")

        if show_undeclared:
            for obj in rd.objects:
                if obj.undeclared:
                    note = ("  (fields on the console that YAML does "
                            "not declare)")
                    out.append(
                        f"    {c('? ' + str(obj.identity), 'cyan')}"
                        + c(note, "dim")
                    )
                    for field in obj.undeclared:
                        out.append(f"        {c(field, 'dim')}")

        for change in rd.ordering:
            out.append(f"    {c('~ ordering ' + change.cell, 'yellow')}")
            for placement, _, label in BUCKETS:
                want = change.desired.get(placement, [])
                have = change.live.get(placement, [])
                if want == have:
                    continue
                # One policy per line: the names themselves contain "->".
                out.append(f"        {label}")
                for tag, names, colour in (("now: ", have, "red"),
                                           ("want:", want, "green")):
                    for i, name in enumerate(names or ["(empty)"]):
                        lead = tag if i == 0 else " " * len(tag)
                        out.append(f"          {lead} {c(name, colour)}")
            if change.foreign:
                note = ("also holds unmanaged user-defined policies: "
                        + ", ".join(change.foreign) + " (apply refuses)")
                out.append(f"        {c('! ' + note, 'cyan')}")

        if show_unmanaged and rd.unmanaged:
            note = (f"{len(rd.unmanaged)} object(s) outside the managed "
                    "set, left alone")
            out.append(f"    {c(note, 'dim')}")
            for name, origin in rd.unmanaged:
                out.append(f"        {c(f'{name}  [{origin}]', 'dim')}")
        out.append("")

    if plan.pending_refs:
        out.append(
            c("Forward references, shown as <pending:...>:", "cyan")
        )
        for key, name in plan.pending_refs:
            out.append(c(f"    {key}/{name} — declared here, not on the "
                         "console yet", "dim"))
        out.append(
            c("  Create those first (--only <type> --apply), then re-run. "
              "--apply refuses while any remain.", "dim")
        )
        out.append("")

    tally = plan.counts()
    if plan.empty:
        out.append(c("No changes. Console matches desired state.", "green"))
    else:
        out.append(
            c(
                f"Plan: {tally[CREATE]} to create, {tally[UPDATE]} to update, "
                f"{tally[ORPHAN]} orphaned, {tally['reorder']} cell(s) to "
                "reorder.",
                "bold",
            )
        )
    return "\n".join(out)


def _render_body(body, indent=0):
    lines = []
    for key, value in (body or {}).items():
        if isinstance(value, dict):
            lines.append(f"{'  ' * indent}{key}:")
            lines.extend(_render_body(value, indent + 1))
        else:
            lines.append(f"{'  ' * indent}{key}: {_fmt(value, key)}")
    return lines


def _fmt(value, field=None):
    from . import redact as redactmod

    if field is not None and redactmod.is_secret(str(field).rsplit(".", 1)[-1]):
        if not isinstance(value, (bool, int, float, type(None))):
            return redactmod.PLACEHOLDER
    if value is None:
        return "(unset)"
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (list, dict)):
        return json.dumps(value, default=str)
    return str(value)
