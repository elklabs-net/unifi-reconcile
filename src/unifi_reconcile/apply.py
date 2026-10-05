"""Send a plan to a console.

Nothing here runs unless `--apply` was passed. The entry point takes an already
computed plan, so what gets written is exactly what was displayed -- there is no
second, unreviewed computation between the diff and the write.

Order matters and is not configurable. Resources are applied in the order
`resources.RESOURCES` declares them, which is dependency order: zones before
networks because a network names a zone, both before policies because a policy
names either. Within a resource type, creates and updates land before deletes,
so a rename expressed as create-then-delete never leaves a gap.

Dependency order is *not* safety order, and one case matters enough to be
refused rather than reordered: moving a network into a zone. That write is what
makes zone policy start applying, and dependency order puts it (zones, networks)
ahead of the policies it depends on. The CLI refuses any run that changes
zone membership while the policy matrix has unapplied creates, updates or
reorders -- see state.membership_changes. Policies first, membership second, as
two reviewed runs.
"""

from __future__ import annotations

import datetime
import json
import os

from . import diff as diffmod
from . import redact as redactmod
from . import resources as res
from . import sanitize


class ApplyError(RuntimeError):
    pass


class Result:
    def __init__(self):
        self.created, self.updated, self.deleted, self.reordered = [], [], [], []
        self.skipped = []

    @property
    def total(self):
        return len(self.created) + len(self.updated) + len(self.deleted)

    def summary(self):
        parts = []
        for label, items in (
            ("created", self.created),
            ("updated", self.updated),
            ("deleted", self.deleted),
            ("reordered", self.reordered),
        ):
            if items:
                parts.append(f"{len(items)} {label}")
        return ", ".join(parts) or "nothing to do"


def capture_state(directory, actual, site_cfg, version, site_id):
    """Write the pre-change console state, redacted, and return the path.

    This runs before the first write and is not optional. The `.unifi` console
    backup is the disaster-recovery path; this is the much smaller thing you
    actually want when a single policy went wrong and you need to see what it
    looked like ten seconds ago.
    """
    stamp = datetime.datetime.now().strftime("%Y%m%dT%H%M%S")
    # Named for the console, so several consoles can share a directory.
    console = site_cfg["console"].get("name", "console")
    path = os.path.join(directory, f"{stamp}-{console}")
    os.makedirs(path, exist_ok=True)
    for key, items in actual.items():
        with open(os.path.join(path, f"{key}.json"), "w") as handle:
            json.dump(redactmod.redact(items), handle, indent=2, sort_keys=True)
    with open(os.path.join(path, "_meta.json"), "w") as handle:
        json.dump(
            {
                "capturedAt": stamp,
                "console": site_cfg["console"].get("name"),
                "applicationVersion": version,
                "siteId": site_id,
                "note": "pre-change state captured by unifi-reconcile --apply",
            },
            handle,
            indent=2,
        )
    return path


def apply_plan(client, plan, site_id, allow_delete=False, log=print):
    result = Result()

    for rd in plan.resources:
        resource = rd.resource
        creates = [o for o in rd.objects if o.kind == diffmod.CREATE]
        updates = [o for o in rd.objects if o.kind == diffmod.UPDATE]
        orphans = [o for o in rd.objects if o.kind == diffmod.ORPHAN]

        for obj in creates:
            body = sanitize.for_create(obj.desired)
            created = client.post(resource.collection_path(site_id), body)
            new_id = (created or {}).get("id")
            obj.actual = created or {}
            log(f"  + {resource.key}/{obj.identity}  created" +
                (f" ({new_id})" if new_id else ""))
            result.created.append((resource.key, obj.identity))

        for obj in updates:
            object_id = obj.object_id
            if not object_id:
                raise ApplyError(
                    f"{resource.key}/{obj.identity}: update with no id"
                )
            path = resource.item_path(site_id, object_id)
            if resource.patchable:
                # PATCH takes just the changed fields, which is both smaller and
                # safer than a full replace -- nothing unmentioned can be lost.
                client.patch(path, sanitize.for_create(obj.desired))
                how = "patched"
            else:
                # No PATCH, so PUT the whole object: current state sanitized,
                # with the desired fields merged over it.
                body = sanitize.for_write(obj.actual, obj.desired)
                client.put(path, body)
                how = "replaced"
            log(f"  ~ {resource.key}/{obj.identity}  {how}")
            result.updated.append((resource.key, obj.identity))

        for obj in orphans:
            if not allow_delete:
                log(f"  - {resource.key}/{obj.identity}  SKIPPED "
                    "(needs --allow-delete)")
                result.skipped.append((resource.key, obj.identity))
                continue
            client.delete(resource.item_path(site_id, obj.object_id))
            log(f"  - {resource.key}/{obj.identity}  deleted")
            result.deleted.append((resource.key, obj.identity))

    return result


def apply_policy_ordering(client, site_id, ordering_changes, log=print):
    """Write the per-cell policy order the plan said was wrong.

    Ordering is scoped to one cell of the zone matrix -- source zone and
    destination zone -- and within that cell user policies sit either before or
    after the controller's own implicit policy for the pair. That split is why
    a Block toward the Gateway works at all: the pair's system default is Allow
    All, so a Block only denies anything by being evaluated ahead of it.

    Only cells in the plan are written, so what is sent is what was displayed.
    Policy ids are looked up after the creates, since a cell's order usually
    changes precisely because a policy in it was just created.
    """
    if not ordering_changes:
        return []
    resource = res.get("policies")
    live = {
        resource.identify(p): p["id"]
        for p in client.get_all(resource.collection_path(site_id))
        if resource.writability(p) == res.FULL
    }

    written = []
    for change in ordering_changes:
        missing = [
            n
            for bucket in change.desired.values()
            for n in bucket
            if n not in live
        ]
        if missing:
            raise ApplyError(
                f"ordering {change.cell}: these policies are declared but "
                f"not on the console: {', '.join(missing)}"
            )
        body = {
            "orderedFirewallPolicyIds": {
                api_key: [live[n] for n in change.desired[placement]]
                for placement, api_key, _ in diffmod.BUCKETS
            }
        }
        params = {
            "sourceFirewallZoneId": change.source_id,
            "destinationFirewallZoneId": change.destination_id,
        }
        client.put(resource.ordering_path(site_id), body, params=params)
        log(f"  ~ ordering {change.cell}")
        written.append(change.cell)
    return written
