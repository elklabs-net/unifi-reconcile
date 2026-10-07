#!/usr/bin/env python3
"""Reconcile a UniFi Network console against declarative YAML.

Computes and prints a diff; that is the default and the primary use. --apply
sends exactly the diff it printed, after refusing anything that cannot be sent
safely in one run (forward references, zone membership ahead of policy,
suspected UI renames). --verify checks the Verified tier -- verified.yaml,
read through the legacy API and reported, never written.

    unifi-reconcile --config network/unifi
    unifi-reconcile --config ... --only policies --apply
    unifi-reconcile --config ... --verify
    unifi-reconcile --config ... --dump dump/   # save raw console state

See README.md.
"""

from __future__ import annotations

import argparse
import datetime
import json
import os
import sys

from . import __version__
from . import apply as applymod
from . import client as clientmod
from . import diff as diffmod
from . import redact as redactmod
from . import resources as res
from . import state as statemod
from . import verify as verifymod


def default_env_file(config_dir):
    """secrets.sops.env in the parent directory of --config. Decrypted in
    memory by load_env_file.

    Derived from --config rather than fixed to one path. A Site Manager key is
    account-scoped and reaches every console the account can see, so a fixed
    default would let a run against one console that forgot --env-file
    authenticate with another console's credentials and look fine.
    """
    return os.path.join(os.path.dirname(os.path.abspath(config_dir)), "secrets.sops.env")


def default_state_dir(config_dir):
    """.reconcile-state/ inside --config, so captures stay with the site they
    belong to. Gitignore it there."""
    return os.path.join(os.path.abspath(config_dir), ".reconcile-state")


def build_parser():
    p = argparse.ArgumentParser(
        prog="unifi-reconcile",
        description="Diff a UniFi console against declarative YAML.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Exit codes: 0 no changes, 1 error, 2 changes pending "
            "(so a dry run is usable as a drift check)."
        ),
    )
    p.add_argument(
        "--config",
        required=True,
        metavar="DIR",
        help="Directory holding site.yaml and the per-resource YAML files.",
    )
    p.add_argument(
        "--env-file",
        metavar="PATH",
        help="KEY=VALUE file supplying the API key; *.sops.* files are decrypted "
        "with sops (default: secrets.sops.env in the parent directory of "
        "--config).",
    )
    p.add_argument(
        "--only",
        metavar="TYPE",
        action="append",
        choices=res.all_keys(),
        help="Limit to one resource type. Repeatable.",
    )

    mode = p.add_mutually_exclusive_group()
    mode.add_argument(
        "--dry-run",
        action="store_true",
        default=True,
        help="Compute and print the diff. The default; no writes.",
    )
    mode.add_argument(
        "--apply",
        action="store_true",
        help="Send the diff to the console, after printing it.",
    )
    mode.add_argument(
        "--verify",
        action="store_true",
        help="Check verified.yaml against the console via the legacy API. "
        "Read-only; exits 2 on drift.",
    )

    p.add_argument(
        "--allow-delete",
        action="store_true",
        help="Permit deleting managed objects absent from YAML. Needs --apply.",
    )
    p.add_argument(
        "--allow-suspected-renames",
        action="store_true",
        help="Create objects even when an unmanaged object looks like a UI "
        "rename of them.",
    )
    p.add_argument(
        "--allow-version-mismatch",
        action="store_true",
        help="Proceed when the console version differs from the site.yaml pin.",
    )
    p.add_argument(
        "--state-dir",
        metavar="DIR",
        help="Where --apply writes pre-change console state "
        "(default: .reconcile-state/ inside --config; gitignore it).",
    )
    p.add_argument(
        "--dump",
        metavar="DIR",
        help="Write raw console state as JSON, one file per resource type.",
    )
    p.add_argument(
        "--show-undeclared",
        action="store_true",
        help="List fields present on the console that YAML does not declare.",
    )
    p.add_argument("--json", action="store_true", help="Emit the plan as JSON.")
    p.add_argument("--no-color", action="store_true", help="Disable ANSI color.")
    p.add_argument("--version", action="version",
                   version=f"%(prog)s {__version__}")
    return p


def main(argv=None):
    args = build_parser().parse_args(argv)
    if args.env_file is None:
        args.env_file = default_env_file(args.config)
    if args.state_dir is None:
        args.state_dir = default_state_dir(args.config)

    if args.verify:
        if args.only or args.allow_delete or args.allow_suspected_renames:
            fail("--verify takes no --only or --allow-* flags; it checks the "
                 "whole of verified.yaml and never writes.")
        return run_verify(args)
    if args.allow_delete and not args.apply:
        fail("--allow-delete is meaningless without --apply.")

    color = not args.no_color and sys.stdout.isatty()

    try:
        site_cfg, desired = statemod.load_site(args.config)
        problems = statemod.validate(desired)
        if problems:
            fail("Desired state failed schema validation:\n  " +
                 "\n  ".join(problems))

        env = clientmod.load_env_file(args.env_file)
        client = clientmod.Client.from_site_config(site_cfg, env)

        console = site_cfg["console"]
        pinned = console.get("network_version")
        if pinned:
            version = client.assert_version(
                pinned, allow_mismatch=args.allow_version_mismatch
            )
        else:
            version = client.application_version()

        site_id = client.resolve_site_id(console.get("site", "default"))

        plan, actual = statemod.build_plan(
            client, site_cfg, desired, site_id, version, keys=args.only
        )

        if args.dump:
            dump(args.dump, actual, site_cfg, version, site_id)

    except (clientmod.UniFiError, statemod.ConfigError) as exc:
        fail(str(exc))

    if args.json:
        print(json.dumps(plan_as_dict(plan), indent=2, default=str))
    else:
        print(
            diffmod.render(
                plan, color=color, show_undeclared=args.show_undeclared
            )
        )

    if not args.apply:
        return 0 if plan.empty else 2

    if plan.empty:
        print("\nNothing to apply.")
        return 0

    if plan.pending_refs:
        names = ", ".join(f"{k}/{n}" for k, n in plan.pending_refs)
        types = sorted({k for k, _ in plan.pending_refs})
        fail(
            "The plan references objects that do not exist on the console yet, "
            f"so parts of it resolved to placeholders: {names}.\n"
            "A placeholder must never be written, so apply the dependency "
            "first and then re-run:\n"
            + "".join(
                f"    unifi-reconcile --config {args.config} --only {t} --apply\n"
                for t in types
            )
            + "This is only needed the first time an object is created; once it "
            "exists, its name resolves normally."
        )

    renames = plan.rename_suspects
    if renames and not args.allow_suspected_renames:
        fail(
            "These creates look like objects that were renamed in the UI:\n"
            + "".join(
                f"    {k}/{n}  <- console has {', '.join(repr(x) for x in s)}\n"
                for k, n, s in renames
            )
            + "Creating them would leave a duplicate beside the renamed one. "
            "Either rename it back in the UI, or adopt the new name in the YAML "
            "and in site.yaml's managed list. If the match is a coincidence, "
            "re-run with --allow-suspected-renames."
        )

    blocked = [
        change.cell
        for rd in plan.resources
        for change in rd.ordering
        if change.foreign
    ]
    if blocked:
        fail(
            "Policy order would be rewritten in cells that also hold "
            f"user-defined policies this tool does not manage: "
            f"{', '.join(blocked)}. The ordering PUT lists only declared "
            "policies, and what the controller does with the ones left out is "
            "untested. Declare them (policies.yaml plus site.yaml's managed "
            "list) or remove them in the UI, then re-run."
        )

    moves = statemod.membership_changes(plan)
    if moves:
        policies_rd = plan.get("policies")
        if policies_rd is None:
            # --only left policies out, but the check is about them regardless.
            try:
                policy_plan, _ = statemod.build_plan(
                    client, site_cfg, desired, site_id, version,
                    keys=["policies"],
                )
            except (clientmod.UniFiError, statemod.ConfigError) as exc:
                fail(f"could not check the policy matrix before a zone "
                     f"membership change: {exc}")
            policies_rd = policy_plan.get("policies")
        writes, cells = statemod.pending_policy_work(policies_rd)
        if writes or cells:
            fail(
                "This run moves networks into zones ("
                + ", ".join(f"{k}/{n}" for k, n in moves)
                + ") while the policy matrix still has unapplied changes ("
                + f"{len(writes)} policy write(s), {len(cells)} cell(s) to "
                "reorder).\n"
                "Zone membership is the moment policy starts applying, so the "
                "policies have to be on the console first. Dependency order "
                "would write zones and networks before policies, which is the "
                "wrong way round. Run:\n"
                f"    unifi-reconcile --config {args.config} --only policies --apply\n"
                "then re-run this. A new zone that other policies reference is "
                "declared with `networks: []` first and populated afterwards."
            )

    # The diff above is what gets sent. Nothing is recomputed in between.
    try:
        captured = applymod.capture_state(
            args.state_dir, actual, site_cfg, version, site_id
        )
        print(f"\npre-change state captured to {captured}")

        print("applying:")
        result = applymod.apply_plan(
            client, plan, site_id, allow_delete=args.allow_delete
        )

        policies_rd = plan.get("policies")
        if policies_rd is not None:
            result.reordered = applymod.apply_policy_ordering(
                client, site_id, policies_rd.ordering
            )

        print(f"\ndone: {result.summary()}")
        if result.skipped:
            print(
                f"{len(result.skipped)} delete(s) skipped; re-run with "
                "--allow-delete to remove them."
            )
    except (clientmod.UniFiError, applymod.ApplyError,
            statemod.ConfigError) as exc:
        print(
            f"\nerror during apply: {exc}\n"
            f"Pre-change state is in {args.state_dir}. The console may be "
            "partially changed -- re-run without --apply to see what is "
            "currently different.",
            file=sys.stderr,
        )
        return 1

    return 0


def run_verify(args):
    """The Verified tier: legacy reads compared with verified.yaml. No writes."""
    color = not args.no_color and sys.stdout.isatty()
    try:
        site_cfg, _ = statemod.load_site(args.config)
        desired = verifymod.load(args.config)
        if desired is None:
            fail(f"No {verifymod.YAML_FILE} in {args.config}; nothing to verify.")

        env = clientmod.load_env_file(args.env_file)
        client = clientmod.Client.from_site_config(site_cfg, env)
        console = site_cfg["console"]
        pinned = console.get("network_version")
        version = (client.assert_version(
            pinned, allow_mismatch=args.allow_version_mismatch)
            if pinned else client.application_version())

        live = verifymod.collect(client, site=console.get("site", "default"),
                                 desired=desired)
        if args.dump:
            dump(args.dump, live, site_cfg, version, console.get("site", "default"))
        findings = verifymod.check(desired, live)
    except (clientmod.UniFiError, statemod.ConfigError,
            verifymod.VerifyError) as exc:
        fail(str(exc))

    if args.json:
        print(json.dumps({
            "site": console.get("name"),
            "applicationVersion": version,
            "clean": not findings,
            "findings": [f.as_dict() for f in findings],
        }, indent=2, default=str))
    else:
        print(verifymod.render(findings, desired, console.get("name"), version,
                               color=color))
    return 2 if findings else 0


def dump(directory, actual, site_cfg, version, site_id):
    os.makedirs(directory, exist_ok=True)
    stamp = datetime.datetime.now().strftime("%Y%m%dT%H%M%S")
    hidden = set()
    for key, items in actual.items():
        # Redact on the way out, always. Integration v1 returns no secrets
        # today, but the Verified tier reads rest/wlanconf and get/setting,
        # which carry the Wi-Fi PSKs and the device SSH password. The
        # gitignore on this directory does not protect against a pasted
        # traceback or a shared terminal.
        hidden |= redactmod.redacted_field_names(items)
        path = os.path.join(directory, f"{key}.json")
        with open(path, "w") as handle:
            json.dump(redactmod.redact(items), handle, indent=2, sort_keys=True)
    if hidden:
        print(
            "# redacted from the dump: " + ", ".join(sorted(hidden)),
            file=sys.stderr,
        )
    meta = {
        "capturedAt": stamp,
        "redacted": sorted(hidden),
        "console": site_cfg["console"].get("name"),
        "applicationVersion": version,
        "siteId": site_id,
    }
    with open(os.path.join(directory, "_meta.json"), "w") as handle:
        json.dump(meta, handle, indent=2)
    print(f"# console state written to {directory}/ ({stamp})", file=sys.stderr)


def plan_as_dict(plan):
    return {
        "site": plan.site_name,
        "applicationVersion": plan.version,
        "empty": plan.empty,
        "counts": plan.counts(),
        "resources": [
            {
                "type": rd.resource.key,
                "objects": [
                    {
                        "identity": obj.identity,
                        "action": obj.kind,
                        "changes": [
                            {
                                "field": f,
                                "desired": redactmod.PLACEHOLDER
                                if redactmod.is_secret(f.rsplit(".", 1)[-1])
                                else w,
                                "actual": redactmod.PLACEHOLDER
                                if redactmod.is_secret(f.rsplit(".", 1)[-1])
                                else h,
                            }
                            for f, w, h in obj.changes
                        ],
                        "undeclaredFields": obj.undeclared,
                        "renameSuspects": obj.rename_suspects,
                    }
                    for obj in rd.objects
                    if obj.kind != diffmod.UNCHANGED or obj.undeclared
                ],
                "ordering": [
                    {
                        "cell": ch.cell,
                        "desired": ch.desired,
                        "actual": ch.live,
                        "foreignPolicies": ch.foreign,
                    }
                    for ch in rd.ordering
                ],
                "unmanaged": [
                    {"identity": n, "origin": o} for n, o in rd.unmanaged
                ],
            }
            for rd in plan.resources
        ],
    }


def fail(message):
    print(f"error: {message}", file=sys.stderr)
    raise SystemExit(1)


def entry():
    sys.exit(main())


if __name__ == "__main__":
    entry()
