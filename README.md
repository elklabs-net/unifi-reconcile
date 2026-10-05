# unifi-reconcile

Configuration as code for UniFi Network consoles. You describe zones, networks,
firewall policies and the rest in YAML; the tool compares that against the live
console and shows you the difference. With `--apply` it sends exactly the
difference it showed you, and nothing else.

Not affiliated with or endorsed by Ubiquiti. UniFi is Ubiquiti's trademark.

- **Dry run by default.** Without flags it only reads and prints the diff, so it
  doubles as a drift check: exit `0` means the console matches, `2` means it
  doesn't.
- **Refuses unsafe applies.** Before writing anything, it stops on forward
  references, zone membership changes ahead of their policies, suspected UI
  renames, and policy reorders in cells it doesn't fully own. Deletes need a
  second flag.
- **Verifies what the API can't write.** `--verify` checks reservations, SSIDs,
  radios, switch ports, WAN DNS, static routes, Auto-Link, mDNS and IPS against
  the console. It reports drift and never writes.
- **Keeps secrets out of output.** Anything with a secret-sounding field name is
  redacted on screen and on disk, and the API key never goes in YAML.

Tested against UniFi Network 10.6 on a UDM-SE. Expect rough edges on other
versions; the tool refuses to run against a version other than the one you pin,
and [api-hazards.md](api-hazards.md) explains how to move the pin.

## Install

Python 3.9 or newer.

```bash
python3 -m venv .venv
./.venv/bin/pip install "git+https://github.com/elklabs-net/unifi-reconcile@v0.1.0"
./.venv/bin/unifi-reconcile --version
```

Pin a tag. Console firmware changes API behavior, and a newer version of this
tool may assume a newer console.

## A site

One directory per console. Only `site.yaml` is required; a resource type with
no file is reported as unmanaged and left alone.

```
network/
  secrets.sops.env        # the API key; see "The API key" below
  unifi/                  # what you pass to --config
    site.yaml             # console identity, and the objects the tool may write
    zones.yaml
    networks.yaml
    matching-lists.yaml
    policies.yaml
    dns.yaml
    wifi.yaml
    acl-rules.yaml
    verified.yaml         # the read-only Verified tier
```

`site.yaml` names the console and lists, per type, the objects the tool is
allowed to write. Declaring an object in its YAML file is not enough; it also
has to appear under `managed:`. That second signature means a typo in a name
can't quietly create a near-duplicate firewall policy.

```yaml
# yaml-language-server: $schema=https://raw.githubusercontent.com/elklabs-net/unifi-reconcile/v0.1.0/src/unifi_reconcile/schema/site.schema.json
console:
  name: home-gateway
  base_url: https://192.168.1.1/proxy/network/integration/v1
  api_key_env: HOME_UNIFI_API_KEY
  verify_tls: false          # LAN address, self-signed certificate
  network_version: "10.6.106"
managed:
  zones: [IoT]
  networks: [Default, IoT]
  policies:
    - IoT -> Gateway - Allow DNS
```

Objects are named, never referenced by UUID; the tool resolves names per
console. A policy:

```yaml
policies:
  - name: IoT -> Gateway - Allow DNS
    _comment: Keys starting with an underscore are notes and never sent.
    enabled: true
    placement: BEFORE_SYSTEM
    action:
      type: ALLOW
      allowReturnTraffic: false   # must be false toward Gateway
    source:
      zone: IoT
    destination:
      zone: Gateway
      trafficFilter:
        type: PORT
        portFilter:
          type: PORTS
          matchOpposite: false
          items:
            - type: PORT_NUMBER
              value: 53
    ipProtocolScope:
      ipVersion: IPV4
      protocolFilter:
        type: PRESET
        preset:
          name: TCP_UDP
```

Every resource file is validated against the JSON Schemas in
[src/unifi_reconcile/schema/](src/unifi_reconcile/schema/) before anything is
sent. Their descriptions document the traps worth knowing. Point your editor at
them with a `yaml-language-server` comment, as above.

## The API key

Two ways to reach a console, chosen by `base_url`:

- **Locally**, at the console's LAN address, with a key created on the console
  under Settings → Control Plane → Integrations. Scoped to that one console.
- **Through Ubiquiti's cloud connector**, with a Site Manager key:
  `https://api.ui.com/v1/connector/consoles/{hostId}/proxy/network/integration/v1`,
  with `host_id` set in `site.yaml`. The connector only serves the console's
  owner, and the key reaches every console the account owns.

`site.yaml` names the environment variable that holds the key. The tool reads it
from `--env-file`, which defaults to `secrets.sops.env` in the parent directory
of `--config`. A file with `.sops.` in its name is decrypted in memory with
[sops](https://github.com/getsops/sops); any other file is read as plaintext
`KEY=VALUE`. Give each site its own variable name, so one site's key file can
never satisfy another site's run.

## Use

```bash
# Diff. Dry run is the default.
unifi-reconcile --config network/unifi

# One type at a time
unifi-reconcile --config network/unifi --only policies

# Send it. Prints the same diff first, then captures pre-change state.
unifi-reconcile --config network/unifi --only policies --apply

# What the console holds that the YAML does not claim
unifi-reconcile --config network/unifi --show-undeclared

# Raw console state, redacted, for reading or a before/after
unifi-reconcile --config network/unifi --dump dump/

# The Verified tier
unifi-reconcile --config network/unifi --verify
```

Exit codes: `0` no changes (or no drift), `1` error, `2` changes pending (or
drift found). A dry run in cron is a drift alarm without parsing any output.

`--apply` writes a redacted copy of the console's current state to
`.reconcile-state/<timestamp>-<console>/` inside `--config` before its first
write. Gitignore that directory.

`--apply` refuses, before writing anything, when a run:

- references an object that does not exist yet (`<pending:...>`). Apply the
  dependency with `--only <type>` first.
- moves a network into a zone while policies are unapplied. Apply
  `--only policies` first; zone membership is the moment policy starts applying.
- creates something an unmanaged object looks like a UI rename of. Rename it
  back, adopt the new name, or pass `--allow-suspected-renames`.
- would reorder a zone-pair cell that holds user policies the tool does not
  manage.

Deletes also need `--allow-delete`, and only ever touch user-defined objects in
the managed list.

### The Verified tier

Some settings can be read but not written through the integration API:
reservations, radio settings, switch port overrides, WAN DNS, static routes,
Auto-Link, the site mDNS setting and IPS mode. `verified.yaml` records what they
should be, and `--verify` reads them through the console's legacy API and
reports drift. The UI stays the place to change them.

Four sections are exhaustive: `wifi`, `radios.access_points`, `reservations`
and `static_routes`. Anything on the console those sections don't list is
reported, because the drift that matters there is the object nobody declared.
`verified.yaml` is refused outright if it contains a secret-named key, so a
passphrase can't be committed by mistake.

## Things worth knowing before you rely on it

**The diff compares only what the YAML declares.** A field absent from your YAML
is unclaimed, not drift. The API forces this: many optional fields are simply
missing from a GET body when unset, so whole-object comparison would report
drift that no YAML edit could ever clear. The cost is that an undeclared field
can change in the UI unnoticed. `--show-undeclared` shows the gap.

**Policy order is part of the diff.** Ordering is per zone-pair cell, in two
buckets either side of the cell's system policy (`placement:`). A policy dragged
in the UI is drift like any other.

**Names are identity, but only for objects the tool owns.** The controller
generates one implicit policy per zone pair, and every blocking one is called
"Block All Traffic", so policy names are not unique on a real console. There is
no last-applied state, so a rename in the UI looks like a create plus a stray
object; the dry run flags that pair as a suspected rename.

**Ownership has three levels, not two.**

| Origin | May the tool write it? |
| --- | --- |
| `USER_DEFINED` | Yes: create, update, delete. |
| `SYSTEM_DEFINED` + `configurable: true` | Update only. The `Default` network (VLAN 1) is this: its subnet and DHCP are yours, its existence is the controller's. |
| `SYSTEM_DEFINED` + `configurable: false` | No. `Gateway`, `External`, `Vpn`. |
| `DERIVED` | No. Generated from other settings; declare the cause instead. |
| no `metadata` | Yes. Traffic matching lists have no origin in the API. |

Where the console departs from its own published spec, and what to do when its
version changes: [api-hazards.md](api-hazards.md). Why the tool works the way it
does: [decisions.md](decisions.md).

## Layout

```
src/unifi_reconcile/
  cli.py        Argument handling and rendering. No API knowledge.
  client.py     HTTP, auth, paging, version assertion, site resolution.
  resources.py  The resource table. Adding a type is an entry here.
  state.py      YAML loading, schema validation, name->ID resolution,
                ownership rules, plan construction, ordering drift,
                rename and zone-membership checks.
  diff.py       Comparison and output.
  apply.py      Writes, per-cell policy ordering, pre-change capture.
  sanitize.py   Turns a GET body into a PUT body the API will accept.
  redact.py     Strips secret-named fields from anything printed or saved.
  verify.py     The Verified tier. Read-only by construction: the client has
                no legacy write method.
  schema/       JSON Schema per resource type.
```

## License

MIT. See [LICENSE](LICENSE).
