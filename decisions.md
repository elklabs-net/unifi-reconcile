# Design decisions

The smaller choices behind the tool, with the alternatives considered. Dated
when made, oldest first.

## 2026-09-17 — The diff compares only declared fields

Rather than comparing whole objects. Forced by the API: `connectionStateFilter`
is documented "if null, matches all connection states", so an object that
matches all states simply has no such key in its GET body, and several other
optional fields behave the same way. Whole-object comparison would report
permanent drift that no YAML edit could resolve, and the diff would never be
empty. Alternative considered: encode a default for every optional field and
compare against that. Rejected — it means maintaining a shadow copy of the
controller's defaults, per version, forever, and being wrong about one of them
silently reintroduces the same problem. The cost of the chosen approach is that
undeclared fields drift unnoticed, which `--show-undeclared` exposes rather than
hides.

## 2026-09-17 — Seven declarative resource types, not nine

The OpenAPI spec has nine writable types. Hotspot vouchers and device
adoption/actions are excluded: a voucher is a one-shot credential and adoption
is an event, so neither is state a file can describe. Reconciling them would
mean inventing a desired-state model the API does not have. Nine is the write
surface, not the list of things to reconcile.

## 2026-09-17 — Ownership is three-valued

`USER_DEFINED` is fully writable; `SYSTEM_DEFINED` with `configurable: true` is
update-only; `SYSTEM_DEFINED` with `configurable: false` and `DERIVED` are
untouchable. The two-valued version of this rule ("write user-defined objects
only") looks obviously right and is wrong: the `Default` network is
SYSTEM_DEFINED, and a site that repurposes it (as a management VLAN, say) needs
to change its subnet. Its settings are ours; its existence is the controller's.

A fifth case: objects with no `metadata` at all are treated as fully writable.
Traffic matching lists are the instance — their schema has no `metadata`
property, so there is no origin to read, and defaulting absent-to-unwritable
would make an existing list permanently unmanageable.

## 2026-09-17 — Names index only reference targets

Only zones, networks and matching lists get a name→ID index, because only those
are referenced by name from other objects. Policies are deliberately not indexed:
one UDM-SE had 126 policies sharing 14 names, 52 of them called "Block All
Traffic", so a name index over policies is both useless and a guaranteed
collision. Duplicate names are an error only when more than one *user-defined*
object shares one.

## 2026-09-17 — `_comment`, not `description`

Underscore-prefixed keys are stripped recursively before anything is compared or
sent. Firewall policies have a real `description` field, but zones and networks
do not, so a note written there would either be rejected on write or accepted and
discarded — and the second failure mode shows up as permanent drift, which is
worse.

## 2026-09-17 — A package, not a single file

Started as a single script. Split into a CLI plus a package once the client,
the resource table, the ownership rules and the diff were all real: client and
diff have no reason to know about each other, and the resource table is the part
that gets edited most. `cli.py` keeps argument handling and rendering and has no
API knowledge.

## 2026-09-17 — Pin the console version, assert at runtime

The first idea was to pin the OpenAPI snapshot matching the console's version.
No such artifact exists: Ubiquiti publishes one Network spec version at a time,
10.4.57 on this date, while consoles ran 10.6.101. `/unifi-api/network/openapi.json`
on the console serves the UniFi OS SPA shell, and
`/proxy/network/integration/v1/openapi.json` is a 404. So the spec is reference
material only; the guard that actually holds is comparing `GET /v1/info` to the
`network_version` pin in `site.yaml` before any write.

*Revised 2026-10-05: the spec is no longer kept in the repository. It is
Ubiquiti's document to publish, and nothing in the code reads it.*

## 2026-09-17 — Base URL tolerates a trailing `/v1`

Ubiquiti documents the base URL ending in `/integration/v1`, while paths in this
tool carry their own `/v1` so they read like the spec. The client strips a
trailing `/v1` from the base rather than making the documented URL wrong.

## 2026-09-17 — Policy ordering is per zone-pair, in two buckets

Discovered while writing the first policies, and it is a better model than the
one first assumed: a full-list PUT, with a warning never to interleave with
predefined policies. The actual endpoint is:

    GET|PUT /firewall/policies/ordering
            ?sourceFirewallZoneId=<X>&destinationFirewallZoneId=<Y>

    {"orderedFirewallPolicyIds": {
       "beforeSystemDefined": [id, ...],
       "afterSystemDefined":  [id, ...]}}

So ordering is scoped to a single **cell of the zone matrix**, and within that
cell user policies sit in one of two buckets relative to the controller's own
implicit policy. Three consequences:

- **Interleaving is structurally impossible**, so the warning is moot. You do not
  order against system policies, you choose which side of them you are on.
- **"Allow above block" is a within-cell property**, not a global one. IoT →
  Gateway's allow and block order relative to each other; they have no ordering
  relationship to anything in Clients → Core.
- **`beforeSystemDefined` is what makes a Gateway block work at all.** That cell's
  system default is Allow All, so a user Block only denies anything by being
  evaluated ahead of it. A Block placed in `afterSystemDefined` would be dead
  code — the system Allow would match first.

The tool therefore derives ordering from YAML list order *within each
(source, destination, placement) group*, and `policies.yaml` carries an optional
`placement:` defaulting to `BEFORE_SYSTEM`. A global order field would have been
both wrong and unnecessary.

Worth noting one non-finding: both query parameters *are* documented in the spec.
The 400s that surfaced this were my own omission, not another spec gap — unlike
the genuine discrepancies in [api-hazards.md](api-hazards.md).

## 2026-09-18 — Zone membership is refused out of order, not reordered

An audit found that `apply_plan` writes in dependency order -- zones, networks,
policies -- which is exactly backwards for segmenting a live network: policies
are inert while zones are empty, so they must land *before* networks move into
zones. One `--apply` after both YAML edits would have populated the zones first.

Alternative considered: have apply split each run into "everything but
membership" and "membership last". Rejected. It needs zone creates to be split
into create-empty-then-populate, which is the tool quietly rewriting what the
diff showed, and it turns the single most consequential write into a side
effect of an unrelated run. Refusing keeps what is sent identical to what was
displayed and makes membership its own reviewed run. The check reads the policy
plan even under `--only networks`, since that is the invocation most likely to
skip it.

## 2026-09-18 — Policy order is diffed, not only written

Order is not a field on any policy, so the field diff could not see a UI
reorder, and an apply with nothing else to do exited before the ordering step
ran. A dragged Block All above its allows was invisible and uncorrectable. The
plan now reads each declared cell's live order and reports mismatches, and
apply writes only those cells. Live order is filtered to the policies declared
for the cell; other user-defined policies in the cell make apply refuse,
because the ordering PUT lists only declared ids and what the controller does
with the rest is untested.

## 2026-09-18 — UI renames are detected heuristically, not tracked

Names are identity and nothing records which console id the tool last wrote,
so a rename in the UI looks like a create plus an unmanaged object, and applying
it makes a duplicate. Alternative considered: keep a last-applied id map and
match on id. Rejected -- it makes the diff three-way and adds a state file that
can go stale or be lost, for an event that happens rarely. Instead a create is
flagged when an unmanaged user-defined object matches it on identifying fields
(`match_fields` in the resource table), and apply refuses with an override for
the genuine coincidence.

## 2026-09-18 — Reference targets are always read

`--only policies` used to read only policies, so the resolver had no zones and
failed on the first `zone: Gateway`. Zones, networks and matching lists are now
read on every run whatever `--only` says; `--only` limits what is diffed and
written, not what is resolvable.

## 2026-09-21 — The Verified tier is its own file and its own mode

`verified.yaml` beside the Managed-tier files, checked by `--verify`, rather
than extra fields on the Managed types. The two tiers have opposite write
semantics -- one is applied, the other only asserted -- and mixing them in one
file would make every reader work out which fields `--apply` will touch. The
client grew `legacy_get` and deliberately no legacy write method, so "read-only"
is a property of the code rather than a promise.

## 2026-09-21 — No passphrase assertion, not even as a hash

An early sketch compared `x_passphrase` "as changed/unchanged". With no
last-applied state there is nothing to compare it to except a stored value, and
a stored hash of a WPA PSK is an offline brute-force target sitting in git.
Security *mode*, PMF, WPA3 and transition are asserted; the key is not. A
changed PSK is noticed the old-fashioned way: devices fall off.

## 2026-09-21 — SSIDs, APs and reservations are exhaustive

Everywhere else only declared objects are compared, but in these three the
drift that matters is the object nobody declared -- an Auto-Link SSID quietly
on VLAN 1, an adopted AP with default settings, a reservation made in the UI
and never recorded. So anything present and undeclared is reported. The SSID
set is the union of four views (`rest/wlanconf`, `vap_table`, `stat/sta`
associations, `element_adopt`) because the first two both hide system WLANs.

## 2026-09-21 — Legacy values compared loosely, booleans strictly

The legacy API is inconsistent about numeric types (a channel may be `36` or
`"36"`), so numbers compare as strings and asserted lists (bands, networks)
compare as sets. Booleans are never coerced: `true` must not equal `"True"`.

## 2026-09-24 — The key file follows `--config`, and each site names its own key

Found adding a second console. `--env-file` defaulted to one fixed file
whatever `--config` pointed at, and that file held a Site Manager key, which is
account-scoped: once the account is an admin on a second console, the key
reaches that console too. So a run against the second console that forgot
`--env-file` would have authenticated with the first console's key and worked,
and nothing would have said which key did what.

Two changes, either of which alone closes it. The default is now
`secrets.sops.env` in the parent directory of `--config`, so each site's key
file sits beside that site's YAML. And each `site.yaml` names its own
`api_key_env`, so one site's file never defines the variable another site asks
for. Alternative considered: make `--env-file` required. Rejected, since it
adds a flag to every invocation to guard against a mistake the derived default
already prevents.

Two smaller second-site changes in the same pass. A `host_id` still reading
`TODO:` is refused by name rather than sent to `api.ui.com`, since a
placeholder is how a site's `site.yaml` is written before its console exists.
And pre-change captures are named `<timestamp>-<console>`, so several consoles
can share a capture directory.

## 2026-10-05 — Packaged, and captures live with the site

Moved into its own repository as an installable package with an
`unifi-reconcile` command, so each site pins a tagged version with pip rather
than carrying a copy. Pre-change captures used to land in the tool's own
`state/` directory, which mixed every site's captures in one place, and an
installed package has no writable directory of its own anyway. They now
default to `.reconcile-state/` inside `--config`; `--state-dir` overrides.

## 2026-10-06 — sops is pointed at ~/.config/sops/age/keys.txt when unset

sops looks for age keys in its user config directory: `~/.config` on Linux,
`~/Library/Application Support` on macOS. A key kept at the Linux path on a Mac
works only while `SOPS_AGE_KEY_FILE` is set, and a profile is not always read.
Agent and IDE shells are often non-interactive and start from a desktop app's
environment, so the variable set in a shell rc file never reaches them, and
decryption failed there while it worked in a terminal. So when the variable is
unset or empty and that file exists, the tool sets it for the `sops` call only,
without changing its own environment. An explicit setting still wins, and on
Linux the value is sops's own default, so nothing changes there. Alternatives
considered: a key-file flag on the tool, rejected because it duplicates a
setting sops already has; and leaving it to the user's shell setup, rejected
because the failure only shows up in the environments that are hardest to see.

## 2026-10-06 — Dynamic DNS and VPN servers are verified, not managed

Neither can be written through integration v1, so both join the Verified tier
rather than the Managed one. Legacy writes were considered and rejected for the
reason the client has no legacy write method: full-record replaces with no
schema, on records that carry the DDNS password and the server's private key.

Two reads go beyond the legacy API. WireGuard peers and firewall zone names
exist only in the console's v2 API, so the client gained a read-only `v2_get`,
called only when `vpn_servers` is declared. And `resolves_to_wan` does a DNS
lookup, the tool's first read of anything but the console: a DDNS client that
stops updating leaves the console looking correct, and the only evidence is
the name answering with an old address. The lookup uses the resolver of the
machine running `--verify`, which is what a phone would ask too.

Peers are exhaustive and keyed by name, with the public key compared. A new
key under an old name means the peer was recreated, and an undeclared peer is
an unreviewed way in. Public keys are not secret, so `public_key` joins
redaction's allow list.
