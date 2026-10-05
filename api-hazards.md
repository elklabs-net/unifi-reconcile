# UniFi API hazards

Where the console differs from Ubiquiti's published OpenAPI spec (10.4.57 at the
time of writing; it is Ubiquiti's to publish, so it is not copied here), or from
what a careful client would assume. Each one is either handled in code or
is a trap to know about when writing desired state.

`Last seen:` is the newest Network version the hazard was observed on. It is a
record of evidence, not a claim that the hazard is gone on later versions. Most
of these only show on a write, so a tag stays put until an `--apply` exercises
the hazard again.

Last reviewed against: Network **10.6.106**.

Several were first documented in
[go-unifi#195](https://github.com/filipowm/go-unifi/issues/195), against the
same version.

## When a console's version changes

`site.yaml` pins `network_version`, and the tool refuses to run against a
console reporting anything else. That refusal is the only thing that says
whether the behavior below still holds, because Ubiquiti publishes one spec
version at a time and there is no per-release snapshot to pin.

1. Dry-run with `--allow-version-mismatch` and read the diff. A read-side
   hazard that changed shows up here as unexpected drift.
2. Run `--verify`. That covers the legacy reads: hidden WLANs, the mDNS site
   setting.
3. Walk this file. Bump `Last seen:` on anything the runs confirmed. Delete an
   entry that no longer holds, and the workaround with it; git keeps the
   history.
4. Move the pin in `site.yaml` in the same commit.

Each console upgrades on its own schedule, so each site's pin is a separate
fact.

## Writes

### GET-modify-PUT is not safe as-is

Last seen: 10.6.106 · Handled in: `sanitize.py`

A GET body carries fields the API rejects on write.
`dhcpGuarding.trustedDhcpServerIpAddresses` reads back as
`[<gateway>, "", ""]` and is a 400 when sent unchanged. Every update goes GET,
sanitize, merge, PUT: server-owned keys are stripped and empty strings dropped
from string lists.

### Networks have PUT and no PATCH, and PUT is a full replace

Last seen: 10.6.106 · Handled in: `sanitize.for_write`, `apply.py`

PUT requires `cellularBackupEnabled`, `enabled`, `internetAccessEnabled`,
`ipv4Configuration`, `isolationEnabled`, `name` and `vlanId`. A partial body
meant to set only `zoneId` silently drops the DHCP pool. Declare networks
whole.

### Policies have PATCH, but it only takes `loggingEnabled`

Last seen: 10.6.106 · Handled in: `resources.py` (`patchable=False`)

Sending any other field, `name` included, is a 400 `unknown-property`.
Policies are updated like networks: GET, sanitize, merge, full-replace PUT.

### Undocumented required fields on network create

Last seen: 10.6.106 · Handled in: `schema/networks.schema.json`

Creation needs `zoneId` and `dhcpConfiguration.pingConflictDetectionEnabled`,
though the spec marks both optional.

### A network PUT rewrites the site mDNS setting

Last seen: 10.6.106 · Handled in: `verify.py` (asserted, not written)

The reflector's scope is stored twice: per network (`mdnsForwardingEnabled` in
integration v1, `mdns_enabled` in legacy `networkconf`) and site-wide
(`get/setting` → `mdns.enabled_for` plus `enabled_for_network_ids`). A PUT
carrying `mdnsForwardingEnabled: true` adds that network to the site list. If
the site was on `all`, it first converts to an explicit list holding only that
network; once every network is listed, it folds back to `all`.

So a run that PUTs *some* networks while the site is on `all` narrows the
reflector to those networks, silently, and a run that PUTs every network leaves
it on `all`. The per-network flag does not change, so neither the dry run nor a
pre-change capture sees it. Only `--verify` does, which is why the site setting
is asserted there as `enabled_for` rather than as a network list: `all` stores
an empty list. Whether `mdnsForwardingEnabled: false` on a PUT removes a network
from the list is untested.

The console's Admin Activity log records each change as `actor: UNKNOWN` in the
same second as the PUT. It is
`POST /proxy/network/v2/api/site/default/system-log/admin-activity` with
`{timestampFrom, timestampTo, pageSize, pageNumber}`, in the internal v2 API: a
read despite the POST.

## Firewall policies

### `allowReturnTraffic` is required on every ALLOW, and refused toward Gateway

Last seen: 10.6.106 · Handled in: `schema/policies.schema.json`

Omitting it is a 400 (`must not be null`). `true` makes the controller derive a
`<name> (Return)` policy (`DERIVED` origin) in the mirrored cell, and that is
how return traffic survives: the system `Block All Traffic` in the reverse cell
has no connection-state filter, so it matches ESTABLISHED too. Toward the
Gateway zone `true` is a 400 (`cant-allow-return-traffic`), because
`Gateway → X` is already Allow All.

### `NAMED_PROTOCOL` nests the name

Last seen: 10.6.106 · Handled in: `schema/policies.schema.json`

`{type: NAMED_PROTOCOL, matchOpposite: false, protocol: {name: TCP}}`. A flat
`name` beside `type` is rejected.

### Protocol names must be uppercase

Last seen: 10.6.106 · Handled in: `schema/policies.schema.json`

`UDP`, `ICMP`, or a preset object
(`{"type": "PRESET", "preset": {"name": "TCP_UDP"}}`). The spec contradicts
itself: the named-protocol enum generates lowercase (`tcp`) while the
discriminator mapping keys are uppercase.

### Traffic-filter types are the console's list, not the spec's

Last seen: 10.6.106 · Handled in: `schema/policies.schema.json`

An IP filter is `IP_ADDRESS`, not `IP`. The 400 enumerates the valid set:
`PORT`, `NETWORK`, `MAC_ADDRESS`, `IP_ADDRESS`, `IPV6_IID`, `REGION`,
`VPN_SERVER`, `SITE_TO_SITE_VPN_TUNNEL`.

## Reads

### The networks collection is a projection

Last seen: 10.6.106 · Handled in: `Resource.detail_get`

`GET .../networks` omits `ipv4Configuration`, `isolationEnabled`,
`internetAccessEnabled` and the DHCP block. Networks are fetched again per
object.

### Collection endpoints hide system-generated WLANs

Last seen: 10.6.106 · Handled in: `verify._observed_ssids`

`rest/wlanconf` returns only user SSIDs. A system-generated WLAN, such as the
one the **UniFi Auto-Link** setting (`element_adopt`) creates, is omitted
entirely, though `rest/wlanconf/<id>` returns it. Each AP's `vap_table` omits it
too, while listing hidden *user* SSIDs normally, so the filter is on system
origin rather than `hide_ssid`. Such a WLAN can carry no `networkconf_id`, which
puts it on the default network, VLAN 1.

A drift check that enumerates from a collection cannot see what the collection
omits. The SSID set `--verify` checks is the union of `rest/wlanconf`, every
AP's `vap_table`, the `essid` of every associated client (`stat/sta`) and the
Auto-Link setting. The Auto-Link WLAN has come back as `enabled: true` after
firmware upgrades.

### A single-object GET can return a secret the collection does not

Last seen: 10.6.106 · Handled in: `redact.py`

The `wifi/broadcasts` collection returns `securityConfiguration: {type: ...}`
and no PSK, but `wifi/broadcasts/{id}` returns
`securityConfiguration.passphrase` in cleartext. Redaction is by field name,
not by endpoint, for this reason.

### Client groups are invisible to both APIs this tool reads

Last seen: 10.6.106 · Handled in: nothing; a trap when reading the UI

The UI's per-client **Groups** field shows MAC-based client groups
(`network-members-groups`), which live only in the internal v2 API: not in
integration v1, and not in `rest/firewallgroup`. A client group and a traffic
matching list can share a name, and the UI then makes one look like the other.
Traffic matching lists, the ZBF-era object and not the legacy `firewallgroup`
IP-group alias, are under **Settings → Networks → Network Lists**.
