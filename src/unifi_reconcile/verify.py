"""The Verified tier: assert intended state the integration API cannot write.

Reservations, radio settings, per-port VLANs, WAN DNS forwarders, static
routes, Dynamic DNS, VPN servers, Auto-Link, site mDNS and IPS mode are all absent from integration v1 for writing -- most
of them for reading too -- but readable through the legacy API, and WireGuard
peers through the v2 API. So intended
state is recorded in `verified.yaml`, read back from the console, and drift is
reported. Nothing here writes; the UI stays the write path for this tier.

Same rules as the Managed-tier diff, on purpose:

- Only declared fields are compared. An undeclared field can drift unnoticed;
  that is the price of a report that can come back clean.
- Objects are keyed by something stable across consoles -- MAC, SSID name, WAN
  name, (device MAC, port index) -- never the legacy 24-hex `_id`.
- Networks are named in YAML and resolved to legacy ids at runtime.

Some sections are exhaustive -- reservations, SSIDs, access points, static
routes -- because the drift that matters most there is an object nobody
declared: a forgotten reservation, a system-generated SSID broadcasting on the
wrong VLAN, or a route pinning a subnet that a renumber then cannot move. The
SSID set is assembled from four sources for exactly that reason; see
`_observed_ssids`.

Output is redacted like every other path out of this tool, and `load` refuses
a verified.yaml containing any secret-named key, so a passphrase cannot be
committed by mistake.
"""

from __future__ import annotations

import json
import os
import socket

from . import redact as redactmod

SCHEMA = os.path.join(os.path.dirname(__file__), "schema",
                      "verified.schema.json")
YAML_FILE = "verified.yaml"

CHANGED, MISSING, UNEXPECTED = "changed", "missing", "unexpected"


class VerifyError(RuntimeError):
    """verified.yaml is malformed, or names something the console lacks."""


class Finding:
    def __init__(self, section, identity, kind, field=None, expected=None,
                 actual=None, note=None):
        self.section = section
        self.identity = identity
        self.kind = kind
        self.field = field
        self.expected = expected
        self.actual = actual
        self.note = note

    def as_dict(self):
        secret = self.field and redactmod.is_secret(self.field.rsplit(".", 1)[-1])
        return {
            "section": self.section,
            "identity": self.identity,
            "kind": self.kind,
            "field": self.field,
            "expected": redactmod.PLACEHOLDER if secret else self.expected,
            "actual": redactmod.PLACEHOLDER if secret else self.actual,
            "note": self.note,
        }


# ---- loading ---------------------------------------------------------------

def load(config_dir):
    """Read and validate verified.yaml. Returns None when the site has none."""
    import yaml

    path = os.path.join(config_dir, YAML_FILE)
    if not os.path.exists(path):
        return None
    with open(path) as handle:
        desired = yaml.safe_load(handle) or {}
    desired = _strip_comments(desired)

    leaked = sorted(_secret_keys(desired))
    if leaked:
        raise VerifyError(
            f"{YAML_FILE} contains secret-named keys ({', '.join(leaked)}). "
            "The Verified tier asserts configuration, never credentials -- "
            "passphrases stay out of version control."
        )

    try:
        import jsonschema
    except ImportError as exc:  # pragma: no cover
        raise VerifyError("jsonschema is not installed; pip install "
                          "jsonschema") from exc
    with open(SCHEMA) as handle:
        schema = json.load(handle)
    errors = sorted(
        jsonschema.Draft202012Validator(schema).iter_errors(desired),
        key=lambda e: list(e.path),
    )
    if errors:
        raise VerifyError(
            f"{YAML_FILE} failed schema validation:\n  " + "\n  ".join(
                f"{'/'.join(str(p) for p in e.path) or '(root)'}: {e.message}"
                for e in errors
            )
        )
    return desired


def _strip_comments(value):
    if isinstance(value, dict):
        return {k: _strip_comments(v) for k, v in value.items()
                if not str(k).startswith("_")}
    if isinstance(value, list):
        return [_strip_comments(v) for v in value]
    return value


def _secret_keys(value, found=None):
    found = set() if found is None else found
    if isinstance(value, dict):
        for key, val in value.items():
            if redactmod.is_secret(key):
                found.add(key)
            _secret_keys(val, found)
    elif isinstance(value, list):
        for item in value:
            _secret_keys(item, found)
    return found


# ---- reading the console -----------------------------------------------------

#: Legacy endpoints the Verified tier reads, keyed by the name used in dumps.
SOURCES = {
    "networkconf": "rest/networkconf",
    "setting": "get/setting",
    "wlanconf": "rest/wlanconf",
    "device": "stat/device",
    "sta": "stat/sta",
    "user": "rest/user",
    "routing": "rest/routing",
    "dynamicdns": "rest/dynamicdns",
}

#: v2 endpoints, read only when verified.yaml declares vpn_servers, so a site
#: without one never depends on the v2 API answering.
V2_SOURCES = {
    "wireguard_users": "wireguard/users",
    "zones": "firewall/zone",
}


def collect(client, site="default", desired=None):
    """Fetch every source once. Raw -- redact before showing any of it."""
    live = {name: client.legacy_get(path, site=site)
            for name, path in SOURCES.items()}
    wanted = desired is None or "vpn_servers" in desired
    for name, path in V2_SOURCES.items():
        live[name] = (client.v2_get(path, site=site) or []) if wanted else []
    return live


# ---- comparison --------------------------------------------------------------

def check(desired, live):
    """Compare verified.yaml against legacy console state. Returns findings."""
    ctx = _Context(live)
    findings = []
    for section, fn in (
        ("wan", _check_wan),
        ("settings", _check_settings),
        ("wifi", _check_wifi),
        ("radios", _check_radios),
        ("ports", _check_ports),
        ("reservations", _check_reservations),
        ("static_routes", _check_static_routes),
        ("dynamic_dns", _check_dynamic_dns),
        ("vpn_servers", _check_vpn_servers),
    ):
        if section in desired:
            findings.extend(fn(desired[section], ctx))
    return findings


class _Context:
    def __init__(self, live):
        self.live = live
        self.net_name = {n["_id"]: n.get("name") for n in live["networkconf"]}
        self.net_id = {v: k for k, v in self.net_name.items()}
        self.settings = {s.get("key"): s for s in live["setting"]}
        # A WAN is "wan" or "wan2" in Dynamic DNS and VPN records, "WAN" or
        # "WAN2" as a network's group, and "wan1"/"wan2" on the gateway device.
        self.wan_name = {str(n.get("wan_networkgroup", "")).lower(): n.get("name")
                         for n in live["networkconf"] if n.get("purpose") == "wan"}
        gateways = [d for d in live["device"] if d.get("type") in ("udm", "ugw", "uxg")]
        self.gateway = gateways[0] if gateways else {}
        self.zone_name = {z.get("_id"): z.get("name") for z in live.get("zones") or []}

    def wan_ip(self, interface):
        """The gateway's current address on a WAN, by its Dynamic DNS/VPN name."""
        key = {"wan": "wan1"}.get(interface, interface)
        return (self.gateway.get(key) or {}).get("ip")

    def names(self, ids):
        return [self.net_name.get(i, f"<unknown network {i}>") for i in ids or []]

    def resolve(self, section, name):
        if name not in self.net_id:
            raise VerifyError(
                f"{section}: network {name!r} does not exist on the console. "
                f"Known: {', '.join(sorted(n for n in self.net_id if n))}"
            )
        return self.net_id[name]


def _norm(value):
    """Make YAML and legacy JSON spellings of one value compare equal.

    Numbers compare as strings because the legacy API is inconsistent about
    them (a channel can be 36 or "36"); lists compare as sets because every list
    asserted here -- bands, networks -- has no meaningful order. Booleans are
    left alone: True must never equal "True".
    """
    if isinstance(value, bool) or value is None:
        return value
    if isinstance(value, (int, float)):
        return str(int(value)) if float(value).is_integer() else str(value)
    if isinstance(value, list):
        return sorted((_norm(v) for v in value), key=lambda v: json.dumps(v, default=str))
    return value


def _compare(section, identity, expected_map, actual_map):
    out = []
    for field, want in expected_map.items():
        have = actual_map.get(field)
        if _norm(want) != _norm(have):
            out.append(Finding(section, identity, CHANGED, field, want, have))
    return out


def _check_wan(declared, ctx):
    wans = {n.get("name"): n for n in ctx.live["networkconf"]
            if n.get("purpose") == "wan"}
    out = []
    for wan in declared:
        name = wan["name"]
        live = wans.get(name)
        if live is None:
            out.append(Finding("wan", name, MISSING,
                               note=f"no WAN named {name!r} (have: "
                                    f"{', '.join(sorted(wans))})"))
            continue
        fields = {"dns_preference": "wan_dns_preference",
                  "dns1": "wan_dns1", "dns2": "wan_dns2"}
        out += _compare("wan", name,
                        {k: wan[k] for k in fields if k in wan},
                        {k: live.get(v) for k, v in fields.items()})
    return out


def _check_settings(declared, ctx):
    out = []
    s = ctx.settings
    if "auto_link" in declared:
        out += _compare("settings", "auto_link",
                        {"enabled": declared["auto_link"]},
                        {"enabled": s.get("element_adopt", {}).get("enabled")})
    if "mdns" in declared:
        live = s.get("mdns", {})
        want = dict(declared["mdns"])
        have = {"mode": live.get("mode"),
                "enabled_for": live.get("enabled_for"),
                "networks": ctx.names(live.get("enabled_for_network_ids"))}
        for n in want.get("networks", []):
            ctx.resolve("settings.mdns", n)
        out += _compare("settings", "mdns", want, have)
    if "ips" in declared:
        live = s.get("ips", {})
        want = dict(declared["ips"])
        have = {"mode": live.get("ips_mode"),
                "networks": ctx.names(live.get("enabled_networks"))}
        for n in want.get("networks", []):
            ctx.resolve("settings.ips", n)
        out += _compare("settings", "ips", want, have)
    return out


#: YAML field -> legacy wlanconf field.
WLAN_FIELDS = {
    "enabled": "enabled",
    "security": "security",
    "wpa_mode": "wpa_mode",
    "wpa3": "wpa3_support",
    "wpa3_transition": "wpa3_transition",
    "pmf": "pmf_mode",
    "hidden": "hide_ssid",
    "fast_roaming": "fast_roaming_enabled",
    "bands": "wlan_bands",
}


def _observed_ssids(ctx):
    """Every SSID the console is broadcasting, by any account, with provenance.

    `rest/wlanconf` omits system-generated WLANs such as the Auto-Link SSID,
    and each AP's `vap_table` omits them too (api-hazards.md). So the set is
    the union of four views, and an SSID reported by any one of them that is
    not declared is drift:

    - wlanconf: the user WLAN collection
    - vap_table: what each AP says it is broadcasting
    - associated: essids clients are actually connected to (stat/sta)
    - auto_link: the element_adopt SSID, when that setting is on
    """
    seen = {}

    def add(ssid, source):
        if ssid:
            seen.setdefault(ssid, set()).add(source)

    for w in ctx.live["wlanconf"]:
        add(w.get("name"), "wlanconf")
    for d in ctx.live["device"]:
        for vap in d.get("vap_table") or []:
            add(vap.get("essid"), "vap_table")
    for sta in ctx.live["sta"]:
        if not sta.get("is_wired"):
            add(sta.get("essid"), "associated")
    ea = ctx.settings.get("element_adopt", {})
    if ea.get("enabled"):
        add(ea.get("x_element_essid"), "auto_link")
    return seen


def _check_wifi(declared, ctx):
    out = []
    wlans = {w.get("name"): w for w in ctx.live["wlanconf"]}
    declared_names = set()
    for ssid in declared:
        name = ssid["ssid"]
        declared_names.add(name)
        live = wlans.get(name)
        if live is None:
            out.append(Finding("wifi", name, MISSING,
                               note="declared but not in rest/wlanconf"))
            continue
        if "network" in ssid:
            ctx.resolve(f"wifi.{name}", ssid["network"])
            out += _compare("wifi", name, {"network": ssid["network"]},
                            {"network": ctx.net_name.get(live.get("networkconf_id"),
                                                         live.get("networkconf_id"))})
        out += _compare("wifi", name,
                        {k: ssid[k] for k in WLAN_FIELDS if k in ssid},
                        {k: live.get(v) for k, v in WLAN_FIELDS.items()})
    for name, sources in sorted(_observed_ssids(ctx).items()):
        if name not in declared_names:
            out.append(Finding(
                "wifi", name, UNEXPECTED,
                note="broadcasting but not declared (seen in: "
                     + ", ".join(sorted(sources)) + ")"))
    return out


RADIO_FIELDS = ("channel", "ht", "tx_power_mode", "tx_power",
                "min_rssi_enabled", "min_rssi")


def _check_radios(declared, ctx):
    out = []
    defaults = declared.get("defaults", {})
    aps = {d["mac"]: d for d in ctx.live["device"] if d.get("type") == "uap"}
    listed = set()
    for ap in declared.get("access_points", []):
        mac = ap["mac"].lower()
        listed.add(mac)
        label = ap.get("name", mac)
        live = aps.get(mac)
        if live is None:
            out.append(Finding("radios", label, MISSING,
                               note=f"no access point with MAC {mac}"))
            continue
        if "name" in ap and ap["name"] != live.get("name"):
            out.append(Finding("radios", label, CHANGED, "name", ap["name"],
                               live.get("name")))
        by_band = {r.get("radio"): r for r in live.get("radio_table") or []}
        overrides = ap.get("bands", {})
        for band in sorted(set(defaults) | set(overrides)):
            want = {**defaults.get(band, {}), **overrides.get(band, {})}
            radio = by_band.get(band)
            if radio is None:
                # An AP without a 6 GHz radio is not drift against a 6e default.
                if band in overrides:
                    out.append(Finding("radios", f"{label} {band}", MISSING,
                                       note="no such radio on this AP"))
                continue
            out += _compare("radios", f"{label} {band}", want,
                            {k: radio.get(k) for k in RADIO_FIELDS})
    for mac, live in sorted(aps.items()):
        if mac not in listed:
            out.append(Finding("radios", live.get("name") or mac, UNEXPECTED,
                               note=f"access point {mac} is not declared"))
    return out


#: YAML field -> legacy port_overrides field. Network-valued fields resolve.
PORT_FIELDS = {
    "native": "native_networkconf_id",
    "tagged": "tagged_vlan_mgmt",
    "excluded": "excluded_networkconf_ids",
    "forward": "forward",
    "poe": "poe_mode",
}
PORT_NETWORK_FIELDS = {"native", "excluded"}


def _check_ports(declared, ctx):
    out = []
    devices = {d["mac"]: d for d in ctx.live["device"]}
    for dev in declared:
        mac = dev["mac"].lower()
        label = dev.get("name", mac)
        live = devices.get(mac)
        if live is None:
            out.append(Finding("ports", label, MISSING,
                               note=f"no device with MAC {mac}"))
            continue
        overrides = {p.get("port_idx"): p for p in live.get("port_overrides") or []}
        for port in dev["ports"]:
            idx = port["port"]
            ident = f"{label} port {idx}"
            po = overrides.get(idx)
            if po is None:
                out.append(Finding("ports", ident, MISSING,
                                   note="no override on this port (defaults apply)"))
                continue
            want, have = {}, {}
            for field, key in PORT_FIELDS.items():
                if field not in port:
                    continue
                want[field] = port[field]
                raw = po.get(key)
                if field in PORT_NETWORK_FIELDS:
                    for n in (port[field] if isinstance(port[field], list)
                              else [port[field]]):
                        ctx.resolve(ident, n)
                    raw = (ctx.names(raw) if isinstance(raw, list)
                           else ctx.net_name.get(raw, raw))
                have[field] = raw
            out += _compare("ports", ident, want, have)
    return out


def _check_reservations(declared, ctx):
    out = []
    live = {u["mac"].lower(): u for u in ctx.live["user"] if u.get("use_fixedip")}
    listed = set()
    for r in declared:
        mac = r["mac"].lower()
        listed.add(mac)
        label = f"{r['ip']} {r.get('name') or mac}"
        u = live.get(mac)
        if u is None:
            out.append(Finding("reservations", label, MISSING,
                               note=f"no fixed-IP reservation for {mac}"))
            continue
        want = {"ip": r["ip"]}
        have = {"ip": u.get("fixed_ip")}
        if "name" in r:
            want["name"], have["name"] = r["name"], u.get("name")
        out += _compare("reservations", label, want, have)
    for mac, u in sorted(live.items(), key=lambda kv: _ip_key(kv[1].get("fixed_ip"))):
        if mac not in listed:
            out.append(Finding(
                "reservations", f"{u.get('fixed_ip')} {u.get('name') or u.get('hostname') or mac}",
                UNEXPECTED, note=f"reserved on the console for {mac}, not declared"))
    return out


#: verified.yaml route type -> legacy `static-route_type`.
ROUTE_TYPES = {"next_hop": "nexthop-route", "interface": "interface-route",
               "blackhole": "blackhole"}


def _check_static_routes(declared, ctx):
    """Keyed by route name. The interface of an interface route is stored as a
    network id on some firmware and a bare WAN name on others, so an id that
    resolves is shown as its network name and anything else is compared as is."""
    out = []
    live = {r.get("name"): r for r in ctx.live["routing"]
            if r.get("type") == "static-route"}
    kinds = {v: k for k, v in ROUTE_TYPES.items()}
    listed = set()
    for r in declared:
        name = r["name"]
        listed.add(name)
        u = live.get(name)
        if u is None:
            out.append(Finding("static_routes", name, MISSING,
                               note=f"no static route named {name!r}"))
            continue
        iface = u.get("static-route_interface")
        have = {"destination": u.get("static-route_network"),
                "type": kinds.get(u.get("static-route_type"), u.get("static-route_type")),
                "next_hop": u.get("static-route_nexthop"),
                "interface": ctx.net_name.get(iface, iface),
                "distance": u.get("static-route_distance"),
                "enabled": u.get("enabled")}
        want = {k: r[k] for k in have if k in r}
        out += _compare("static_routes", name, want, have)
    for name, u in sorted(live.items(), key=lambda kv: kv[0] or ""):
        if name not in listed:
            out.append(Finding(
                "static_routes", name or "<unnamed>", UNEXPECTED,
                note=f"{u.get('static-route_network')} on the console, not declared"))
    return out


def _resolve_ipv4(host):
    try:
        return sorted({a[4][0] for a in socket.getaddrinfo(host, None, socket.AF_INET)})
    except (socket.gaierror, UnicodeError):
        return []


#: Module-level so a test can swap in a resolver that needs no network.
resolve_ipv4 = _resolve_ipv4


def _check_resolves(section, identity, host, interface, ctx):
    """`resolves_to_wan`: the name a client is given answers with the address
    the gateway holds right now. This is the drift a Dynamic DNS client that
    quietly stopped updating produces, and nothing on the console shows it.
    It asks this machine's resolver, so it reads what clients would see from
    wherever --verify runs."""
    want = ctx.wan_ip(interface)
    if not want:
        return [Finding(section, identity, CHANGED, "resolves_to", "the WAN address",
                        None, note=f"the gateway reports no address on {interface!r}")]
    have = resolve_ipv4(host) if host else []
    if want in have:
        return []
    return [Finding(section, identity, CHANGED, "resolves_to", want,
                    have or f"{host or 'no hostname'} does not resolve")]


def _check_dynamic_dns(declared, ctx):
    """Keyed by hostname, and exhaustive: an extra Dynamic DNS entry publishes
    the house's address under a name nobody declared."""
    out = []
    live = {d.get("host_name"): d for d in ctx.live["dynamicdns"]}
    listed = set()
    for entry in declared:
        host = entry["hostname"]
        listed.add(host)
        d = live.get(host)
        if d is None:
            out.append(Finding("dynamic_dns", host, MISSING,
                               note="no Dynamic DNS entry for this hostname"))
            continue
        have = {"service": d.get("service"),
                "wan": ctx.wan_name.get(d.get("interface"), d.get("interface")),
                "server": d.get("server"),
                "login": d.get("login")}
        out += _compare("dynamic_dns", host, {k: entry[k] for k in have if k in entry}, have)
        if entry.get("resolves_to_wan"):
            out += _check_resolves("dynamic_dns", host, host, d.get("interface"), ctx)
    for host, d in sorted(live.items(), key=lambda kv: kv[0] or ""):
        if host not in listed:
            out.append(Finding("dynamic_dns", host or "<no hostname>", UNEXPECTED,
                               note=f"{d.get('service')} entry on the console, not declared"))
    return out


#: Legacy vpn_type -> the type verified.yaml declares.
VPN_TYPES = {"wireguard-server": "wireguard", "openvpn-server": "openvpn",
             "l2tp-server": "l2tp", "pptp-server": "pptp"}


def _check_vpn_servers(declared, ctx):
    """Keyed by name, and exhaustive, as are each server's peers: the drift
    that matters is a way in, or a phone, that nobody declared. Teleport is not
    a VPN server network and does not appear here. `wan`, `client_address` and
    `peers` are read from WireGuard's fields; other types leave them unset."""
    out = []
    live = {n.get("name"): n for n in ctx.live["networkconf"]
            if n.get("purpose") == "remote-user-vpn"}
    listed = set()
    for server in declared:
        name = server["name"]
        listed.add(name)
        n = live.get(name)
        if n is None:
            out.append(Finding("vpn_servers", name, MISSING,
                               note="no VPN server with this name"))
            continue
        iface = n.get("wireguard_interface")
        override = (n.get("vpn_client_configuration_remote_ip_override")
                    if n.get("vpn_client_configuration_remote_ip_override_enabled") else None)
        have = {"type": VPN_TYPES.get(n.get("vpn_type"), n.get("vpn_type")),
                "enabled": n.get("enabled"),
                "subnet": n.get("ip_subnet"),
                "port": n.get("local_port"),
                "wan": ctx.wan_name.get(iface, iface),
                "zone": ctx.zone_name.get(n.get("firewall_zone_id"), n.get("firewall_zone_id")),
                "client_address": override}
        out += _compare("vpn_servers", name, {k: server[k] for k in have if k in server}, have)
        if server.get("resolves_to_wan"):
            out += _check_resolves("vpn_servers", name, override, iface, ctx)
        if "peers" in server:
            out += _check_peers(name, server["peers"], n.get("_id"), ctx)
    for name, n in sorted(live.items(), key=lambda kv: kv[0] or ""):
        if name not in listed:
            out.append(Finding("vpn_servers", name or "<unnamed>", UNEXPECTED,
                               note=f"{n.get('vpn_type')} on {n.get('ip_subnet')}, not declared"))
    return out


def _check_peers(server_name, declared, network_id, ctx):
    out = []
    live = {u.get("name"): u for u in ctx.live["wireguard_users"]
            if u.get("network_id") == network_id}
    listed = set()
    for peer in declared:
        ident = f"{server_name} / {peer['name']}"
        listed.add(peer["name"])
        u = live.get(peer["name"])
        if u is None:
            out.append(Finding("vpn_servers", ident, MISSING, note="no such peer"))
            continue
        have = {"ip": u.get("interface_ip"), "public_key": u.get("public_key")}
        out += _compare("vpn_servers", ident, {k: peer[k] for k in have if k in peer}, have)
    for name, u in sorted(live.items(), key=lambda kv: kv[0] or ""):
        if name not in listed:
            out.append(Finding("vpn_servers", f"{server_name} / {name}", UNEXPECTED,
                               note=f"peer at {u.get('interface_ip')}, not declared"))
    return out


def _ip_key(ip):
    try:
        return tuple(int(p) for p in (ip or "").split("."))
    except ValueError:
        return (999,)


# ---- rendering ---------------------------------------------------------------

SYMBOL = {CHANGED: "~", MISSING: "-", UNEXPECTED: "+"}


def render(findings, desired, site_name, version, color=True):
    def paint(text, code):
        return f"\033[{code}m{text}\033[0m" if color else text

    lines = [f"verify {site_name}  (Network {version})", ""]
    for section in ("wan", "settings", "wifi", "radios", "ports", "reservations",
                    "static_routes", "dynamic_dns", "vpn_servers"):
        if section not in desired:
            continue
        mine = [f for f in findings if f.section == section]
        if not mine:
            lines.append(f"  {section} " + paint("ok", "32"))
            continue
        lines.append(f"  {section}")
        for f in mine:
            d = f.as_dict()
            head = f"    {SYMBOL[f.kind]} {f.identity}"
            if f.kind == CHANGED:
                lines.append(paint(
                    f"{head}  {f.field}: expected {_show(d['expected'])}, "
                    f"found {_show(d['actual'])}", "33"))
            else:
                lines.append(paint(f"{head}  ({f.note})",
                                   "31" if f.kind == UNEXPECTED else "33"))
    lines.append("")
    if findings:
        counts = {k: sum(1 for f in findings if f.kind == k)
                  for k in (CHANGED, MISSING, UNEXPECTED)}
        lines.append(
            f"Drift: {counts[CHANGED]} changed, {counts[MISSING]} missing, "
            f"{counts[UNEXPECTED]} unexpected. The UI is the write path for this "
            "tier -- fix it there, or update verified.yaml if the console is "
            "right.")
    else:
        lines.append("No drift. Console matches verified.yaml.")
    return "\n".join(lines)


def _show(value):
    return json.dumps(value, default=str) if not isinstance(value, str) else value
