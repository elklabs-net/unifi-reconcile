"""Make a GET body safe to send back in a PUT.

`networks` has PUT and no PATCH, and PUT is a full replace: a partial body
intended to change one field silently drops everything omitted. So the only
correct update is GET, merge the desired fields in, PUT the whole thing back.

That round-trip is not safe as-is, which is the part worth being careful about.
A GET response carries fields the API will not accept on write, and
[go-unifi#195](https://github.com/filipowm/go-unifi/issues/195) documents the
worst of them: `dhcpGuarding.trustedDhcpServerIpAddresses` reads back as
`[<gateway>, "", ""]` and is rejected with a 400 when sent unchanged. Reading
your own data and handing it straight back should not fail, and here it does.

So: GET, **sanitize**, merge, PUT.
"""

from __future__ import annotations

#: Server-owned fields. Present in every GET, rejected or ignored on write.
READ_ONLY = {
    "id",
    "metadata",
    "index",
    "default",
    "references",
}


def strip_read_only(body):
    """Drop server-owned keys, recursively."""
    if isinstance(body, list):
        return [strip_read_only(item) for item in body]
    if isinstance(body, dict):
        return {
            key: strip_read_only(value)
            for key, value in body.items()
            if key not in READ_ONLY
        }
    return body


def drop_empty_strings_in_lists(body):
    """Remove "" entries from string lists.

    Narrowly aimed at `dhcpGuarding.trustedDhcpServerIpAddresses`, which reads
    back padded with empty strings and is rejected on write. Applied generally
    to string lists because the padding is an artifact of how the controller
    serializes fixed-width arrays, not something specific to that one field --
    and an empty string is never a meaningful entry in any list this tool sends.
    """
    if isinstance(body, dict):
        return {k: drop_empty_strings_in_lists(v) for k, v in body.items()}
    if isinstance(body, list):
        cleaned = [drop_empty_strings_in_lists(v) for v in body]
        if all(isinstance(v, str) for v in cleaned):
            return [v for v in cleaned if v != ""]
        return cleaned
    return body


def for_write(live_body, desired_body):
    """Build a PUT body: sanitize what the console returned, then merge desired.

    Desired wins on every key it declares. Keys the YAML does not mention keep
    the console's current value, which is what makes a full-replace PUT safe to
    use for a partial change -- and is the same "only declared fields are owned"
    rule the diff uses, applied to writes.

    Except across a change of `type`. The API's polymorphic objects (DNS
    policies, traffic filters, Wi-Fi security) are discriminated by `type`, and
    each type has its own fields: carrying the old type's fields into the new
    one is a 400 (`api.request.unknown-property`). So wherever the desired
    object's `type` differs from the live one's, at any depth, the desired
    object replaces it whole, and the YAML must declare everything the new type
    needs. `type_change_drops` lists what that leaves behind, for the diff.
    """
    merged = drop_empty_strings_in_lists(strip_read_only(live_body or {}))
    return _deep_merge(merged, desired_body or {})


def _type_changes(base, overlay):
    """True when both declare a `type` and they differ."""
    return ("type" in base and "type" in overlay
            and base["type"] != overlay["type"])


def _deep_merge(base, overlay):
    if _type_changes(base, overlay):
        return dict(overlay)
    out = dict(base)
    for key, value in overlay.items():
        if isinstance(value, dict) and isinstance(out.get(key), dict):
            out[key] = _deep_merge(out[key], value)
        else:
            out[key] = value
    return out


def type_change_drops(live_body, desired_body, prefix=""):
    """Live fields an update will not send because their object changes `type`.

    Returns (dotted path, live value) pairs, in the order the console returned
    them, for the diff to show before anything is written. Server-owned keys are
    left out: they are never sent anyway.
    """
    live = strip_read_only(live_body or {})
    desired = desired_body or {}
    if not isinstance(live, dict) or not isinstance(desired, dict):
        return []
    if _type_changes(live, desired):
        return [(f"{prefix}{key}", value) for key, value in live.items()
                if key not in desired]
    drops = []
    for key, value in desired.items():
        if isinstance(value, dict) and isinstance(live.get(key), dict):
            drops += type_change_drops(live[key], value, f"{prefix}{key}.")
    return drops


def for_create(desired_body):
    """A create body is the desired state with nothing server-owned in it."""
    return strip_read_only(desired_body or {})
