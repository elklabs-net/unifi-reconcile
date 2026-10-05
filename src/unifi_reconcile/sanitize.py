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
    """
    merged = drop_empty_strings_in_lists(strip_read_only(live_body or {}))
    return _deep_merge(merged, desired_body or {})


def _deep_merge(base, overlay):
    out = dict(base)
    for key, value in overlay.items():
        if isinstance(value, dict) and isinstance(out.get(key), dict):
            out[key] = _deep_merge(out[key], value)
        else:
            out[key] = value
    return out


def for_create(desired_body):
    """A create body is the desired state with nothing server-owned in it."""
    return strip_read_only(desired_body or {})
