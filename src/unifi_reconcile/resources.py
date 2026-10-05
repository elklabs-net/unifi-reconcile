"""The resource registry: what this tool can read, and how each type behaves.

Everything specific to a UniFi resource type lives here rather than being
spread through the reconciler. Adding a type is a table entry.

Scope note. The OpenAPI spec has nine writable resource types. Seven of them are declarative state and appear below. The other two --
hotspot vouchers and device adoption/actions -- are imperative operations
against a console, not state a file can describe: a voucher is a one-shot
credential and adoption is an event. Reconciling them would mean inventing a
desired-state model the API does not have. They stay out, and the count of
declarative types is seven.
"""

from __future__ import annotations

from collections import OrderedDict

#: How far the tool may go with an existing object. See Resource.writability.
FULL = "full"
UPDATE_ONLY = "update-only"
NONE = "none"

#: YAML key -> (registry key of the referenced type, API field it becomes).
#:
#: The YAML names objects; the API wants UUIDs that differ per console. The
#: resolver walks desired state recursively and rewrites these keys wherever
#: they appear, at any nesting depth -- which is what lets a policy say
#: `source: {zone: IoT}` and a zone say `networks: [Core]` with one mechanism.
REFERENCE_KEYS = {
    "zone": ("zones", "zoneId"),
    "zones": ("zones", "zoneIds"),
    "network": ("networks", "networkId"),
    "networks": ("networks", "networkIds"),
    "matchingList": ("matching-lists", "trafficMatchingListId"),
    "matchingLists": ("matching-lists", "trafficMatchingListIds"),
}


class Resource:
    """One UniFi resource type.

    identity      Field that names an object stably across consoles. The YAML
                  keys on it and the tool resolves it to the UUID. DNS policies
                  have no `name`, so they key on `domain`.
    detail_get    True when the collection response is a thin projection and
                  each object must be fetched individually. Networks are the
                  case that matters: the list omits ipv4Configuration,
                  isolationEnabled, internetAccessEnabled and the DHCP block
                  entirely, so reconciling from the list alone would diff a
                  subnet against nothing.
    ordered       True when relative order is semantic and the API exposes an
                  ordering endpoint.
    unordered_fields
                  List-valued fields whose order carries no meaning. Compared
                  as sets so the console returning [5, 2.4] against a YAML
                  [2.4, 5] is not reported as drift.
    match_fields  Dotted API paths that identify an object *apart from* its
                  name, used to spot a UI rename: a declared object that is
                  about to be created while an unmanaged user-defined object
                  matches it on these fields is probably the same object under
                  a new name. None means "every declared field but the name".
    membership_field
                  The field that puts a network into a firewall zone. Changing
                  it is the moment zone policy starts applying to that
                  network, so apply refuses to do it while the policy matrix
                  still has unapplied changes.
    create_defaults
                  Fields a create must carry that the YAML may leave
                  undeclared, filled in only when the object is created.
                  Updates never see them, so they claim nothing about the
                  object afterwards.
    """

    def __init__(
        self,
        key,
        path,
        identity="name",
        detail_get=False,
        ordered=False,
        unordered_fields=(),
        patchable=False,
        has_metadata=True,
        yaml_file=None,
        label=None,
        match_fields=None,
        membership_field=None,
        create_defaults=None,
    ):
        self.key = key
        self.path = path
        self.identity = identity
        self.detail_get = detail_get
        self.ordered = ordered
        self.unordered_fields = tuple(unordered_fields)
        self.patchable = patchable
        self.has_metadata = has_metadata
        self.yaml_file = yaml_file or f"{key}.yaml"
        self.label = label or key
        self.match_fields = tuple(match_fields) if match_fields else None
        self.membership_field = membership_field
        self.create_defaults = dict(create_defaults or {})

    def collection_path(self, site_id):
        return f"/v1/sites/{site_id}/{self.path}"

    def item_path(self, site_id, object_id):
        return f"/v1/sites/{site_id}/{self.path}/{object_id}"

    def ordering_path(self, site_id):
        if not self.ordered:
            raise ValueError(f"{self.key} has no ordering endpoint")
        return f"/v1/sites/{site_id}/{self.path}/ordering"

    def identify(self, obj):
        return obj.get(self.identity)

    def origin(self, obj):
        return (obj.get("metadata") or {}).get("origin", "UNKNOWN")

    def writability(self, obj):
        """How far this tool may go with an existing object.

        The API reports three origins, and collapsing them to
        "user-defined or not" gets the `Default` network wrong. It is
        SYSTEM_DEFINED but carries `configurable: true`: the built-in VLAN 1
        network, whose subnet and DHCP are the operator's to change. It must be
        updatable. It must also never be created or deleted, because the
        controller owns its existence.

            FULL        USER_DEFINED. Create, update, delete.
            UPDATE_ONLY SYSTEM_DEFINED with configurable true. The object's
                        existence belongs to the controller; its settings do
                        not.
            NONE        SYSTEM_DEFINED with configurable false, or DERIVED.
                        Never touched. DERIVED is the important one: a
                        network's isolation toggle generates its own
                        policies, and deleting those to match a YAML file
                        that does not mention them is the obvious way to
                        wreck a console.
        """
        if not self.has_metadata:
            # The type has no origin concept in the API at all, so every
            # instance is one somebody created. Traffic matching lists are the
            # case: their schema carries no `metadata` property, and reading an
            # absent origin as "not user-defined" would make the DNS/DHCP list
            # -- which an existing policy already references -- permanently
            # unwritable.
            return FULL
        meta = obj.get("metadata") or {}
        origin = meta.get("origin", "UNKNOWN")
        if origin == "USER_DEFINED":
            return FULL
        if origin == "SYSTEM_DEFINED" and meta.get("configurable") is True:
            return UPDATE_ONLY
        return NONE

    def is_system_defined(self, obj):
        """True when the tool may not create or delete this object."""
        return self.writability(obj) != FULL

    def __repr__(self):
        return f"<Resource {self.key}>"


#: Declaration order is read order, and read order is dependency order:
#: zones before networks because networks reference a zone, both before
#: policies because policies reference either.
RESOURCES = OrderedDict()


def _register(resource):
    RESOURCES[resource.key] = resource
    return resource


_register(
    Resource(
        "zones",
        "firewall/zones",
        unordered_fields=["networkIds"],
        membership_field="networkIds",
        # POST rejects a zone without networkIds ("networkIds must not be
        # null", Network 10.6.106, 2026-10-02). Membership is declared on the
        # network side (`zone:`), so a zone's YAML leaves the field out; a
        # declared `networks: []` would later diff against the networks that
        # joined it and try to remove them.
        create_defaults={"networkIds": []},
        label="firewall zone",
    )
)
_register(
    Resource(
        "networks",
        "networks",
        detail_get=True,
        match_fields=["vlanId"],
        membership_field="zoneId",
        label="network",
    )
)
_register(
    Resource(
        "matching-lists",
        "traffic-matching-lists",
        has_metadata=False,
        yaml_file="matching-lists.yaml",
        label="traffic matching list",
    )
)
_register(
    Resource(
        "policies",
        "firewall/policies",
        ordered=True,
        # PATCH exists but its body is {loggingEnabled} and nothing else --
        # sending `name` is a 400. Any real update is a full-replace PUT.
        patchable=False,
        # `items` covers address and port filter lists, which are sets: the
        # controller stores ["224.0.0.251", "ff02::fb"] back IPv6-first.
        unordered_fields=["connectionStateFilter", "items"],
        match_fields=["source.zoneId", "destination.zoneId", "action.type"],
        yaml_file="policies.yaml",
        label="firewall policy",
    )
)
_register(
    Resource(
        "acl-rules",
        "acl-rules",
        ordered=True,
        yaml_file="acl-rules.yaml",
        label="ACL rule",
    )
)
_register(
    Resource(
        "dns-policies",
        "dns/policies",
        identity="domain",
        yaml_file="dns.yaml",
        label="DNS policy",
    )
)
_register(
    Resource(
        "wifi",
        "wifi/broadcasts",
        unordered_fields=["broadcastingFrequenciesGHz"],
        yaml_file="wifi.yaml",
        label="Wi-Fi broadcast",
    )
)


def get(key):
    try:
        return RESOURCES[key]
    except KeyError:
        known = ", ".join(RESOURCES)
        raise KeyError(f"Unknown resource type '{key}'. Known: {known}") from None


def all_keys():
    return list(RESOURCES)
