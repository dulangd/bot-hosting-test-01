def _short_id(used: set[str]) -> str:
    while True:
        value = secrets.token_hex(8)
        if value.lower() not in used:
            used.add(value.lower())
            return value


def _sync_routing_users(config: dict, clients: list[dict]) -> None:
    """Assign every inbound UUID exactly once in rust-reality routing policy.

    ``routing.users`` is a list of policy-group objects, not a flat UUID list.
    Each group has a ``userIds`` array. Endpoint expansion adds two clients to
    the existing inbound, so the UUIDs must be synchronized into the existing
    policy group without changing the established/default client identity or
    its routing policy.
    """
    inbound_ids: list[str] = []
    seen: set[str] = set()
    for client in clients:
        if not isinstance(client, dict):
            raise ValueError("rust-reality inbound contains a non-object client")
        client_id = str(client.get("id", "")).strip()
        if not client_id:
            raise ValueError("rust-reality inbound contains a client without id")
        if client_id in seen:
            raise ValueError(
                f"duplicate inbound client UUID cannot be routed exactly once: {client_id}"
            )
        seen.add(client_id)
        inbound_ids.append(client_id)

    routing = config.setdefault("routing", {})
    if not isinstance(routing, dict):
        raise ValueError("rust-reality routing must be an object")

    groups = routing.get("users")
    if groups is None:
        groups = []
    if not isinstance(groups, list):
        raise ValueError("rust-reality routing.users must be a list of policy groups")

    # The generated standalone config normally has one default policy group.
    # Preserve its name/outbound/rules. If an existing group contains the
    # established/default UUID, keep that group as the owner of all three
    # endpoint identities.
    owner = None
    for group in groups:
        if not isinstance(group, dict):
            raise ValueError("rust-reality routing.users contains a non-object group")
        user_ids = group.get("userIds", [])
        if not isinstance(user_ids, list):
            raise ValueError("rust-reality routing.users[].userIds must be a list")
        if NODE_IDS["default"] in {str(value).strip() for value in user_ids}:
            owner = group
            break

    if owner is None and groups:
        owner = groups[0]

    if owner is None:
        owner = {
            "name": "default-users",
            "userIds": [],
            "defaultOutbound": "direct",
            "rules": [],
        }
        groups.append(owner)

    inbound_set = set(inbound_ids)

    # Remove current inbound UUIDs from every group first, then assign all
    # three to the owner. Unknown/stale UUIDs are also removed because the
    # current public inbound has exactly the endpoint clients in ``clients``.
    for group in groups:
        current = group.get("userIds", [])
        group["userIds"] = [
            str(value).strip()
            for value in current
            if str(value).strip() in inbound_set
        ]

    owner["userIds"] = list(inbound_ids)

    # rust-reality requires every policy group to have at least one UUID.
    routing["users"] = [group for group in groups if group.get("userIds")]


def ensure_endpoint_clients(config: dict) -> dict[str, dict]:
    clients = config["inbounds"][0]["settings"]["clients"]
    if not clients:
        raise ValueError("rust-reality config contains no clients")
    by_email = {str(c.get("email", "")): c for c in clients if isinstance(c, dict)}
    used = {str(s).lower() for c in clients for s in c.get("shortIds", [])}
    default_id = NODE_IDS["default"]
    if default_id not in by_email:
        first = clients[0]
        old_email = str(first.get("email", "")).strip()
        if not old_email or old_email.startswith("bot-hosting-"):
            first["email"] = default_id
        by_email[default_id] = first
    flow = str(clients[0].get("flow", "xtls-rprx-vision"))
    for kind in ("ip", "custom"):
        label = NODE_IDS[kind]
        if label not in by_email:
            client = {
                "id": str(uuid.uuid4()), "shortIds": [_short_id(used)],
                "email": label, "flow": flow,
            }
            clients.append(client)
            by_email[label] = client

    _sync_routing_users(config, clients)
    return {kind: by_email[NODE_IDS[kind]] for kind in ("default", "ip", "custom")}


def _authority(host: str) -> str:
    try:
        ip = ipaddress.ip_address(host)
        return f"[{host}]" if ip.version == 6 else host
    except ValueError:
        return host


def _uri(client: dict, meta: dict, host: str, port: int, name: str) -> str:
    query = urllib.parse.urlencode({
        "encryption": "none", "flow": "xtls-rprx-vision", "security": "reality",