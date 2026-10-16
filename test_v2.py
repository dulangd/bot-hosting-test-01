    clients = agent.ensure_endpoint_clients(cfg)
    all_clients = cfg["inbounds"][0]["settings"]["clients"]
    assert len(all_clients) == 3
    assert clients["default"]["id"] == old["id"]
    assert clients["default"]["shortIds"][0] == old["shortIds"][0]
    assert len({clients[k]["id"] for k in ("default", "ip", "custom")}) == 3
    assert len({clients[k]["shortIds"][0] for k in ("default", "ip", "custom")}) == 3


def test_routing_users_tracks_all_endpoint_clients() -> None:
    cfg = fake_config()
    original_uuid = cfg["inbounds"][0]["settings"]["clients"][0]["id"]
    # Simulate a stale one-client policy group from the original config.
    cfg["routing"]["users"] = [{
        "name": "default-users",
        "userIds": [original_uuid],
        "defaultOutbound": "direct",
        "rules": [],
    }]
    clients = agent.ensure_endpoint_clients(cfg)
    ids = [client["id"] for client in cfg["inbounds"][0]["settings"]["clients"]
    ]
    assert len(ids) == 3
    assert len(set(ids)) == 3
    groups = cfg["routing"]["users"]
    assigned = [uid for group in groups for uid in group["userIds"]]
    assert assigned == ids
    assert assigned.count(original_uuid) == 1
    assert len(groups) == 1
    assert groups[0]["name"] == "default-users"
    assert groups[0]["defaultOutbound"] == "direct"


def test_three_endpoint_links_and_names() -> None:
    cfg = fake_config()
    agent.ensure_endpoint_clients(cfg)
    original = agent.discover_hosts
    try:
        agent.discover_hosts = lambda _host: {
            "default": "fi3.bot-hosting.net",
            "ip": "65.108.103.151",
            "custom": "bth.richd.cc.cd",
        }
        eps = agent.build_endpoints(
            cfg,
            {"sni": "www.microsoft.com", "publicKey": "PUBLIC_KEY", "shortId": "0123456789abcdef"},
            "fi3.bot-hosting.net", 25901, "FI",
        )
    finally:
        agent.discover_hosts = original
    assert [x["kind"] for x in eps] == ["default", "ip", "custom"]
    assert [x["node_id"] for x in eps] == [
        "bot-hosting-01", "bot-hosting-ip-01", "bot-hosting-domain-01"
    ]
    assert [x["name"] for x in eps] == [
        "FI-BotHosting-Default-01", "FI-BotHosting-IP-01", "FI-BotHosting-Custom-01"
    ]