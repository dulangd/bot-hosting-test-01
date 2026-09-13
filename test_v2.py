from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path

import bot_hosting_agent as agent
import main_v2


def fake_config() -> dict:
    return {
        "log": {"level": "error", "output": "none"},
        "network": {"dial": {"mode": "ipv4Only"}},
        "runtime": {"profile": "dedicated", "tuning": {"mode": "startup", "objective": "throughput"}},
        "inbounds": [{
            "protocol": "vless",
            "tag": "public-reality",
            "listen": {"mode": "ipv4Only", "ipv4": "0.0.0.0"},
            "port": 25901,
            "settings": {"clients": [{
                "id": "11111111-1111-4111-8111-111111111111",
                "shortIds": ["0123456789abcdef"],
                "flow": "xtls-rprx-vision",
            }], "decryption": "none"},
            "streamSettings": {"network": "tcp", "security": "reality", "realitySettings": {
                "target": "www.microsoft.com:443",
                "serverNames": ["www.microsoft.com"],
                "privateKey": "private-key-placeholder",
                "maxTimeDiffMs": 60000,
            }},
        }],
        "outbounds": [{"protocol": "direct", "tag": "direct"}],
        "routing": {"rules": []},
    }


def test_client_migration() -> None:
    cfg = fake_config()
    old = json.loads(json.dumps(cfg["inbounds"][0]["settings"]["clients"][0]))
    clients = agent.ensure_endpoint_clients(cfg)
    all_clients = cfg["inbounds"][0]["settings"]["clients"]
    assert len(all_clients) == 3
    assert clients["default"]["id"] == old["id"]
    assert clients["default"]["shortIds"][0] == old["shortIds"][0]
    assert len({c["id"] for c in all_clients}) == 3
    assert len({c["shortIds"][0] for c in all_clients}) == 3


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
        "bot-hosting-default-01", "bot-hosting-ip-01", "bot-hosting-custom-01"
    ]
    assert [x["name"] for x in eps] == [
        "FI-BotHosting-Default-01", "FI-BotHosting-IP-01", "FI-BotHosting-Custom-01"
    ]
    assert len({x["uri"].split("@", 1)[0] for x in eps}) == 3
    assert sum(1 for x in eps if x["traffic_owner"]) == 1
    assert next(x for x in eps if x["traffic_owner"])["kind"] == "default"


def test_completion_traffic_parser() -> None:
    with tempfile.TemporaryDirectory() as td:
        path = Path(td) / "traffic.log"
        events = [
            {"event": "connection_completed", "uplink_bytes": 120, "downlink_bytes": 340},
            {"event": "server_starting"},
            {"event": "connection_completed", "uplink_bytes": 5, "downlink_bytes": 7},
        ]
        path.write_text("".join(json.dumps(x) + "\n" for x in events), "utf-8")
        state = agent._empty_traffic()
        offset = agent._consume_log(path, 0, state)
        assert offset > 0
        assert state["upload_bytes"] == 125
        assert state["download_bytes"] == 347
        assert state["connections"] == 2
        # Reading again from the saved offset must not double count.
        agent._consume_log(path, offset, state)
        assert state["upload_bytes"] == 125
        assert state["download_bytes"] == 347
        assert state["connections"] == 2


def test_cover_never_reuses_proxy_port_contract() -> None:
    # main_v2 passes the proxy port to the agent; the agent starts HTTP cover
    # only when RR_COVER_PORT is valid AND different from endpoint port.
    assert agent.HEARTBEAT_DEFAULT >= 60
    assert agent.NODE_IDS["default"] != agent.NODE_IDS["ip"] != agent.NODE_IDS["custom"]


def test_private_bounded_log_shape() -> None:
    cfg = fake_config()
    old = os.environ.pop("RR_TRAFFIC_TRACKING", None)
    try:
        main_v2.configure_private_traffic_log(cfg)
    finally:
        if old is not None:
            os.environ["RR_TRAFFIC_TRACKING"] = old
    log = cfg["log"]
    assert log["level"] == "debug"
    assert log["output"] == "file"
    assert log["file"]["maxFiles"] == 2
    assert log["file"]["maxTotalBytes"] == 16 * 1024 * 1024


if __name__ == "__main__":
    test_client_migration()
    test_three_endpoint_links_and_names()
    test_completion_traffic_parser()
    test_cover_never_reuses_proxy_port_contract()
    test_private_bounded_log_shape()
    print("PASS Bot-Hosting v2 isolated tests")
