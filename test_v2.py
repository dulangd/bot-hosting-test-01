from __future__ import annotations

import json
import os
import socket
import threading
import tempfile
import time
from pathlib import Path

import bot_hosting_agent as agent
import bot_hosting_cf as cf
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
    agent.ensure_endpoint_clients(cfg)
    ids = [client["id"] for client in cfg["inbounds"][0]["settings"]["clients"]]
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
    assert len({x["uri"].split("@", 1)[0] for x in eps}) == 3
    assert sum(1 for x in eps if x["traffic_owner"]) == 1
    assert next(x for x in eps if x["traffic_owner"])["kind"] == "default"



def test_local_subscription_contains_all_four_endpoints() -> None:
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

    eps.append(cf.build_cf_endpoint(
        {"uuid": "44444444-4444-4444-8444-444444444444", "ws_path": "/ws-test"},
        "unit-test.trycloudflare.com",
        "FI",
    ))
    raw, encoded = agent.subscription_content(eps)
    decoded = __import__("base64").b64decode(encoded).decode("utf-8")
    assert decoded == raw
    lines = [line for line in decoded.splitlines() if line]
    assert len(lines) == 4
    assert all(line.startswith("vless://") for line in lines)
    assert "fi3.bot-hosting.net:25901" in lines[0]
    assert "65.108.103.151:25901" in lines[1]
    assert "bth.richd.cc.cd:25901" in lines[2]
    assert "unit-test.trycloudflare.com:443" in lines[3]
    assert "type=ws" in lines[3]
    assert "security=tls" in lines[3]

    url = agent.subscription_url("fi3.bot-hosting.net", 25901, "stable-token")
    assert url == "http://fi3.bot-hosting.net:25901/sub64/stable-token"

    with tempfile.TemporaryDirectory() as td1, tempfile.TemporaryDirectory() as td2:
        assert agent.subscription_token(Path(td1), "stable-client-uuid") == agent.subscription_token(Path(td2), "stable-client-uuid")

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


def test_internal_dispatcher_serves_subscription_and_relays_cover() -> None:
    endpoints = [
        {"kind": "default", "node_id": "bot-hosting-01", "name": "FI-BotHosting-Default-01",
         "host": "fi3.bot-hosting.net", "port": 25901, "uri": "vless://default@fi3.bot-hosting.net:25901?x=1",
         "traffic_scope": "shared-instance", "traffic_owner": True},
        {"kind": "ip", "node_id": "bot-hosting-ip-01", "name": "FI-BotHosting-IP-01",
         "host": "65.108.103.151", "port": 25901, "uri": "vless://default@65.108.103.151:25901?x=1",
         "traffic_scope": "shared-instance", "traffic_owner": False},
        {"kind": "custom", "node_id": "bot-hosting-domain-01", "name": "FI-BotHosting-Custom-01",
         "host": "bth.richd.cc.cd", "port": 25901, "uri": "vless://default@bth.richd.cc.cd:25901?x=1",
         "traffic_scope": "shared-instance", "traffic_owner": False},
        {"kind": "cf", "node_id": "bot-hosting-cf-01", "name": "FI-BotHosting-CF-01",
         "host": "unit-test.trycloudflare.com", "port": 443,
         "uri": "vless://44444444-4444-4444-8444-444444444444@unit-test.trycloudflare.com:443?encryption=none&security=tls&type=ws&host=unit-test.trycloudflare.com&path=%2Fws-test",
         "proof_endpoint": "https://unit-test.trycloudflare.com",
         "traffic_scope": "shared-instance", "traffic_owner": False},
    ]

    cover = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    cover.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    cover.bind(("127.0.0.1", 0))
    cover.listen(8)
    cover_port = cover.getsockname()[1]

    def cover_loop() -> None:
        try:
            conn, _ = cover.accept()
            with conn:
                data = conn.recv(4096)
                conn.sendall(data)
        finally:
            cover.close()

    worker = threading.Thread(target=cover_loop, daemon=True)
    worker.start()

    reserve = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    reserve.bind(("127.0.0.1", 0))
    dispatcher_port = reserve.getsockname()[1]
    reserve.close()

    mux = agent.SubscriptionMux(
        25901,
        dispatcher_port,
        endpoints,
        "stable-token",
        cover_host="127.0.0.1",
        cover_port=cover_port,
    )
    try:
        mux.start()

        http = socket.create_connection(("127.0.0.1", dispatcher_port), timeout=3)
        with http:
            http.sendall(b"GET /sub64/stable-token HTTP/1.1\r\nHost: fi3.bot-hosting.net\r\nConnection: close\r\n\r\n")
            response = b""
            while True:
                chunk = http.recv(4096)
                if not chunk:
                    break
                response += chunk
        body = response.split(b"\r\n\r\n", 1)[1].decode("ascii")
        decoded = __import__("base64").b64decode(body).decode("utf-8")
        assert decoded == "\n".join(ep["uri"] for ep in endpoints) + "\n"

        tls = socket.create_connection(("127.0.0.1", dispatcher_port), timeout=3)
        with tls:
            marker = b"\x16\x03\x01\x00\x10"
            tls.sendall(marker)
            assert tls.recv(len(marker)) == marker
    finally:
        mux.close()
        worker.join(timeout=2)

    assert agent.HEARTBEAT_DEFAULT >= 60
    assert len({agent.NODE_IDS["default"], agent.NODE_IDS["ip"], agent.NODE_IDS["custom"], agent.NODE_IDS["cf"]}) == 4


def test_runtime_config_keeps_reality_on_public_port() -> None:
    cfg = fake_config()
    with tempfile.TemporaryDirectory() as td:
        original_state = main_v2.RUNTIME_CONFIG
        original_validate = main_v2.core.validate_config_file
        try:
            main_v2.RUNTIME_CONFIG = Path(td) / "runtime-config.json"
            main_v2.core.validate_config_file = lambda *_args, **_kwargs: None
            main_v2.prepare_runtime_config(cfg, 25901, 25902)
            runtime = json.loads(main_v2.RUNTIME_CONFIG.read_text("utf-8"))
        finally:
            main_v2.RUNTIME_CONFIG = original_state
            main_v2.core.validate_config_file = original_validate

    inbound = runtime["inbounds"][0]
    assert inbound["port"] == 25901
    assert inbound["listen"] == {"mode": "ipv4Only"}
    assert inbound["streamSettings"]["realitySettings"]["target"] == "127.0.0.1:25902"



def test_cf_endpoint_identity_and_uri_shape() -> None:
    with tempfile.TemporaryDirectory() as td:
        one = cf.load_identity(Path(td))
        two = cf.load_identity(Path(td))
        assert one == two
        ep = cf.build_cf_endpoint(one, "example.trycloudflare.com", "FI")
        assert ep["kind"] == "cf"
        assert ep["node_id"] == "bot-hosting-cf-01"
        assert ep["name"] == "FI-BotHosting-CF-01"
        assert ep["host"] == "example.trycloudflare.com"
        assert ep["port"] == 443
        assert ep["proof_endpoint"] == "https://example.trycloudflare.com"
        assert f"vless://{one['uuid']}@" in ep["uri"]
        assert "security=tls" in ep["uri"]
        assert "type=ws" in ep["uri"]
        assert "flow=" not in ep["uri"]
        assert "sid=" not in ep["uri"]



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
    test_local_subscription_contains_all_four_endpoints()
    test_completion_traffic_parser()
    test_internal_dispatcher_serves_subscription_and_relays_cover()
    test_runtime_config_keeps_reality_on_public_port()
    test_cf_endpoint_identity_and_uri_shape()
    test_private_bounded_log_shape()
    print("PASS Bot-Hosting v2 isolated tests")