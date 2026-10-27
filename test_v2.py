from __future__ import annotations

import json
import os
import socket
import urllib.parse
import threading
import tempfile
import time
from pathlib import Path

import bot_hosting_agent as agent
import bot_hosting_cf as cf
import bot_hosting_core as core
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


def test_sni_candidate_probe_order() -> None:
    expected = (
        "www.microsoft.com",
        "www.apple.com",
        "www.cloudflare.com",
        "www.amazon.com",
        "www.ibm.com",
        "www.nvidia.com",
    )
    assert core.DEFAULT_SNI_CANDIDATES == expected
    calls = []
    latency = {host: (index + 1) * 10 for index, host in enumerate(expected)}
    original_probe = core.probe_sni_once
    try:
        core.probe_sni_once = lambda host: calls.append(host) or latency[host]
        results = core.probe_sni_candidates()
    finally:
        core.probe_sni_once = original_probe
    assert tuple(results) == expected
    assert calls == [host for host in expected for _ in range(2)]
    assert results["www.microsoft.com"] == 10



def test_existing_node_keeps_sni_when_microsoft_probe_fails() -> None:
    cfg = fake_config()
    reality = cfg["inbounds"][0]["streamSettings"]["realitySettings"]
    reality["target"] = "www.amazon.com:443"
    reality["serverNames"] = ["www.amazon.com"]
    meta = {
        "version": "1.6.1",
        "uuid": "11111111-1111-4111-8111-111111111111",
        "shortId": "0123456789abcdef",
        "publicKey": "PUBLIC_KEY_PLACEHOLDER",
        "sni": "www.amazon.com",
    }
    original_env = {
        name: os.environ.get(name)
        for name in ("RR_SNI", "RR_SNI_ROLLBACK")
    }
    original_values = {
        name: getattr(core, name)
        for name in ("SNI_MIGRATION_FILE", "SNI_ROLLBACK_FILE", "probe_sni_once")
    }
    for name in original_env:
        os.environ.pop(name, None)
    try:
        with tempfile.TemporaryDirectory() as td:
            core.SNI_MIGRATION_FILE = Path(td) / "sni-migration-v1.json"
            core.SNI_ROLLBACK_FILE = Path(td) / "sni-rollback.json"
            calls = []

            def fake_probe(host: str):
                calls.append(host)
                return None if host == "www.microsoft.com" else 20

            core.probe_sni_once = fake_probe
            returned_config, returned_meta = core.maybe_migrate_existing_sni(cfg, meta)
            assert returned_meta["sni"] == "www.amazon.com"
            returned_reality = returned_config["inbounds"][0]["streamSettings"]["realitySettings"]
            assert returned_reality["target"] == "www.amazon.com:443"
            assert returned_reality["serverNames"] == ["www.amazon.com"]
            assert calls == [host for host in core.DEFAULT_SNI_CANDIDATES for _ in range(2)]
            report = json.loads(core.SNI_MIGRATION_FILE.read_text("utf-8"))
            assert report["outcome"] == "candidate-probe-failed-current-retained"
            assert not core.SNI_ROLLBACK_FILE.exists()
    finally:
        for name, value in original_values.items():
            setattr(core, name, value)
        for name, value in original_env.items():
            if value is None:
                os.environ.pop(name, None)
            else:
                os.environ[name] = value


def test_existing_node_sni_migration_is_one_shot_and_identity_safe() -> None:
    cfg = fake_config()
    reality = cfg["inbounds"][0]["streamSettings"]["realitySettings"]
    reality["target"] = "www.amazon.com:443"
    reality["serverNames"] = ["www.amazon.com"]
    meta = {
        "version": "1.6.1",
        "uuid": "11111111-1111-4111-8111-111111111111",
        "shortId": "0123456789abcdef",
        "publicKey": "PUBLIC_KEY_PLACEHOLDER",
        "sni": "www.amazon.com",
    }
    expected_candidates = core.DEFAULT_SNI_CANDIDATES
    original_env = {
        name: os.environ.get(name)
        for name in ("RR_SNI", "RR_SNI_ROLLBACK")
    }
    for name in original_env:
        os.environ.pop(name, None)
    # Exercise the legacy case where RR_SNI still pins the persisted Amazon value.
    os.environ["RR_SNI"] = "www.amazon.com"

    original_values = {
        name: getattr(core, name)
        for name in (
            "STATE_DIR", "CONFIG", "CLIENT_META",
            "SNI_MIGRATION_FILE", "SNI_ROLLBACK_FILE",
            "validate_config_file", "probe_sni_once",
        )
    }
    try:
        with tempfile.TemporaryDirectory() as td:
            state = Path(td)
            config_path = state / "config.json"
            meta_path = state / "client.json"
            migration_path = state / "sni-migration-v1.json"
            rollback_path = state / "sni-rollback.json"
            config_path.write_text(json.dumps(cfg), "utf-8")
            meta_path.write_text(json.dumps(meta), "utf-8")
            calls = []
            latency = {
                host: (index + 1) * 10
                for index, host in enumerate(expected_candidates)
            }
            try:
                core.STATE_DIR = state
                core.CONFIG = config_path
                core.CLIENT_META = meta_path
                core.SNI_MIGRATION_FILE = migration_path
                core.SNI_ROLLBACK_FILE = rollback_path
                core.validate_config_file = lambda *_args, **_kwargs: None
                core.probe_sni_once = lambda host: calls.append(host) or latency[host]

                migrated_meta = core.load_existing_node(25901)
                migrated_config = json.loads(config_path.read_text("utf-8"))
                assert migrated_meta["sni"] == "www.microsoft.com"
                migrated_reality = migrated_config["inbounds"][0]["streamSettings"]["realitySettings"]
                assert migrated_reality["target"] == "www.microsoft.com:443"
                assert migrated_reality["serverNames"] == ["www.microsoft.com"]
                assert migrated_meta["uuid"] == meta["uuid"]
                assert migrated_meta["shortId"] == meta["shortId"]
                assert migrated_meta["publicKey"] == meta["publicKey"]
                assert migrated_config["inbounds"][0]["settings"]["clients"] == cfg["inbounds"][0]["settings"]["clients"]
                assert calls[:12] == [host for host in expected_candidates for _ in range(2)]
                assert calls[12] == "www.microsoft.com"
                assert migration_path.exists() and rollback_path.exists()

                calls.clear()
                migrated_meta_again = core.load_existing_node(25901)
                assert migrated_meta_again["sni"] == "www.microsoft.com"
                assert calls == ["www.microsoft.com"]

                restored_config, restored_meta = core._rollback_persisted_sni(
                    json.loads(config_path.read_text("utf-8")),
                    migrated_meta_again,
                )
                assert restored_meta["sni"] == "www.amazon.com"
                restored_reality = restored_config["inbounds"][0]["streamSettings"]["realitySettings"]
                assert restored_reality["target"] == "www.amazon.com:443"
                assert restored_reality["serverNames"] == ["www.amazon.com"]
                assert restored_meta["uuid"] == meta["uuid"]
                assert restored_meta["shortId"] == meta["shortId"]
                assert restored_meta["publicKey"] == meta["publicKey"]
            finally:
                for name, value in original_values.items():
                    setattr(core, name, value)
    finally:
        for name, value in original_env.items():
            if value is None:
                os.environ.pop(name, None)
            else:
                os.environ[name] = value


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
    assert all("sni=www.microsoft.com" in x["uri"] for x in eps)
    assert len({x["uri"].split("@", 1)[0] for x in eps}) == 3
    assert sum(1 for x in eps if x["traffic_owner"]) == 1
    assert next(x for x in eps if x["traffic_owner"])["kind"] == "default"



def test_local_subscription_contains_all_three_endpoints() -> None:
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

    raw, encoded = agent.subscription_content(eps)
    decoded = __import__("base64").b64decode(encoded).decode("utf-8")
    assert decoded == raw
    lines = [line for line in decoded.splitlines() if line]
    assert len(lines) == 3
    assert all(line.startswith("vless://") for line in lines)
    assert "fi3.bot-hosting.net:25901" in lines[0]
    assert "65.108.103.151:25901" in lines[1]
    assert "bth.richd.cc.cd:25901" in lines[2]

    url = agent.subscription_url("fi3.bot-hosting.net", 25901, "stable-token")
    assert url == "http://fi3.bot-hosting.net:25901/sub64/stable-token"

    with tempfile.TemporaryDirectory() as td1, tempfile.TemporaryDirectory() as td2:
        assert agent.subscription_token(Path(td1), "stable-client-uuid") == agent.subscription_token(Path(td2), "stable-client-uuid")



def test_ws_endpoint_is_fourth_and_persistent() -> None:
    saved = {
        key: os.environ.get(key)
        for key in ("BOT_HOSTING_WS_UUID", "BOT_HOSTING_WS_PATH")
    }
    try:
        os.environ.pop("BOT_HOSTING_WS_UUID", None)
        os.environ.pop("BOT_HOSTING_WS_PATH", None)
        with tempfile.TemporaryDirectory() as td:
            endpoint, identity = agent.build_ws_endpoint(
                Path(td), "fi3.bot-hosting.net", 25901, "FI"
            )
            endpoint2, identity2 = agent.build_ws_endpoint(
                Path(td), "fi3.bot-hosting.net", 25901, "FI"
            )
            assert identity2 == identity
            assert endpoint2["uri"] == endpoint["uri"]
            assert endpoint["kind"] == "ws"
            assert endpoint["node_id"] == "bot-hosting-ws-01"
            assert endpoint["name"] == "FI-BotHosting-WS-01"
            assert endpoint["host"] == "fi3.bot-hosting.net"
            assert endpoint["port"] == 25901
            assert "security=none" in endpoint["uri"]
            assert "type=ws" in endpoint["uri"]
            assert endpoint["force_public_proof"] is True
            assert endpoint["proof_endpoint"] == "http://fi3.bot-hosting.net:25901"

            baseline = [
                {"kind": "default", "uri": "vless://default"},
                {"kind": "ip", "uri": "vless://ip"},
                {"kind": "custom", "uri": "vless://custom"},
            ]
            raw, encoded = agent.subscription_content(baseline + [endpoint])
            decoded = __import__("base64").b64decode(encoded).decode("utf-8")
            assert decoded == raw
            lines = decoded.splitlines()
            assert lines[:3] == ["vless://default", "vless://ip", "vless://custom"]
            assert lines[3] == endpoint["uri"]
    finally:
        for key, value in saved.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value




def test_cloudflare_ws_endpoint_is_fifth_and_uses_tls() -> None:
    saved = {
        key: os.environ.get(key)
        for key in ("BOT_HOSTING_WS_UUID", "BOT_HOSTING_WS_PATH")
    }
    try:
        os.environ.pop("BOT_HOSTING_WS_UUID", None)
        os.environ.pop("BOT_HOSTING_WS_PATH", None)
        with tempfile.TemporaryDirectory() as td:
            direct, identity = agent.build_ws_endpoint(
                Path(td), "fi3.bot-hosting.net", 25901, "FI"
            )
            cf = agent.build_cf_ws_endpoint(
                identity, "FI", "fi3.bot-hosting.net", 25901
            )
            assert cf["kind"] == "cfws"
            assert cf["node_id"] == "bot-hosting-cf-ws-01"
            assert cf["name"] == "FI-BotHosting-CF-WS-01"
            assert cf["host"] == "bth-ws-cf.k1.us.ci"
            assert cf["port"] == 443
            assert cf["force_public_proof"] is True
            assert cf["proof_endpoint"] == "http://fi3.bot-hosting.net:25901"
            assert direct["uri"].split("@", 1)[0] == cf["uri"].split("@", 1)[0]
            assert "security=tls" in cf["uri"]
            assert "type=ws" in cf["uri"]
            assert "sni=bth-ws-cf.k1.us.ci" in cf["uri"]
            assert "host=bth-ws-cf.k1.us.ci" in cf["uri"]
            assert urllib.parse.urlsplit(cf["uri"]).port == 443

            baseline = [
                {"kind": "default", "uri": "vless://default"},
                {"kind": "ip", "uri": "vless://ip"},
                {"kind": "custom", "uri": "vless://custom"},
                direct,
                cf,
            ]
            raw, encoded = agent.subscription_content(baseline)
            decoded = __import__("base64").b64decode(encoded).decode("utf-8")
            assert decoded.splitlines() == [
                "vless://default",
                "vless://ip",
                "vless://custom",
                direct["uri"],
                cf["uri"],
            ]
    finally:
        for key, value in saved.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value



def test_named_cloudflare_tunnel_endpoint_and_subscription() -> None:
    keys = ("CF_TUNNEL_TOKEN", "CF_TUNNEL_HOSTNAME", "CF_ORIGIN_PORT")
    saved = {key: os.environ.get(key) for key in keys}
    try:
        os.environ["CF_TUNNEL_TOKEN"] = "test-token-must-not-appear-in-links"
        os.environ["CF_TUNNEL_HOSTNAME"] = "bth-cf.k1.us.ci"
        os.environ["CF_ORIGIN_PORT"] = "25903"
        with tempfile.TemporaryDirectory() as td:
            endpoint, identity = cf.prepare_cf_endpoint(Path(td), "FI")
            assert endpoint["kind"] == "cf"
            assert endpoint["node_id"] == "bot-hosting-cf-01"
            assert endpoint["host"] == "bth-cf.k1.us.ci"
            assert endpoint["port"] == 443
            assert endpoint["proof_endpoint"] == "https://bth-cf.k1.us.ci"
            assert identity["uuid"]
            assert identity["ws_path"].startswith("/")
            query = urllib.parse.parse_qs(urllib.parse.urlsplit(endpoint["uri"]).query)
            assert query["security"] == ["tls"]
            assert query["type"] == ["ws"]
            assert query["sni"] == ["bth-cf.k1.us.ci"]
            assert query["host"] == ["bth-cf.k1.us.ci"]
            assert "test-token-must-not-appear-in-links" not in endpoint["uri"]
            assert cf.cf_origin_port() == 25903

            baseline = [
                {"kind": "default", "uri": "vless://default"},
                {"kind": "ip", "uri": "vless://ip"},
                {"kind": "custom", "uri": "vless://custom"},
                {"kind": "ws", "uri": "vless://ws"},
                {"kind": "cfws", "uri": "vless://cfws"},
                endpoint,
            ]
            raw, encoded = agent.subscription_content(baseline)
            decoded = __import__("base64").b64decode(encoded).decode("utf-8")
            assert raw.splitlines() == decoded.splitlines()
            assert decoded.splitlines() == [
                "vless://default",
                "vless://ip",
                "vless://custom",
                "vless://ws",
                "vless://cfws",
                endpoint["uri"],
            ]
    finally:
        for key, value in saved.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value


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

    ws_identity = {
        "uuid": "22222222-2222-4222-8222-222222222222",
        "ws_path": "/ws-test",
    }
    mux = agent.SubscriptionMux(
        25901,
        dispatcher_port,
        endpoints,
        "stable-token",
        cover_host="127.0.0.1",
        cover_port=cover_port,
        ws_identity=ws_identity,
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

        ws = socket.create_connection(("127.0.0.1", dispatcher_port), timeout=3)
        with ws:
            ws.sendall(
                b"GET /ws-test HTTP/1.1\r\n"
                b"Host: fi3.bot-hosting.net\r\n"
                b"Upgrade: websocket\r\n"
                b"Connection: Upgrade\r\n"
                b"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
                b"Sec-WebSocket-Version: 13\r\n\r\n"
            )
            response = ws.recv(4096)
            assert response.startswith(b"HTTP/1.1 101 Switching Protocols")

        tls = socket.create_connection(("127.0.0.1", dispatcher_port), timeout=3)
        with tls:
            marker = b"\x16\x03\x01\x00\x10"
            tls.sendall(marker)
            assert tls.recv(len(marker)) == marker
    finally:
        mux.close()
        worker.join(timeout=2)

    assert agent.HEARTBEAT_DEFAULT >= 60
    assert len({agent.NODE_IDS["default"], agent.NODE_IDS["ip"], agent.NODE_IDS["custom"]}) == 3


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
    assert inbound["streamSettings"]["realitySettings"]["serverNames"] == ["www.microsoft.com"]


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
    test_sni_candidate_probe_order()
    test_existing_node_keeps_sni_when_microsoft_probe_fails()
    test_existing_node_sni_migration_is_one_shot_and_identity_safe()
    test_client_migration()
    test_three_endpoint_links_and_names()
    test_local_subscription_contains_all_three_endpoints()
    test_ws_endpoint_is_fourth_and_persistent()
    test_cloudflare_ws_endpoint_is_fifth_and_uses_tls()
    test_named_cloudflare_tunnel_endpoint_and_subscription()
    test_completion_traffic_parser()
    test_internal_dispatcher_serves_subscription_and_relays_cover()
    test_runtime_config_keeps_reality_on_public_port()
    test_private_bounded_log_shape()
    print("PASS Bot-Hosting v2 isolated tests")