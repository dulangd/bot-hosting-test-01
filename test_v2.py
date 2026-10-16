from __future__ import annotations

import json
import os
import socket
import threading
import tempfile
import time
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
    assert len(all_clients) == 1
    assert {clients[k]["id"] for k in ("default", "ip", "custom")} == {old["id"]}
    assert {clients[k]["shortIds"][0] for k in ("default", "ip", "custom")} == {old["shortIds"][0]}


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
    assert len({x["uri"].split("@", 1)[0] for x in eps}) == 1
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


def test_single_public_port_mux_serves_subscription_and_forwards_reality() -> None:
    cfg = fake_config()
    agent.ensure_endpoint_clients(cfg)
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

    backend = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    backend.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    backend.bind(("127.0.0.1", 0))
    backend.listen(8)
    backend_port = backend.getsockname()[1]

    def backend_loop() -> None:
        try:
            for _ in range(1):
                conn, _ = backend.accept()
                with conn:
                    data = conn.recv(4096)
                    conn.sendall(data)
        finally:
            backend.close()

    worker = threading.Thread(target=backend_loop, daemon=True)
    worker.start()

    mux_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    mux_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    mux_socket.bind(("127.0.0.1", 0))
    mux_port = mux_socket.getsockname()[1]
    mux_socket.close()

    mux = agent.SubscriptionMux(mux_port, backend_port, endpoints, "stable-token")
    try:
        mux.start()

        http = socket.create_connection(("127.0.0.1", mux_port), timeout=3)
        with http:
            http.sendall(b"GET /sub64/stable-token HTTP/1.1\\r\\nHost: fi3.bot-hosting.net\\r\\nConnection: close\\r\\n\\r\\n")
            response = b""
            while True:
                chunk = http.recv(4096)
                if not chunk:
                    break
                response += chunk
        body = response.split(b"\\r\\n\\r\\n", 1)[1].decode("ascii")
        decoded = __import__("base64").b64decode(body).decode("utf-8")
        assert decoded == "\n".join(ep["uri"] for ep in endpoints) + "\n"

        reality = socket.create_connection(("127.0.0.1", mux_port), timeout=3)
        with reality:
            marker = b"\\x16\\x03\\x01\\x00\\x10"
            reality.sendall(marker)
            assert reality.recv(len(marker)) == marker
    finally:
        mux.close()
        worker.join(timeout=2)

    assert agent.HEARTBEAT_DEFAULT >= 60
    assert len({agent.NODE_IDS["default"], agent.NODE_IDS["ip"], agent.NODE_IDS["custom"]}) == 3


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
    test_local_subscription_contains_all_three_endpoints()
    test_completion_traffic_parser()
    test_single_public_port_mux_serves_subscription_and_forwards_reality()
    test_private_bounded_log_shape()
    print("PASS Bot-Hosting v2 isolated tests")