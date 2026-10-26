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


def test_runtime_config_keeps_reality_on_public_port() -> None:
    cfg = fake_config()
    with tempfile.TemporaryDirectory() as td:
        original_state = main_v2.RUNTIME_CONFIG
        try:
            main_v2.RUNTIME_CONFIG = Path(td) / "runtime-config.json"
            original_validate = main_v2.core.validate_config_file
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


if __name__ == "__main__":
    test_client_migration()
    test_three_endpoint_links_and_names()
    test_local_subscription_contains_all_three_endpoints()
    test_completion_traffic_parser()
    test_internal_dispatcher_serves_subscription_and_relays_cover()
    test_runtime_config_keeps_reality_on_public_port()
    test_private_bounded_log_shape()
    print("PASS Bot-Hosting v2 isolated tests")