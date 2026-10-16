"""Bot-Hosting v2 entrypoint.

The known-working ``main.py`` remains the bootstrap baseline. v2 adds:
- three independent Registry endpoint identities;
- the persisted working VLESS/REALITY credential reused for all three endpoints;
- independent endpoint heartbeat/re-registration;
- one stable individual subscription URL containing all three endpoints;
- one public TCP port shared by the subscription HTTP path and REALITY traffic;
- shared physical-instance traffic ownership with no triple counting.
"""

from __future__ import annotations

import contextlib
import fcntl
import json
import os
import signal
import socket
import subprocess
import sys
from pathlib import Path

import main as core
from bot_hosting_agent import (
    SubscriptionMux,
    build_endpoints,
    ensure_endpoint_clients,
    start_agent,
    subscription_token,
    verified_country,
)

CLIENT_LINKS = core.STATE_DIR / "client-links.txt"
TRAFFIC_LOG = core.STATE_DIR / "traffic-events.log"


def configure_private_traffic_log(config: dict) -> None:
    if os.environ.get("RR_TRAFFIC_TRACKING", "1") == "0":
        config["log"] = {"level": "error", "output": "none"}
        return

    config["log"] = {
        "level": "debug",
        "output": "file",
        "file": {
            "path": str(TRAFFIC_LOG),
            "maxBytes": 8 * 1024 * 1024,
            "maxFiles": 2,
            "maxTotalBytes": 16 * 1024 * 1024,
        },
    }


def save_config(config: dict) -> None:
    data = (json.dumps(config, ensure_ascii=False, indent=2) + "\n").encode()
    fd, tmp_name = core.tempfile.mkstemp(
        prefix=".config.v2.", suffix=".json", dir=core.STATE_DIR
    )
    tmp = core.Path(tmp_name)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        core.validate_config_file(tmp, self_test=False)
    finally:
        with contextlib.suppress(FileNotFoundError):
            tmp.unlink()
    core.atomic_write(core.CONFIG, data)


RUNTIME_CONFIG = core.STATE_DIR / "runtime-config.json"


def pick_backend_port(public_port: int) -> int:
    """Pick a loopback-only backend port not equal to the one Bot-Hosting publishes."""
    start = max(20000, public_port + 1)
    candidates = list(range(start, min(start + 256, 65535)))
    # Also try a deterministic high range if SERVER_PORT is already high.
    candidates += list(range(45000, min(45256, 65535)))
    for candidate in candidates:
        if candidate == public_port:
            continue
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind(("0.0.0.0", candidate))
            return candidate
        except OSError:
            pass
        finally:
            sock.close()
    raise core.BootstrapError("could not reserve an internal rust-reality backend port")


def prepare_runtime_config(config: dict, public_port: int) -> int:
    runtime_port = pick_backend_port(public_port)
    runtime = json.loads(json.dumps(config))
    runtime["inbounds"][0]["port"] = runtime_port
    data = (json.dumps(runtime, ensure_ascii=False, indent=2) + "\n").encode()
    core.atomic_write(RUNTIME_CONFIG, data)
    core.validate_config_file(RUNTIME_CONFIG, self_test=False)
    return runtime_port


def supervise_runtime(binary: Path, runtime_config: Path, environment: dict[str, str], mux: SubscriptionMux) -> int:
    process = subprocess.Popen(
        [str(binary), "serve", "--config", str(runtime_config)],
        stdin=subprocess.DEVNULL,
        stdout=None,
        stderr=None,
        env=environment,
    )
    def forward_signal(signum: int, _frame: object) -> None:
        mux.close()
        if process.poll() is None:
            with contextlib.suppress(ProcessLookupError):
                process.send_signal(signum)

    previous_term = signal.signal(signal.SIGTERM, forward_signal)
    previous_int = signal.signal(signal.SIGINT, forward_signal)
    try:
        return process.wait()
    finally:
        signal.signal(signal.SIGTERM, previous_term)
        signal.signal(signal.SIGINT, previous_int)
        mux.close()
        if process.poll() is None:
            with contextlib.suppress(Exception):
                process.terminate()
                process.wait(timeout=3)


def run() -> None:
    if sys.platform != "linux":
        raise core.BootstrapError("Linux is required")
    if os.uname().machine != "x86_64":
        raise core.BootstrapError("this bootstrap requires x86_64")

    core.STATE_DIR.mkdir(parents=True, exist_ok=True)
    os.chmod(core.STATE_DIR, 0o700)

    with open(core.LOCK_FILE, "a+b") as lock:
        fcntl.flock(lock.fileno(), fcntl.LOCK_EX)

        port = core.public_port()
        host = core.public_host()
        core.log(f"Bot-Hosting SERVER_PORT={port}")
        resolved = core.resolve_ipv4(host)
        if resolved:
            core.log(f"{host} resolves to: {', '.join(resolved)}")

        core.install_binary()
        meta = core.load_or_create_node(port)

        # Preserve the persisted working client identity; Registry endpoint IDs remain independent.
        config = json.loads(core.CONFIG.read_text("utf-8"))
        ensure_endpoint_clients(config)
        configure_private_traffic_log(config)
        save_config(config)

        geo = verified_country(core.STATE_DIR)
        country = str(geo.get("country", "XX")).upper()
        endpoints = build_endpoints(config, meta, host, port, country)
        required_kinds = {"default", "ip", "custom"}
        actual_kinds = {ep["kind"] for ep in endpoints}
        if actual_kinds != required_kinds:
            missing = ",".join(sorted(required_kinds - actual_kinds))
            raise core.BootstrapError(
                "Bot-Hosting v2 requires all 3 endpoints; "
                f"missing={missing or 'unknown'}; refusing to start with a reduced node set"
            )

        default_ep = next(
            ep for ep in endpoints if ep["kind"] == "default"
        )
        core.atomic_write(core.CLIENT_LINK, (default_ep["uri"] + "\n").encode())
        core.atomic_write(
            CLIENT_LINKS,
            ("\n".join(ep["uri"] for ep in endpoints) + "\n").encode(),
        )

        # Totals are persisted in traffic.json; do not replay old completion events.
        for old_log in core.STATE_DIR.glob("traffic-events.log*"):
            with contextlib.suppress(FileNotFoundError):
                old_log.unlink()

        # A provider-scoped token is preferred over any generic registry token.
        # Railway already accepts BOT_HOSTING_REGISTER_TOKEN as a registration token;
        # the Bot-Hosting-specific Railway patch restricts that token to these 3 IDs.
        provider_token = os.environ.get("BOT_HOSTING_REGISTER_TOKEN", "").strip()
        if provider_token:
            os.environ["REGISTRY_TOKEN"] = provider_token

        # Railway verifies Bot-Hosting country from the direct-IP record. Register
        # that record first so Default and Custom can inherit the same independent
        # Railway-side check during the very first registration pass.
        registry_endpoints = sorted(
            endpoints,
            key=lambda ep: {"ip": 0, "default": 1, "custom": 2}.get(ep["kind"], 9),
        )
        sub_token = subscription_token(core.STATE_DIR)
        backend_port = prepare_runtime_config(config, port)
        mux = SubscriptionMux(
            public_port=port,
            backend_port=backend_port,
            endpoints=endpoints,
            token=sub_token,
        )
        mux.start()

        agent_pid = start_agent(
            core.STATE_DIR,
            TRAFFIC_LOG,
            registry_endpoints,
            close_fds=(lock.fileno(),),
        )

        core.log(
            f"geo country={country} verified={bool(geo.get('verified'))} "
            f"egress_ip={geo.get('egress_ip') or 'unknown'}"
        )
        core.log(
            "endpoints ready: "
            + ", ".join(
                f"{ep['kind']}={ep['host']}:{ep['port']}" for ep in endpoints
            )
        )
        print()
        print("=" * 78)
        print("BOT-HOSTING INDIVIDUAL SUBSCRIPTION (3 ENDPOINTS)")
        print("Same public port as the existing REALITY endpoint; independent of Railway Registry")
        print()
        print("COPY THIS SINGLE SUBSCRIPTION URL INTO v2rayN / Shadowrocket:")
        print()
        print(mux.url)
        print()
        print("Contains exactly: default + direct-IP + custom-domain")
        print("=" * 78)
        print()
        core.log(
            "traffic scope=shared-instance; rust-reality v1.6.1 does not expose "
            "UUID on completion events, so per-endpoint bytes are not fabricated"
        )
        core.log(
            f"manager agent={'pid=' + str(agent_pid) if agent_pid else 'disabled'}; "
            "local_subscription=ready; "
            "sensitive links saved in private state files"
        )

        if os.environ.get("RR_SHOW_LINKS") == "1":
            for ep in endpoints:
                print(ep["uri"], flush=True)

        environment = os.environ.copy()
        environment.setdefault("RUST_BACKTRACE", "0")
        core.log(
            f"start rust-reality backend=127.0.0.1:{backend_port}; "
            "public port is owned by the single-port subscription/REALITY mux"
        )
        sys.stdout.flush()
        sys.stderr.flush()

        return_code = supervise_runtime(
            core.BINARY,
            RUNTIME_CONFIG,
            environment,
            mux,
        )
        raise SystemExit(return_code if return_code >= 0 else 1
        )


if __name__ == "__main__":
    try:
        run()
    except KeyboardInterrupt:
        raise SystemExit(130)
    except Exception as exc:
        print(f"[FATAL] {exc}", file=sys.stderr, flush=True)
        raise SystemExit(1)