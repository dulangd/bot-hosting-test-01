"""Bot-Hosting v2 entrypoint.

The known-working ``main.py`` remains the bootstrap baseline. v2 adds:
- three independent Registry endpoint identities;
- the existing endpoint client identities are preserved; the historical default identity is not replaced;
- additional endpoint client identities are stable and persisted once created;
- independent endpoint heartbeat/re-registration;
- one stable individual subscription URL containing the three baseline REALITY endpoints and the optional CF Tunnel endpoint;
- rust-reality owns the one public TCP port directly; subscription/proof HTTP uses its loopback cover fallback;
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
import time
from pathlib import Path

import bot_hosting_core as core
from bot_hosting_cf import CloudflareRuntime, prepare_cf_endpoint, start_cf_runtime
from bot_hosting_agent import (
    SubscriptionMux,
    build_endpoints,
    ensure_endpoint_clients,
    registry_proofs,
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


def pick_dispatcher_port(public_port: int) -> int:
    """Pick an internal loopback port for HTTP subscription + cover relay."""
    start = max(20000, public_port + 1)
    candidates = list(range(start, min(start + 256, 65535)))
    candidates += list(range(45000, min(45256, 65535)))
    for candidate in candidates:
        if candidate == public_port:
            continue
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind(("127.0.0.1", candidate))
            return candidate
        except OSError:
            pass
        finally:
            sock.close()
    raise core.BootstrapError("could not reserve an internal cover dispatcher port")


def prepare_runtime_config(
    config: dict,
    public_port: int,
    dispatcher_port: int,
) -> None:
    runtime = json.loads(json.dumps(config))
    inbound = runtime["inbounds"][0]
    inbound["port"] = public_port
    inbound["listen"] = {"mode": "ipv4Only"}
    reality = inbound["streamSettings"]["realitySettings"]
    reality["target"] = f"127.0.0.1:{dispatcher_port}"
    data = (json.dumps(runtime, ensure_ascii=False, indent=2) + "\n").encode()
    core.atomic_write(RUNTIME_CONFIG, data)
    core.validate_config_file(RUNTIME_CONFIG, self_test=False)


def start_runtime(binary: Path, runtime_config: Path, environment: dict[str, str]) -> subprocess.Popen:
    return subprocess.Popen(
        [str(binary), "serve", "--config", str(runtime_config)],
        stdin=subprocess.DEVNULL,
        stdout=None,
        stderr=None,
        env=environment,
    )


def wait_public_ready(process: subprocess.Popen, public_port: int, timeout: float = 8.0) -> None:
    deadline = time.monotonic() + timeout
    last_error: Exception | None = None
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise core.BootstrapError(
                f"rust-reality exited before public listener became ready rc={process.returncode}"
            )
        try:
            probe = socket.create_connection(("127.0.0.1", public_port), timeout=0.5)
            probe.close()
            return
        except OSError as exc:
            last_error = exc
            time.sleep(0.05)
    raise core.BootstrapError(
        f"rust-reality public listener 127.0.0.1:{public_port} did not become ready: {last_error}"
    )


def supervise_process(
    process: subprocess.Popen,
    mux: SubscriptionMux,
    cf_runtime: CloudflareRuntime | None = None,
) -> int:
    def close_sidecars() -> None:
        mux.close()
        if cf_runtime is not None:
            cf_runtime.close()

    def forward_signal(signum: int, _frame: object) -> None:
        close_sidecars()
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
        close_sidecars()
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
        os.environ["RR_GEO_IP"] = str(geo.get("egress_ip", "")).strip()
        os.environ["RR_GEO_COUNTRY"] = country
        endpoints = build_endpoints(config, meta, host, port, country)
        required_kinds = {"default", "ip", "custom"}
        actual_kinds = {ep["kind"] for ep in endpoints}
        if actual_kinds != required_kinds:
            missing = ",".join(sorted(required_kinds - actual_kinds))
            raise core.BootstrapError(
                "Bot-Hosting v2 requires all 3 endpoints; "
                f"missing={missing or 'unknown'}; refusing to start with a reduced node set"
            )

        cf_runtime: CloudflareRuntime | None = None
        try:
            cf_prepared = prepare_cf_endpoint(core.STATE_DIR, country)
            if cf_prepared is None:
                core.log(
                    "CF endpoint disabled: CF_TUNNEL_TOKEN/CF_TUNNEL_HOSTNAME "
                    "are not both configured"
                )
            else:
                cf_ep, cf_identity = cf_prepared
                cf_proofs = registry_proofs(core.STATE_DIR, endpoints + [cf_ep])
                cf_runtime = start_cf_runtime(
                    core.STATE_DIR,
                    cf_identity,
                    cf_proofs[cf_ep["node_id"]],
                    cf_ep["host"],
                )
                endpoints.append(cf_ep)
                core.log(
                    f"CF endpoint activated: {cf_ep['name']}="
                    f"{cf_ep['host']}:{cf_ep['port']} origin=127.0.0.1:25903"
                )
        except Exception as exc:
            if cf_runtime is not None:
                with contextlib.suppress(Exception):
                    cf_runtime.close()
            cf_runtime = None
            core.log(
                "CF endpoint not activated; existing 3 REALITY endpoints "
                f"preserved: {type(exc).__name__}: {exc}"
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
            key=lambda ep: {"ip": 0, "default": 1, "custom": 2, "cf": 3}.get(ep["kind"], 9),
        )
        sub_token = subscription_token(core.STATE_DIR, str(meta["uuid"]))
        proofs = registry_proofs(core.STATE_DIR, endpoints)
        dispatcher_port = pick_dispatcher_port(port)
        prepare_runtime_config(config, port, dispatcher_port)
        mux = SubscriptionMux(
            public_port=port,
            backend_port=dispatcher_port,
            endpoints=endpoints,
            token=sub_token,
            proofs=proofs,
            geo=geo,
            cover_host=str(meta["sni"]),
            cover_port=443,
        )

        environment = os.environ.copy()
        environment.setdefault("RUST_BACKTRACE", "0")
        try:
            # Start the loopback cover/subscription dispatcher first. rust-reality
            # then owns SERVER_PORT directly and uses this dispatcher only as its
            # cover target for HTTP fallbacks and real TLS cover handshakes.
            mux.start()
            process = start_runtime(core.BINARY, RUNTIME_CONFIG, environment)
            wait_public_ready(process, port)
        except Exception:
            mux.close()
            if cf_runtime is not None:
                with contextlib.suppress(Exception):
                    cf_runtime.close()
            with contextlib.suppress(Exception):
                if "process" in locals() and process.poll() is None:
                    process.terminate()
                    process.wait(timeout=3)
            raise

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
        print(f"BOT-HOSTING INDIVIDUAL SUBSCRIPTION ({len(endpoints)} ENDPOINTS)")
        print("Same public port as the existing REALITY endpoint; independent of Railway Registry")
        print()
        print("COPY THIS SINGLE SUBSCRIPTION URL INTO v2rayN / Shadowrocket:")
        print()
        print(mux.url)
        print()
        contains = "default + direct-IP + custom-domain"
        if any(ep["kind"] == "cf" for ep in endpoints):
            contains += " + CF-Tunnel"
        print(f"Contains: {contains}")
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

        core.log(
            f"rust-reality public listener ready=0.0.0.0:{port}; "
            f"cover/subscription dispatcher=127.0.0.1:{dispatcher_port}"
        )
        sys.stdout.flush()
        sys.stderr.flush()

        return_code = supervise_process(process, mux, cf_runtime)
        raise SystemExit(return_code if return_code >= 0 else 1)


if __name__ == "__main__":
    try:
        run()
    except KeyboardInterrupt:
        raise SystemExit(130)
    except Exception as exc:
        print(f"[FATAL] {exc}", file=sys.stderr, flush=True)
        raise SystemExit(1)