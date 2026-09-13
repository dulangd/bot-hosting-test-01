"""Bot-Hosting v2 entrypoint.

This intentionally imports the known-working ``main.py`` instead of replacing it.
The rust-reality v1.6.1 binary, configuration generator, checksum verification,
performance profile and original client identity remain the baseline.

v2 adds only management-plane features:
- three logical endpoints: default hostname, direct IPv4 and verified custom domain;
- unique VLESS identity per endpoint while preserving the old identity as default;
- FI/XX country-prefixed remarks from two-source egress verification;
- Railway registration/heartbeat in a tiny forked helper;
- shared physical-instance traffic totals from rust-reality completion counters;
- optional cover page only on a second port (never on the REALITY port);
- no sensitive VLESS links in Console unless RR_SHOW_LINKS=1.
"""

from __future__ import annotations

import contextlib
import fcntl
import json
import os
import sys

import main as core
from bot_hosting_agent import (
    build_endpoints,
    ensure_endpoint_clients,
    start_agent,
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

        # Preserve the existing client as Default and append IP/Custom identities.
        config = json.loads(core.CONFIG.read_text("utf-8"))
        ensure_endpoint_clients(config)
        configure_private_traffic_log(config)
        save_config(config)

        geo = verified_country(core.STATE_DIR)
        country = str(geo.get("country", "XX")).upper()
        endpoints = build_endpoints(config, meta, host, port, country)
        if not endpoints:
            raise core.BootstrapError("no publishable Bot-Hosting endpoints discovered")

        default_ep = next(
            (ep for ep in endpoints if ep["kind"] == "default"), endpoints[0]
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

        agent_pid = start_agent(
            core.STATE_DIR,
            TRAFFIC_LOG,
            endpoints,
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
        if len(endpoints) < 3:
            core.log(
                "custom endpoint skipped: DNS did not verify against the "
                "Bot-Hosting node; RR_CUSTOM_DOMAIN can override the candidate"
            )
        core.log(
            "traffic scope=shared-instance; rust-reality v1.6.1 does not expose "
            "UUID on completion events, so per-endpoint bytes are not fabricated"
        )
        core.log(
            f"manager agent={'pid=' + str(agent_pid) if agent_pid else 'disabled'}; "
            "sensitive links saved in private state files"
        )

        if os.environ.get("RR_SHOW_LINKS") == "1":
            for ep in endpoints:
                print(ep["uri"], flush=True)

        environment = os.environ.copy()
        environment.setdefault("RUST_BACKTRACE", "0")
        core.log("execve rust-reality; management helper remains out of data path")
        sys.stdout.flush()
        sys.stderr.flush()

        os.execve(
            core.BINARY,
            [str(core.BINARY), "serve", "--config", str(core.CONFIG)],
            environment,
        )


if __name__ == "__main__":
    try:
        run()
    except KeyboardInterrupt:
        raise SystemExit(130)
    except Exception as exc:
        print(f"[FATAL] {exc}", file=sys.stderr, flush=True)
        raise SystemExit(1)
