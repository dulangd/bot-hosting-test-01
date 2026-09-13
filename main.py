"""
High-performance Bot-Hosting bootstrap for rust-reality v1.6.1.

Design:
  - ONLY the official static x86_64 MUSL release is supported.
  - NO gcompat, glibc fallback, package manager, source build, cargo or rustc.
  - VLESS + REALITY + xtls-rprx-vision, standalone/direct.
  - runtime.profile = dedicated
  - runtime.tuning.mode = startup
  - runtime.tuning.objective = throughput
  - IPv4-only for the current Bot-Hosting test deployment.
  - Logging is disabled by default for minimum steady-state overhead.
  - Python calls execve(), so Python is not resident after startup.

Required Bot-Hosting environment:
  SERVER_PORT

Current deployment:
  node = fi3.bot-hosting.net
  port = SERVER_PORT (25901)

Optional environment:
  RR_SERVER_ADDRESS=fi3.bot-hosting.net # override client link address
  RR_PORT=20202                      # override SERVER_PORT
  RR_SNI=www.microsoft.com           # force one REALITY cover
  RR_NODE_NAME=BotHosting-rust-reality # v2rayN display name
  RR_LOG_OUTPUT=stderr               # default: stderr in this diagnostic build
  RR_REGENERATE=1                    # explicitly discard old node identity
"""

from __future__ import annotations

import contextlib
import fcntl
import hashlib
import ipaddress
import json
import os
import re
import shutil
import socket
import struct
import subprocess
import sys
import tarfile
import tempfile
import time
import urllib.parse
import urllib.request
from pathlib import Path


# ---------------------------------------------------------------------------
# Pinned release
# ---------------------------------------------------------------------------

VERSION = "1.6.1"
TAG = "v1.6.1"
REPOSITORY = "jacek4yang/rust-reality"
ASSET = "rust-reality-v1.6.1-linux-x86_64-musl.tar.gz"

RELEASE_BASE = (
    f"https://github.com/{REPOSITORY}/releases/download/{TAG}"
)
ASSET_URL = f"{RELEASE_BASE}/{ASSET}"
SHA256SUMS_URL = f"{RELEASE_BASE}/SHA256SUMS"

# Candidates are intentionally ordinary large TLS 1.3 sites. rust-reality's
# own probe-dest is authoritative; incompatible candidates are ignored.
DEFAULT_SNI_CANDIDATES = (
    "www.microsoft.com",
    "www.apple.com",
    "www.cloudflare.com",
    "www.amazon.com",
    "www.ibm.com",
    "www.nvidia.com",
)

HOME = Path(os.environ.get("HOME", "/home/container"))
STATE_DIR = HOME / ".rust-reality-node" / TAG
BINARY = STATE_DIR / "rust-reality"
CONFIG = STATE_DIR / "config.json"
CLIENT_META = STATE_DIR / "client.json"
CLIENT_LINK = STATE_DIR / "client-link.txt"
LOCK_FILE = STATE_DIR / ".bootstrap.lock"

MAX_DOWNLOAD_BYTES = 128 * 1024 * 1024
HTTP_TIMEOUT = 30

PUBLIC_KEY_RE = re.compile(
    r"REALITY public key for the client:\s*([A-Za-z0-9_-]{40,64})"
)


class BootstrapError(RuntimeError):
    pass


def log(message: str) -> None:
    print(
        f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] {message}",
        flush=True,
    )


def fatal(message: str) -> "NoReturn":
    raise BootstrapError(message)


# ---------------------------------------------------------------------------
# Small robust primitives
# ---------------------------------------------------------------------------

def atomic_write(path: Path, data: bytes, mode: int = 0o600) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)

    fd, tmp_name = tempfile.mkstemp(
        prefix=f".{path.name}.",
        suffix=".tmp",
        dir=path.parent,
    )
    tmp = Path(tmp_name)

    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())

        os.chmod(tmp, mode)
        os.replace(tmp, path)

        # Best-effort durability of the rename itself.
        try:
            directory_fd = os.open(path.parent, os.O_RDONLY)
        except OSError:
            directory_fd = None

        if directory_fd is not None:
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
    finally:
        with contextlib.suppress(FileNotFoundError):
            tmp.unlink()


def run(
    args: list[str],
    *,
    timeout: float = 15.0,
) -> subprocess.CompletedProcess[str]:
    try:
        result = subprocess.run(
            args,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired as exc:
        raise BootstrapError(
            f"command timed out after {timeout}s: {' '.join(args)}"
        ) from exc
    except OSError as exc:
        raise BootstrapError(
            f"cannot execute {' '.join(args)}: {exc}"
        ) from exc

    if result.returncode != 0:
        detail = (result.stderr or result.stdout).strip()
        if len(detail) > 4000:
            detail = detail[-4000:]
        raise BootstrapError(
            f"command failed ({result.returncode}): {' '.join(args)}"
            + (f"\n{detail}" if detail else "")
        )

    return result


def request(url: str):
    return urllib.request.Request(
        url,
        headers={
            "User-Agent": f"bot-hosting-rust-reality/{VERSION}",
            "Accept": "*/*",
        },
    )


def fetch_text(url: str, max_bytes: int = 1024 * 1024) -> str:
    last_error: Exception | None = None

    for attempt in range(3):
        try:
            with urllib.request.urlopen(
                request(url),
                timeout=HTTP_TIMEOUT,
            ) as response:
                data = response.read(max_bytes + 1)

            if len(data) > max_bytes:
                raise BootstrapError(
                    f"response exceeds {max_bytes} bytes: {url}"
                )

            return data.decode("utf-8")
        except Exception as exc:
            last_error = exc
            if attempt != 2:
                time.sleep(1 << attempt)

    raise BootstrapError(
        f"failed to fetch {url}: {last_error}"
    )


def download(url: str, destination: Path) -> None:
    last_error: Exception | None = None

    for attempt in range(3):
        partial = destination.with_name(destination.name + ".part")
        with contextlib.suppress(FileNotFoundError):
            partial.unlink()

        try:
            total = 0
            with urllib.request.urlopen(
                request(url),
                timeout=HTTP_TIMEOUT,
            ) as source, open(partial, "wb") as target:
                while True:
                    chunk = source.read(1024 * 1024)
                    if not chunk:
                        break

                    total += len(chunk)
                    if total > MAX_DOWNLOAD_BYTES:
                        raise BootstrapError(
                            f"download exceeds {MAX_DOWNLOAD_BYTES} bytes"
                        )

                    target.write(chunk)

                target.flush()
                os.fsync(target.fileno())

            if total == 0:
                raise BootstrapError("download returned an empty file")

            os.replace(partial, destination)
            return
        except Exception as exc:
            last_error = exc
            with contextlib.suppress(FileNotFoundError):
                partial.unlink()

            if attempt != 2:
                time.sleep(1 << attempt)

    raise BootstrapError(
        f"failed to download {url}: {last_error}"
    )


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as stream:
        for chunk in iter(
            lambda: stream.read(1024 * 1024),
            b"",
        ):
            digest.update(chunk)
    return digest.hexdigest()


# ---------------------------------------------------------------------------
# MUSL release installation
# ---------------------------------------------------------------------------

def release_archive_sha256() -> str:
    sums = fetch_text(SHA256SUMS_URL)

    for raw_line in sums.splitlines():
        fields = raw_line.strip().split()
        if len(fields) < 2:
            continue

        filename = fields[-1].lstrip("*")
        if filename != ASSET:
            continue

        digest = fields[0].lower()
        if not re.fullmatch(r"[0-9a-f]{64}", digest):
            raise BootstrapError(
                f"invalid checksum for {ASSET} in SHA256SUMS"
            )

        return digest

    raise BootstrapError(
        f"{ASSET} is not listed in the pinned release SHA256SUMS"
    )


def verify_static_x86_64_elf(path: Path) -> None:
    """
    Minimal ELF64 parser:
      - ELF64
      - little-endian
      - x86_64 (EM_X86_64 = 62)
      - no PT_INTERP

    No external readelf/file dependency.
    """
    with open(path, "rb") as stream:
        header = stream.read(64)

        if len(header) < 64 or header[:4] != b"\x7fELF":
            raise BootstrapError("release binary is not ELF")

        # EI_CLASS=2: ELF64, EI_DATA=1: little endian.
        if header[4] != 2 or header[5] != 1:
            raise BootstrapError(
                "release binary is not little-endian ELF64"
            )

        (
            _e_type,
            e_machine,
            _e_version,
            _e_entry,
            e_phoff,
            _e_shoff,
            _e_flags,
            _e_ehsize,
            e_phentsize,
            e_phnum,
            _e_shentsize,
            _e_shnum,
            _e_shstrndx,
        ) = struct.unpack_from("<HHIQQQIHHHHHH", header, 16)

        if e_machine != 62:
            raise BootstrapError(
                f"release binary architecture is not x86_64 "
                f"(e_machine={e_machine})"
            )

        if e_phentsize < 56 or e_phnum > 4096:
            raise BootstrapError("invalid ELF program-header table")

        file_size = path.stat().st_size
        ph_end = e_phoff + e_phentsize * e_phnum
        if e_phoff > file_size or ph_end > file_size:
            raise BootstrapError(
                "ELF program-header table is outside the file"
            )

        stream.seek(e_phoff)

        # PT_INTERP = 3. A fully static MUSL release must not need one.
        for _ in range(e_phnum):
            ph = stream.read(e_phentsize)
            if len(ph) != e_phentsize:
                raise BootstrapError(
                    "truncated ELF program-header table"
                )

            p_type = struct.unpack_from("<I", ph, 0)[0]
            if p_type == 3:
                raise BootstrapError(
                    "release binary contains PT_INTERP; "
                    "expected the fully static MUSL asset"
                )


def binary_is_usable() -> bool:
    if not BINARY.is_file():
        return False

    try:
        verify_static_x86_64_elf(BINARY)
        os.chmod(BINARY, 0o755)
        version = run(
            [str(BINARY), "--version"],
            timeout=5,
        ).stdout.strip()

        return version == f"rust-reality {VERSION}"
    except Exception:
        return False


def install_binary() -> None:
    if binary_is_usable():
        log(f"rust-reality {VERSION} binary ready (cached)")
        return

    archive = STATE_DIR / ASSET

    log(
        f"installing rust-reality {VERSION} "
        f"(static x86_64 MUSL)"
    )

    expected_sha256 = release_archive_sha256()
    download(ASSET_URL, archive)

    actual_sha256 = sha256_file(archive)
    if actual_sha256 != expected_sha256:
        with contextlib.suppress(FileNotFoundError):
            archive.unlink()
        raise BootstrapError(
            "release archive SHA256 mismatch: "
            f"expected={expected_sha256} actual={actual_sha256}"
        )

    with tarfile.open(archive, "r:gz") as tar:
        candidates = [
            member
            for member in tar.getmembers()
            if member.isfile()
            and Path(member.name).name == "rust-reality"
        ]

        if len(candidates) != 1:
            raise BootstrapError(
                "release archive must contain exactly one "
                "rust-reality executable"
            )

        member = candidates[0]
        if not 0 < member.size <= MAX_DOWNLOAD_BYTES:
            raise BootstrapError(
                f"invalid rust-reality size: {member.size}"
            )

        source = tar.extractfile(member)
        if source is None:
            raise BootstrapError(
                "cannot read rust-reality from release archive"
            )

        fd, tmp_name = tempfile.mkstemp(
            prefix=".rust-reality.",
            suffix=".tmp",
            dir=STATE_DIR,
        )
        tmp = Path(tmp_name)

        try:
            with os.fdopen(fd, "wb") as target:
                shutil.copyfileobj(
                    source,
                    target,
                    length=1024 * 1024,
                )
                target.flush()
                os.fsync(target.fileno())

            os.chmod(tmp, 0o755)
            verify_static_x86_64_elf(tmp)
            os.replace(tmp, BINARY)
        finally:
            with contextlib.suppress(FileNotFoundError):
                tmp.unlink()

    with contextlib.suppress(FileNotFoundError):
        archive.unlink()

    if not binary_is_usable():
        raise BootstrapError(
            "the pinned static MUSL rust-reality binary "
            "cannot execute in this container"
        )


# ---------------------------------------------------------------------------
# Bot-Hosting environment
# ---------------------------------------------------------------------------

def public_port() -> int:
    raw = (
        os.environ.get("RR_PORT")
        or os.environ.get("SERVER_PORT")
    )

    if not raw:
        raise BootstrapError(
            "SERVER_PORT is missing; set RR_PORT explicitly"
        )

    try:
        value = int(raw)
    except ValueError as exc:
        raise BootstrapError(
            f"invalid port: {raw!r}"
        ) from exc

    if not 1 <= value <= 65535:
        raise BootstrapError(
            f"port outside 1..65535: {value}"
        )

    return value


BOT_HOSTING_NODE = "fi3.bot-hosting.net"


def public_host() -> str:
    # Use the node hostname shown in Bot-Hosting's Network page.
    # Do not hard-code the panel's displayed IP: fi3 currently resolves
    # to 65.108.103.151 according to Bot-Hosting's node documentation,
    # while the UI screenshot displayed 65.108.103.15. The hostname avoids
    # that mismatch and follows any future node-IP correction.
    value = (
        os.environ.get("RR_SERVER_ADDRESS")
        or BOT_HOSTING_NODE
    ).strip().strip("[]")

    if not value:
        raise BootstrapError(
            "public server address is empty; set RR_SERVER_ADDRESS"
        )

    return value


def resolve_ipv4(host: str) -> list[str]:
    try:
        values = socket.getaddrinfo(
            host,
            None,
            family=socket.AF_INET,
            type=socket.SOCK_STREAM,
        )
    except OSError as exc:
        log(f"DNS lookup failed for {host}: {exc}")
        return []

    return sorted({item[4][0] for item in values})


# ---------------------------------------------------------------------------
# REALITY SNI selection
# ---------------------------------------------------------------------------

def probe_sni_once(sni: str) -> int | None:
    try:
        result = run(
            [
                str(BINARY),
                "probe-dest",
                "--target",
                f"{sni}:443",
                "--server-name",
                sni,
                "--timeout-ms",
                "4000",
            ],
            timeout=6,
        )

        report = json.loads(result.stdout)

        if report.get("compatible") is not True:
            return None

        return int(report["totalMillis"])
    except Exception:
        return None


def select_sni() -> str:
    forced = os.environ.get("RR_SNI", "").strip()

    if forced:
        latency = probe_sni_once(forced)
        if latency is None:
            raise BootstrapError(
                f"RR_SNI={forced!r} failed rust-reality probe-dest"
            )

        log(f"using forced REALITY SNI: {forced} ({latency} ms)")
        return forced

    log("probing REALITY cover candidates")

    results: list[tuple[int, str]] = []

    for sni in DEFAULT_SNI_CANDIDATES:
        # Two attempts reduce one-off DNS/TCP noise. We use the better
        # successful result so one cgroup-throttled sample does not poison
        # selection.
        samples = [
            value
            for value in (
                probe_sni_once(sni),
                probe_sni_once(sni),
            )
            if value is not None
        ]

        if not samples:
            log(f"  {sni}: incompatible/unreachable")
            continue

        latency = min(samples)
        results.append((latency, sni))
        log(f"  {sni}: {latency} ms")

    if not results:
        raise BootstrapError(
            "no compatible REALITY cover found; "
            "set RR_SNI to a reachable TLS 1.3 hostname"
        )

    latency, sni = min(results)
    log(f"selected REALITY SNI: {sni} ({latency} ms)")
    return sni


# ---------------------------------------------------------------------------
# rust-reality configuration
# ---------------------------------------------------------------------------

def apply_performance_profile(
    config: dict,
    port: int,
) -> dict:
    """
    Keep the generated standalone/direct topology and let rust-reality derive
    all numeric resource limits from the real cgroup.

    We specify intent, not hand-tuned magic numbers.
    """
    log_output = (
        os.environ.get("RR_LOG_OUTPUT", "stderr")
        .strip()
        .lower()
    )

    if log_output not in {"none", "stderr"}:
        raise BootstrapError(
            "RR_LOG_OUTPUT must be 'none' or 'stderr'"
        )

    config["log"] = {
        "level": "error",
        "output": log_output,
    }

    network = config.setdefault("network", {})
    dial = network.setdefault("dial", {})
    dial["mode"] = "ipv4Only"

    runtime = config.setdefault("runtime", {})
    runtime["profile"] = "dedicated"
    runtime["tuning"] = {
        "mode": "startup",
        "objective": "throughput",
    }

    try:
        inbound = config["inbounds"][0]
    except (KeyError, IndexError, TypeError) as exc:
        raise BootstrapError(
            "generated configuration contains no public inbound"
        ) from exc

    inbound["port"] = port
    inbound["listen"] = {
        "mode": "ipv4Only",
    }

    return config


def validate_config_file(
    path: Path,
    *,
    self_test: bool,
) -> None:
    run(
        [
            str(BINARY),
            "check",
            "--config",
            str(path),
        ],
        timeout=10,
    )

    if self_test:
        run(
            [
                str(BINARY),
                "self-test",
                "--config",
                str(path),
            ],
            timeout=25,
        )


def generate_node(port: int) -> dict:
    sni = select_sni()

    generated = run(
        [
            str(BINARY),
            "config",
            "generate",
            "standalone",
            "--listen",
            "0.0.0.0",
            "--port",
            str(port),
            "--target",
            f"{sni}:443",
            "--server-name",
            sni,
        ],
        timeout=10,
    )

    try:
        config = json.loads(generated.stdout)
        config = apply_performance_profile(config, port)

        user = config["inbounds"][0]["settings"]["clients"][0]
        uuid = str(user["id"])
        short_ids = user["shortIds"]

        if not isinstance(short_ids, list) or not short_ids:
            raise ValueError("empty shortIds")

        short_id = str(short_ids[0])
    except Exception as exc:
        raise BootstrapError(
            "unexpected rust-reality generated configuration"
        ) from exc

    public_key_match = PUBLIC_KEY_RE.search(generated.stderr)
    if public_key_match is None:
        raise BootstrapError(
            "rust-reality did not return the REALITY public key"
        )

    public_key = public_key_match.group(1)

    config_data = (
        json.dumps(
            config,
            ensure_ascii=False,
            indent=2,
        )
        + "\n"
    ).encode()

    fd, tmp_name = tempfile.mkstemp(
        prefix=".config.",
        suffix=".json",
        dir=STATE_DIR,
    )
    tmp = Path(tmp_name)

    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(config_data)
            stream.flush()
            os.fsync(stream.fileno())

        # Expensive validation is first-generation only.
        validate_config_file(
            tmp,
            self_test=True,
        )
    finally:
        with contextlib.suppress(FileNotFoundError):
            tmp.unlink()

    meta = {
        "version": VERSION,
        "uuid": uuid,
        "shortId": short_id,
        "publicKey": public_key,
        "sni": sni,
    }

    # Client metadata first; CONFIG is the completion marker.
    atomic_write(
        CLIENT_META,
        (
            json.dumps(meta, ensure_ascii=False, indent=2)
            + "\n"
        ).encode(),
    )
    atomic_write(CONFIG, config_data)

    return meta


def explicitly_regenerate_if_requested() -> None:
    if os.environ.get("RR_REGENERATE") != "1":
        return

    log(
        "RR_REGENERATE=1: deleting persisted node identity "
        "(old client links will stop working)"
    )

    for path in (
        CONFIG,
        CLIENT_META,
        CLIENT_LINK,
    ):
        with contextlib.suppress(FileNotFoundError):
            path.unlink()


def load_existing_node(port: int) -> dict | None:
    if not CONFIG.exists():
        return None

    if not CLIENT_META.exists():
        raise BootstrapError(
            f"{CONFIG} exists but {CLIENT_META} is missing. "
            "Set RR_REGENERATE=1 once to create a new identity."
        )

    try:
        config = json.loads(CONFIG.read_text("utf-8"))
        meta = json.loads(CLIENT_META.read_text("utf-8"))
    except Exception as exc:
        raise BootstrapError(
            "persisted node state is unreadable. "
            "Set RR_REGENERATE=1 once to rebuild it."
        ) from exc

    # Reapply the current high-performance profile so an older bootstrap's
    # persisted config cannot silently retain conservative settings.
    config = apply_performance_profile(config, port)

    config_data = (
        json.dumps(
            config,
            ensure_ascii=False,
            indent=2,
        )
        + "\n"
    ).encode()

    atomic_write(CONFIG, config_data)

    # Startup validation is cheap and catches stale/corrupt state.
    validate_config_file(
        CONFIG,
        self_test=False,
    )

    required_meta = {
        "uuid",
        "shortId",
        "publicKey",
        "sni",
    }
    if not required_meta <= set(meta):
        raise BootstrapError(
            "persisted client metadata is incomplete. "
            "Set RR_REGENERATE=1 once to rebuild it."
        )

    log("using persisted node identity")
    persisted_sni = str(meta["sni"])
    latency = probe_sni_once(persisted_sni)
    if latency is None:
        log(f"persisted REALITY SNI probe failed: {persisted_sni}")
    else:
        log(f"persisted REALITY SNI: {persisted_sni} ({latency} ms)")

    return meta


def load_or_create_node(port: int) -> dict:
    explicitly_regenerate_if_requested()

    existing = load_existing_node(port)
    if existing is not None:
        return existing

    return generate_node(port)


# ---------------------------------------------------------------------------
# v2rayN link
# ---------------------------------------------------------------------------

def vless_link(
    meta: dict,
    host: str,
    port: int,
) -> str:
    try:
        parsed_ip = ipaddress.ip_address(host)
        authority_host = (
            f"[{host}]"
            if parsed_ip.version == 6
            else host
        )
    except ValueError:
        authority_host = host

    query = urllib.parse.urlencode(
        {
            "encryption": "none",
            "flow": "xtls-rprx-vision",
            "security": "reality",
            "sni": meta["sni"],
            "fp": "chrome",
            "pbk": meta["publicKey"],
            "sid": meta["shortId"],
            "type": "tcp",
            "headerType": "none",
        },
        safe="",
    )

    node_name = urllib.parse.quote(
        os.environ.get(
            "RR_NODE_NAME",
            "BotHosting-rust-reality",
        ),
        safe="",
    )

    return (
        f"vless://{meta['uuid']}@"
        f"{authority_host}:{port}"
        f"?{query}#{node_name}"
    )


# ---------------------------------------------------------------------------
# Entrypoint
# ---------------------------------------------------------------------------

def main() -> None:
    if sys.platform != "linux":
        raise BootstrapError("Linux is required")

    if os.uname().machine != "x86_64":
        raise BootstrapError(
            "this bootstrap requires x86_64"
        )

    STATE_DIR.mkdir(
        parents=True,
        exist_ok=True,
    )
    os.chmod(STATE_DIR, 0o700)

    # Prevent duplicate panel starts racing persistent state.
    with open(LOCK_FILE, "a+b") as lock:
        fcntl.flock(
            lock.fileno(),
            fcntl.LOCK_EX,
        )

        port = public_port()
        host = public_host()

        log(f"Bot-Hosting SERVER_PORT={port}")
        resolved = resolve_ipv4(host)
        if resolved:
            log(f"{host} resolves to: {', '.join(resolved)}")

        install_binary()

        meta = load_or_create_node(port)
        link = vless_link(meta, host, port)

        atomic_write(
            CLIENT_LINK,
            (link + "\n").encode(),
        )

        print()
        print("=" * 78)
        print(
            f"rust-reality {VERSION} | "
            "standalone/direct | static MUSL"
        )
        print("platform: Bot-Hosting.net")
        print("runtime : dedicated / startup / throughput")
        print("network : IPv4-only")
        print(
            f"logging : "
            f"{os.environ.get('RR_LOG_OUTPUT', 'stderr')}"
        )
        print(f"server  : {host}:{port}")
        print(f"SNI     : {meta['sni']}")
        print()
        print("COPY THIS LINK INTO v2rayN:")
        print()
        print(link)
        print("=" * 78)
        print()
        sys.stdout.flush()
        sys.stderr.flush()

        log(
            "execve rust-reality; Python bootstrap is leaving memory"
        )

        environment = os.environ.copy()
        environment.setdefault(
            "RUST_BACKTRACE",
            "0",
        )

        os.execve(
            BINARY,
            [
                str(BINARY),
                "serve",
                "--config",
                str(CONFIG),
            ],
            environment,
        )


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        raise SystemExit(130)
    except Exception as exc:
        print(
            f"[FATAL] {exc}",
            file=sys.stderr,
            flush=True,
        )
        raise SystemExit(1)