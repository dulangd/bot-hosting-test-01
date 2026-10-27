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
  RR_SNI=www.microsoft.com           # probe and safely migrate an existing node too
  RR_SNI_ROLLBACK=1                  # restore the last SNI migration without regenerating identity
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
SNI_MIGRATION_FILE = STATE_DIR / "sni-migration-v1.json"
SNI_ROLLBACK_FILE = STATE_DIR / "sni-rollback.json"
AUTO_SNI_MIGRATION_FROM = "www.amazon.com"
AUTO_SNI_MIGRATION_TO = "www.microsoft.com"

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


def probe_sni_candidates() -> dict[str, int | None]:
    """Probe all original candidates without modifying persisted node identity."""
    log("probing REALITY cover candidates")
    results: dict[str, int | None] = {}

    for sni in DEFAULT_SNI_CANDIDATES:
        samples = [
            value
            for value in (
                probe_sni_once(sni),
                probe_sni_once(sni),
            )
            if value is not None
        ]

        if not samples:
            results[sni] = None
            log(f"  {sni}: incompatible/unreachable")
            continue

        latency = min(samples)
        results[sni] = latency
        log(f"  {sni}: {latency} ms")

    return results


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

    candidate_results = probe_sni_candidates()
    results = [
        (latency, sni)
        for sni, latency in candidate_results.items()
        if latency is not None
    ]

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
        SNI_MIGRATION_FILE,
        SNI_ROLLBACK_FILE,
    ):
        with contextlib.suppress(FileNotFoundError):
            path.unlink()


def _json_bytes(value: dict) -> bytes:
    return (json.dumps(value, ensure_ascii=False, indent=2) + "\n").encode()


def _reality_settings(config: dict) -> dict:
    try:
        return config["inbounds"][0]["streamSettings"]["realitySettings"]
    except (KeyError, IndexError, TypeError) as exc:
        raise BootstrapError(
            "persisted configuration has no REALITY settings"
        ) from exc


def _validate_config_candidate(config: dict, *, self_test: bool) -> None:
    fd, tmp_name = tempfile.mkstemp(
        prefix=".sni-config.",
        suffix=".json",
        dir=STATE_DIR,
    )
    tmp = Path(tmp_name)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(_json_bytes(config))
            stream.flush()
            os.fsync(stream.fileno())
        validate_config_file(tmp, self_test=self_test)
    finally:
        with contextlib.suppress(FileNotFoundError):
            tmp.unlink()


def _write_node_state(config: dict, meta: dict) -> None:
    """Write config then metadata; restore both files if validation fails."""
    old_config = CONFIG.read_bytes()
    old_meta = CLIENT_META.read_bytes()
    try:
        atomic_write(CONFIG, _json_bytes(config))
        atomic_write(CLIENT_META, _json_bytes(meta))
        validate_config_file(CONFIG, self_test=False)
    except Exception as exc:
        restore_errors = []
        for path, raw in ((CONFIG, old_config), (CLIENT_META, old_meta)):
            try:
                atomic_write(path, raw)
            except Exception:
                restore_errors.append(path.name)
        if restore_errors:
            raise BootstrapError(
                "SNI state update failed and automatic restore failed for "
                + ", ".join(restore_errors)
            ) from exc
        raise


def _persist_sni_change(config: dict, meta: dict, new_sni: str) -> tuple[dict, dict]:
    """Safely change only SNI-related fields while preserving node identity."""
    if new_sni not in DEFAULT_SNI_CANDIDATES:
        raise BootstrapError("SNI migration target is not in the validated candidate list")

    old_sni = str(meta.get("sni", "")).strip()
    if not old_sni:
        raise BootstrapError("persisted client metadata has no SNI")
    if new_sni == old_sni:
        return config, meta

    new_config = json.loads(json.dumps(config))
    new_meta = json.loads(json.dumps(meta))
    reality = _reality_settings(new_config)
    old_target = reality.get("target")
    old_names = reality.get("serverNames")
    if (
        not isinstance(old_target, str)
        or old_target != f"{old_sni}:443"
        or not isinstance(old_names, list)
        or old_sni not in old_names
    ):
        raise BootstrapError(
            "persisted REALITY target/serverNames do not match metadata; "
            "refusing SNI migration"
        )

    backup = {
        "version": 1,
        "saved_at": int(time.time()),
        "from_sni": old_sni,
        "to_sni": new_sni,
        "target": old_target,
        "serverNames": old_names,
    }
    atomic_write(SNI_ROLLBACK_FILE, _json_bytes(backup))

    reality["target"] = f"{new_sni}:443"
    reality["serverNames"] = [new_sni]
    new_meta["sni"] = new_sni

    for field in ("uuid", "shortId", "publicKey"):
        if new_meta.get(field) != meta.get(field):
            raise BootstrapError("SNI migration attempted to alter node identity")
    old_clients = json.dumps(
        config["inbounds"][0]["settings"]["clients"], sort_keys=True
    )
    new_clients = json.dumps(
        new_config["inbounds"][0]["settings"]["clients"], sort_keys=True
    )
    if old_clients != new_clients:
        raise BootstrapError("SNI migration attempted to alter client identities")

    _validate_config_candidate(new_config, self_test=True)
    _write_node_state(new_config, new_meta)
    log(
        f"persisted REALITY SNI migrated: {old_sni} -> {new_sni}; "
        "UUID, Short ID, public key and endpoint identities preserved"
    )
    return new_config, new_meta


def _rollback_persisted_sni(config: dict, meta: dict) -> tuple[dict, dict]:
    if not SNI_ROLLBACK_FILE.exists():
        log("SNI rollback requested, but no saved SNI migration exists")
        return config, meta

    try:
        backup = json.loads(SNI_ROLLBACK_FILE.read_text("utf-8"))
    except Exception:
        log("SNI rollback file is unreadable; persisted node state left unchanged")
        return config, meta

    if str(meta.get("sni", "")) != str(backup.get("to_sni", "")):
        log("SNI rollback skipped; current SNI is not the last migrated target")
        return config, meta

    old_target = backup.get("target")
    old_names = backup.get("serverNames")
    old_sni = str(backup.get("from_sni", "")).strip()
    if not isinstance(old_target, str) or not isinstance(old_names, list) or not old_sni:
        log("SNI rollback data is incomplete; persisted node state left unchanged")
        return config, meta

    restored_config = json.loads(json.dumps(config))
    restored_meta = json.loads(json.dumps(meta))
    reality = _reality_settings(restored_config)
    reality["target"] = old_target
    reality["serverNames"] = old_names
    restored_meta["sni"] = old_sni

    _validate_config_candidate(restored_config, self_test=False)
    _write_node_state(restored_config, restored_meta)
    log(f"persisted REALITY SNI rolled back to {old_sni}; node identity preserved")
    return restored_config, restored_meta


def _record_sni_migration(report: dict) -> None:
    try:
        atomic_write(SNI_MIGRATION_FILE, _json_bytes(report))
    except Exception as exc:
        log(f"could not persist SNI migration report ({type(exc).__name__})")


def maybe_migrate_existing_sni(config: dict, meta: dict) -> tuple[dict, dict]:
    """Apply one probed SNI change to an existing node, without regenerating it."""
    current_sni = str(meta.get("sni", "")).strip()

    if os.environ.get("RR_SNI_ROLLBACK", "").strip() == "1":
        report = {
            "version": 1,
            "attempted_at": int(time.time()),
            "mode": "rollback",
            "from_sni": current_sni,
        }
        try:
            config, meta = _rollback_persisted_sni(config, meta)
            report["outcome"] = (
                "rolled-back" if str(meta.get("sni", "")) != current_sni
                else "rollback-no-op"
            )
        except Exception as exc:
            log(f"SNI rollback failed; current node state retained ({type(exc).__name__})")
            report["outcome"] = "rollback-failed-current-state-retained"
        _record_sni_migration(report)
        return config, meta

    forced = os.environ.get("RR_SNI", "").strip()
    if forced:
        report = {
            "version": 1,
            "attempted_at": int(time.time()),
            "mode": "explicit",
            "from_sni": current_sni,
            "requested_sni": forced,
        }
        if forced not in DEFAULT_SNI_CANDIDATES:
            log("existing-node RR_SNI ignored: choose one of the six validated candidates")
            report["outcome"] = "rejected-not-in-candidate-list"
        elif forced == current_sni:
            log(f"RR_SNI already matches persisted REALITY SNI: {current_sni}")
            report["outcome"] = "already-current"
        else:
            latency = probe_sni_once(forced)
            report["probe_ms"] = latency
            if latency is None:
                log(f"requested REALITY SNI probe failed: {forced}; existing SNI retained")
                report["outcome"] = "probe-failed-current-retained"
            else:
                try:
                    config, meta = _persist_sni_change(config, meta, forced)
                    report["outcome"] = "explicit-migration-applied"
                except Exception as exc:
                    log(
                        f"requested REALITY SNI was not applied; existing state retained "
                        f"({type(exc).__name__})"
                    )
                    report["outcome"] = "config-validation-failed-current-retained"
        _record_sni_migration(report)
        return config, meta

    if SNI_MIGRATION_FILE.exists() or current_sni != AUTO_SNI_MIGRATION_FROM:
        return config, meta

    results = probe_sni_candidates()
    report = {
        "version": 1,
        "attempted_at": int(time.time()),
        "mode": "one-time-existing-node-test",
        "from_sni": current_sni,
        "requested_sni": AUTO_SNI_MIGRATION_TO,
        "candidate_results_ms": results,
    }
    microsoft_latency = results.get(AUTO_SNI_MIGRATION_TO)
    if microsoft_latency is None:
        log(
            f"{AUTO_SNI_MIGRATION_TO} did not pass probe-dest; "
            f"keeping persisted SNI {current_sni}"
        )
        report["outcome"] = "candidate-probe-failed-current-retained"
    else:
        try:
            config, meta = _persist_sni_change(
                config, meta, AUTO_SNI_MIGRATION_TO
            )
            report["outcome"] = "migrated-to-microsoft"
        except Exception as exc:
            log(
                f"{AUTO_SNI_MIGRATION_TO} passed probe-dest but migration validation "
                f"failed; existing SNI retained ({type(exc).__name__})"
            )
            report["outcome"] = "config-validation-failed-current-retained"

    _record_sni_migration(report)
    return config, meta


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

    persisted_sni = str(meta["sni"]).strip()
    if not persisted_sni:
        raise BootstrapError("persisted client metadata contains an empty SNI")

    # Reapply the current profile, then reconcile the persisted server target
    # and accepted serverNames with the client metadata before testing a change.
    config = apply_performance_profile(config, port)
    reality = _reality_settings(config)
    if (
        reality.get("target") != f"{persisted_sni}:443"
        or reality.get("serverNames") != [persisted_sni]
    ):
        log("persisted REALITY target/serverNames differ from metadata; repairing alignment")
        reality["target"] = f"{persisted_sni}:443"
        reality["serverNames"] = [persisted_sni]

    atomic_write(CONFIG, _json_bytes(config))
    validate_config_file(CONFIG, self_test=False)

    config, meta = maybe_migrate_existing_sni(config, meta)

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
        # Keep the Bot-Hosting panel startup file unchanged. By default the
        # existing main.py now enters the additive registry/traffic wrapper.
        # RR_LEGACY_SINGLE_ENDPOINT=1 restores the exact old single-link path.
        if os.environ.get("RR_LEGACY_SINGLE_ENDPOINT", "0") == "1":
            main()
        else:
            sys.modules.setdefault("main", sys.modules[__name__])
            from main_v2 import run as run_managed
            run_managed()
    except KeyboardInterrupt:
        raise SystemExit(130)
    except Exception as exc:
        print(
            f"[FATAL] {exc}",
            file=sys.stderr,
            flush=True,
        )
        raise SystemExit(1)