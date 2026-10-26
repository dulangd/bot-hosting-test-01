from __future__ import annotations

import base64
import contextlib
import hashlib
import ipaddress
import json
import os
import re
import secrets
import shutil
import socket
import ssl
import struct
import subprocess
import threading
import time
import urllib.parse
import urllib.request
import uuid
from pathlib import Path
from typing import Any

CF_NODE_ID = "bot-hosting-cf-01"
CF_BASE_NAME = "BotHosting-CF-01"
CF_DEFAULT_ORIGIN_PORT = 25903
CF_DOWNLOAD_URL = "https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-amd64"
CF_IDENTITY_FILE = "cf-identity.json"
CF_BINARY_FILE = "cloudflared"
CF_MAX_DOWNLOAD = 128 * 1024 * 1024


def _log(message: str) -> None:
    print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] {message}", flush=True)


def _atomic_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    with open(tmp, "wb") as stream:
        stream.write((json.dumps(value, ensure_ascii=False, indent=2) + "\n").encode())
        stream.flush()
        os.fsync(stream.fileno())
    os.chmod(tmp, 0o600)
    os.replace(tmp, path)


def _normalize_ws_path(value: str) -> str:
    value = str(value or "").strip()
    if not value:
        value = "/cf-" + secrets.token_urlsafe(12)
    if not value.startswith("/"):
        value = "/" + value
    return value


def load_cf_identity(state_dir: Path) -> dict[str, str]:
    path = state_dir / CF_IDENTITY_FILE
    old: dict[str, Any] = {}
    try:
        value = json.loads(path.read_text("utf-8"))
        if isinstance(value, dict):
            old = value
    except Exception:
        pass

    candidate = str(os.environ.get("BOT_HOSTING_CF_UUID", "") or old.get("uuid", "")).strip()
    try:
        parsed = uuid.UUID(candidate) if candidate else uuid.uuid4()
    except ValueError:
        parsed = uuid.uuid4()
    if parsed.version != 4:
        parsed = uuid.uuid4()

    identity = {
        "uuid": str(parsed),
        "ws_path": _normalize_ws_path(
            os.environ.get("BOT_HOSTING_CF_WS_PATH", "") or str(old.get("ws_path", ""))
        ),
    }
    _atomic_json(path, identity)
    return identity


def cf_configured() -> bool:
    return bool(
        os.environ.get("CF_TUNNEL_TOKEN", "").strip()
        and os.environ.get("CF_TUNNEL_HOSTNAME", "").strip()
    )


def cf_origin_port() -> int:
    raw = os.environ.get("CF_ORIGIN_PORT", str(CF_DEFAULT_ORIGIN_PORT)).strip()
    try:
        value = int(raw)
    except ValueError as exc:
        raise ValueError(f"invalid CF_ORIGIN_PORT={raw!r}") from exc
    if not 1 <= value <= 65535:
        raise ValueError("CF_ORIGIN_PORT outside 1..65535")
    return value


def prepare_cf_endpoint(state_dir: Path, country: str) -> tuple[dict[str, Any], dict[str, str]] | None:
    if not cf_configured():
        return None
    host = os.environ.get("CF_TUNNEL_HOSTNAME", "").strip().lower().strip("[]")
    if not host or "." not in host or any(ch.isspace() for ch in host):
        raise ValueError("CF_TUNNEL_HOSTNAME is invalid")
    identity = load_cf_identity(state_dir)
    cc = country if len(country) == 2 else "XX"
    name = f"{cc}-{CF_BASE_NAME}"
    query = urllib.parse.urlencode({
        "encryption": "none",
        "security": "tls",
        "type": "ws",
        "path": identity["ws_path"],
        "host": host,
        "sni": host,
        "fp": "chrome",
        "alpn": "http/1.1",
    })
    endpoint = {
        "kind": "cf",
        "node_id": CF_NODE_ID,
        "name": name,
        "host": host,
        "port": 443,
        "uri": f"vless://{identity['uuid']}@{host}:443?{query}#{urllib.parse.quote(name)}",
        "traffic_scope": "independent-cf-tunnel",
        "traffic_owner": False,
        "proof_endpoint": f"https://{host}",
        "force_public_proof": True,
    }
    return endpoint, identity


def _is_public_address(value: str) -> bool:
    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        return False
    return not (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_reserved
        or ip.is_unspecified
    )


def _connect_public(host: str, port: int, timeout: float = 10.0) -> socket.socket:
    last_error: Exception | None = None
    for family, socktype, proto, _canon, sockaddr in socket.getaddrinfo(
        host, port, type=socket.SOCK_STREAM
    ):
        ip = str(sockaddr[0])
        if not _is_public_address(ip):
            continue
        sock = socket.socket(family, socktype, proto)
        sock.settimeout(timeout)
        try:
            sock.connect(sockaddr)
            sock.settimeout(None)
            return sock
        except OSError as exc:
            last_error = exc
            with contextlib.suppress(OSError):
                sock.close()
    raise OSError(f"no reachable public address for {host}:{port}: {last_error}")


def _recv_exact(sock: socket.socket, count: int) -> bytes:
    parts = bytearray()
    while len(parts) < count:
        chunk = sock.recv(count - len(parts))
        if not chunk:
            raise EOFError("unexpected EOF")
        parts.extend(chunk)
    return bytes(parts)


def _ws_frame(payload: bytes, opcode: int = 2, *, masked: bool = False) -> bytes:
    payload = bytes(payload)
    first = 0x80 | (opcode & 0x0F)
    mask_bit = 0x80 if masked else 0
    length = len(payload)
    if length < 126:
        header = bytes([first, mask_bit | length])
    elif length <= 0xFFFF:
        header = bytes([first, mask_bit | 126]) + struct.pack("!H", length)
    else:
        header = bytes([first, mask_bit | 127]) + struct.pack("!Q", length)
    if not masked:
        return header + payload
    mask = secrets.token_bytes(4)
    body = bytes(value ^ mask[index & 3] for index, value in enumerate(payload))
    return header + mask + body


def _read_ws_frame(sock: socket.socket) -> tuple[int, bool, bytes]:
    head = _recv_exact(sock, 2)
    fin = bool(head[0] & 0x80)
    opcode = head[0] & 0x0F
    masked = bool(head[1] & 0x80)
    length = head[1] & 0x7F
    if length == 126:
        length = struct.unpack("!H", _recv_exact(sock, 2))[0]
    elif length == 127:
        length = struct.unpack("!Q", _recv_exact(sock, 8))[0]
    if length > 8 * 1024 * 1024:
        raise ValueError("websocket frame too large")
    mask = _recv_exact(sock, 4) if masked else b""
    payload = bytearray(_recv_exact(sock, int(length)))
    if masked:
        for index in range(len(payload)):
            payload[index] ^= mask[index & 3]
    return opcode, fin, bytes(payload)


def _read_ws_message(sock: socket.socket) -> bytes | None:
    fragments: list[bytes] = []
    started = False
    while True:
        opcode, fin, payload = _read_ws_frame(sock)
        if opcode == 8:
            return None
        if opcode == 9:
            sock.sendall(_ws_frame(payload, opcode=10))
            continue
        if opcode == 10:
            continue
        if opcode == 2:
            fragments = [payload]
            started = True
        elif opcode == 0 and started:
            fragments.append(payload)
        else:
            raise ValueError("unsupported websocket opcode")
        if fin:
            return b"".join(fragments)


def _parse_vless_request(data: bytes, expected_uuid: str) -> tuple[int, str, int, bytes]:
    if len(data) < 24:
        raise ValueError("short VLESS request")
    index = 0
    version = data[index]
    index += 1
    expected = uuid.UUID(expected_uuid).bytes
    supplied = data[index:index + 16]
    index += 16
    if supplied != expected:
        raise ValueError("VLESS authentication failed")
    opt_len = data[index]
    index += 1 + opt_len
    if index + 4 > len(data):
        raise ValueError("invalid VLESS request")
    command = data[index]
    index += 1
    if command != 1:
        raise ValueError("only VLESS TCP CONNECT is supported")
    port = struct.unpack("!H", data[index:index + 2])[0]
    index += 2
    atyp = data[index]
    index += 1
    if atyp == 1:
        if index + 4 > len(data):
            raise ValueError("bad VLESS IPv4")
        host = socket.inet_ntop(socket.AF_INET, data[index:index + 4])
        index += 4
    elif atyp == 2:
        if index >= len(data):
            raise ValueError("bad VLESS domain")
        size = data[index]
        index += 1
        if not size or index + size > len(data):
            raise ValueError("bad VLESS domain")
        host = data[index:index + size].decode("idna")
        index += size
    elif atyp == 3:
        if index + 16 > len(data):
            raise ValueError("bad VLESS IPv6")
        host = socket.inet_ntop(socket.AF_INET6, data[index:index + 16])
        index += 16
    else:
        raise ValueError("unsupported VLESS address type")
    if not 1 <= port <= 65535:
        raise ValueError("invalid VLESS target port")
    return version, host, port, data[index:]


class VlessWsOrigin:
    def __init__(self, port: int, identity: dict[str, str], proof: str) -> None:
        self.port = int(port)
        self.identity = identity
        self.proof = str(proof)
        self._sock: socket.socket | None = None
        self._thread: threading.Thread | None = None
        self._stop = threading.Event()

    def start(self) -> None:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(("127.0.0.1", self.port))
        sock.listen(128)
        sock.settimeout(1.0)
        self._sock = sock
        self._thread = threading.Thread(target=self._serve, name="bot-hosting-cf-origin", daemon=True)
        self._thread.start()
        _log(f"CF_ORIGIN_READY http/ws=127.0.0.1:{self.port}")

    def close(self) -> None:
        self._stop.set()
        sock, self._sock = self._sock, None
        if sock is not None:
            with contextlib.suppress(OSError):
                sock.close()
        thread, self._thread = self._thread, None
        if thread and thread is not threading.current_thread():
            thread.join(timeout=2)

    def _serve(self) -> None:
        while not self._stop.is_set():
            sock = self._sock
            if sock is None:
                return
            try:
                conn, _addr = sock.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            threading.Thread(target=self._handle, args=(conn,), daemon=True).start()

    @staticmethod
    def _http_reply(conn: socket.socket, status: int, body: bytes, ctype: str) -> None:
        reason = {200: "OK", 404: "Not Found", 400: "Bad Request"}.get(status, "Error")
        conn.sendall(
            (
                f"HTTP/1.1 {status} {reason}\r\n"
                f"Content-Type: {ctype}\r\n"
                "Cache-Control: no-store\r\n"
                "Connection: close\r\n"
                f"Content-Length: {len(body)}\r\n\r\n"
            ).encode("ascii")
            + body
        )

    def _handle(self, conn: socket.socket) -> None:
        try:
            conn.settimeout(10.0)
            request = bytearray()
            while b"\r\n\r\n" not in request and len(request) < 65536:
                chunk = conn.recv(4096)
                if not chunk:
                    return
                request.extend(chunk)
            if b"\r\n\r\n" not in request:
                return self._http_reply(conn, 400, b"bad request\n", "text/plain")
            header_blob, head = bytes(request).split(b"\r\n\r\n", 1)
            lines = header_blob.decode("iso-8859-1").split("\r\n")
            method, target, _version = lines[0].split(" ", 2)
            headers: dict[str, str] = {}
            for line in lines[1:]:
                if ":" in line:
                    key, value = line.split(":", 1)
                    headers[key.strip().lower()] = value.strip()
            path = urllib.parse.urlsplit(target).path
            if method == "GET" and path == "/health":
                body = json.dumps({"ok": True, "service": "bot-hosting-cf", "ws": True}).encode()
                return self._http_reply(conn, 200, body, "application/json")
            if method == "GET" and path == "/.well-known/registry-proof":
                body = json.dumps({
                    "provider": "bot-hosting",
                    "proof_sha256": {
                        CF_NODE_ID: hashlib.sha256(self.proof.encode()).hexdigest()
                    },
                }, separators=(",", ":")).encode()
                return self._http_reply(conn, 200, body, "application/json")
            if (
                method != "GET"
                or path != self.identity["ws_path"]
                or headers.get("upgrade", "").lower() != "websocket"
                or "upgrade" not in headers.get("connection", "").lower()
                or not headers.get("sec-websocket-key")
            ):
                return self._http_reply(conn, 404, b"not found\n", "text/plain")
            key = headers["sec-websocket-key"]
            accept = base64.b64encode(
                hashlib.sha1((key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").encode()).digest()
            ).decode("ascii")
            conn.sendall(
                (
                    "HTTP/1.1 101 Switching Protocols\r\n"
                    "Upgrade: websocket\r\n"
                    "Connection: Upgrade\r\n"
                    f"Sec-WebSocket-Accept: {accept}\r\n\r\n"
                ).encode("ascii")
            )
            conn.settimeout(None)
            self._proxy_vless(conn, head)
        except (OSError, EOFError, ValueError, UnicodeError):
            return
        finally:
            with contextlib.suppress(OSError):
                conn.close()

    def _proxy_vless(self, conn: socket.socket, initial: bytes) -> None:
        if initial:
            raise ValueError("unexpected websocket bytes before upgrade")
        first = _read_ws_message(conn)
        if first is None:
            return
        version, host, port, payload = _parse_vless_request(first, self.identity["uuid"])
        remote = _connect_public(host, port)
        write_lock = threading.Lock()
        closed = threading.Event()

        def send_frame(data: bytes, opcode: int = 2) -> None:
            with write_lock:
                conn.sendall(_ws_frame(data, opcode=opcode))

        def remote_to_client() -> None:
            try:
                while not closed.is_set():
                    data = remote.recv(64 * 1024)
                    if not data:
                        return
                    send_frame(data)
            except OSError:
                return
            finally:
                closed.set()
                with contextlib.suppress(OSError):
                    conn.shutdown(socket.SHUT_RDWR)

        try:
            send_frame(bytes([version, 0]))
            if payload:
                remote.sendall(payload)
            worker = threading.Thread(target=remote_to_client, daemon=True)
            worker.start()
            while not closed.is_set():
                message = _read_ws_message(conn)
                if message is None:
                    break
                if message:
                    remote.sendall(message)
        finally:
            closed.set()
            with contextlib.suppress(OSError):
                remote.close()


class CloudflaredProcess:
    def __init__(self, process: subprocess.Popen[str], host: str) -> None:
        self.process = process
        self.host = host

    def close(self) -> None:
        if self.process.poll() is None:
            with contextlib.suppress(Exception):
                self.process.terminate()
                self.process.wait(timeout=4)
            if self.process.poll() is None:
                with contextlib.suppress(Exception):
                    self.process.kill()


class CloudflareRuntime:
    def __init__(self, origin: VlessWsOrigin, tunnel: CloudflaredProcess) -> None:
        self.origin = origin
        self.tunnel = tunnel

    def close(self) -> None:
        self.tunnel.close()
        self.origin.close()


def _ensure_cloudflared(state_dir: Path) -> Path:
    explicit = os.environ.get("CLOUDFLARED_BIN", "").strip()
    if explicit:
        path = Path(explicit)
        if path.is_file() and os.access(path, os.X_OK):
            return path
    system = shutil.which("cloudflared")
    if system:
        return Path(system)
    binary = state_dir / CF_BINARY_FILE
    if binary.is_file() and os.access(binary, os.X_OK):
        try:
            result = subprocess.run(
                [str(binary), "--version"], stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                text=True, timeout=5, check=False,
            )
            if result.returncode == 0:
                return binary
        except Exception:
            pass
    _log("CF_TUNNEL_INSTALL downloading official cloudflared amd64 binary")
    req = urllib.request.Request(CF_DOWNLOAD_URL, headers={"User-Agent": "bot-hosting-cf/1.0"})
    tmp = binary.with_name(binary.name + ".part")
    total = 0
    with urllib.request.urlopen(req, timeout=30) as source, open(tmp, "wb") as target:
        while True:
            chunk = source.read(1024 * 1024)
            if not chunk:
                break
            total += len(chunk)
            if total > CF_MAX_DOWNLOAD:
                raise RuntimeError("cloudflared download exceeds size limit")
            target.write(chunk)
        target.flush()
        os.fsync(target.fileno())
    if total < 1024 * 1024:
        raise RuntimeError("cloudflared download unexpectedly small")
    with open(tmp, "rb") as stream:
        if stream.read(4) != b"\x7fELF":
            raise RuntimeError("cloudflared download is not an ELF binary")
    os.chmod(tmp, 0o755)
    os.replace(tmp, binary)
    result = subprocess.run(
        [str(binary), "--version"], stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        text=True, timeout=5, check=False,
    )
    if result.returncode != 0:
        raise RuntimeError("downloaded cloudflared cannot execute")
    return binary


def _start_cloudflared(state_dir: Path, host: str) -> CloudflaredProcess:
    token = os.environ.get("CF_TUNNEL_TOKEN", "").strip()
    if not token:
        raise RuntimeError("CF_TUNNEL_TOKEN missing")
    binary = _ensure_cloudflared(state_dir)
    _log(f"CF_NAMED_TUNNEL_START host={host} protocol=auto")
    process = subprocess.Popen(
        [str(binary), "tunnel", "--no-autoupdate", "run", "--token", token],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1,
        env=os.environ.copy(),
    )
    ready = threading.Event()
    last_lines: list[str] = []

    def reader() -> None:
        stream = process.stdout
        if stream is None:
            return
        for line in stream:
            clean = line.strip()
            if not clean:
                continue
            clean = clean.replace(token, "[redacted]")
            last_lines.append(clean[-500:])
            del last_lines[:-8]
            if re.search(r"registered tunnel connection|connection .* registered", clean, re.I):
                ready.set()
            if any(word in clean.lower() for word in ("registered", "failed", "error")):
                print(f"[cloudflared] {clean}", flush=True)

    threading.Thread(target=reader, name="bot-hosting-cloudflared-log", daemon=True).start()
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        if process.poll() is not None:
            detail = " | ".join(last_lines[-3:])
            raise RuntimeError(f"cloudflared exited rc={process.returncode}: {detail}")
        if ready.wait(0.25):
            _log(f"CF_NAMED_TUNNEL_READY host={host}")
            return CloudflaredProcess(process, host)
    process.terminate()
    with contextlib.suppress(Exception):
        process.wait(timeout=3)
    detail = " | ".join(last_lines[-3:])
    raise RuntimeError(f"cloudflared did not register within 30s: {detail}")


def _ws_upgrade(sock: socket.socket, host: str, path: str) -> None:
    key = base64.b64encode(secrets.token_bytes(16)).decode("ascii")
    request = (
        f"GET {path} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        "Upgrade: websocket\r\n"
        "Connection: Upgrade\r\n"
        f"Sec-WebSocket-Key: {key}\r\n"
        "Sec-WebSocket-Version: 13\r\n\r\n"
    ).encode("ascii")
    sock.sendall(request)
    response = bytearray()
    while b"\r\n\r\n" not in response and len(response) < 65536:
        chunk = sock.recv(4096)
        if not chunk:
            break
        response.extend(chunk)
    header = bytes(response).split(b"\r\n\r\n", 1)[0]
    if not header.startswith(b"HTTP/1.1 101") and not header.startswith(b"HTTP/1.0 101"):
        first = header.split(b"\r\n", 1)[0].decode("ascii", "replace")
        raise RuntimeError(f"websocket upgrade failed: {first}")


def _vless_probe(host: str, identity: dict[str, str]) -> None:
    raw = socket.create_connection((host, 443), timeout=10)
    context = ssl.create_default_context()
    tls = context.wrap_socket(raw, server_hostname=host)
    tls.settimeout(10)
    try:
        _ws_upgrade(tls, host, identity["ws_path"])
        domain = b"example.com"
        payload = (
            bytes([0])
            + uuid.UUID(identity["uuid"]).bytes
            + bytes([0, 1])
            + struct.pack("!H", 80)
            + bytes([2, len(domain)])
            + domain
            + b"GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n"
        )
        tls.sendall(_ws_frame(payload, masked=True))
        collected = bytearray()
        deadline = time.monotonic() + 10
        got_header = False
        while time.monotonic() < deadline and len(collected) < 256 * 1024:
            opcode, _fin, frame = _read_ws_frame(tls)
            if opcode == 8:
                break
            if opcode == 9:
                tls.sendall(_ws_frame(frame, opcode=10, masked=True))
                continue
            if opcode != 2:
                continue
            if not got_header:
                if len(frame) < 2 or frame[0] != 0:
                    raise RuntimeError("invalid VLESS probe response")
                got_header = True
                frame = frame[2:]
            collected.extend(frame)
            if b"HTTP/" in collected:
                return
        raise RuntimeError("VLESS public probe did not receive HTTP response")
    finally:
        with contextlib.suppress(OSError):
            tls.close()


def _public_selftest(host: str, identity: dict[str, str]) -> None:
    last_error: Exception | None = None
    for attempt in range(1, 7):
        try:
            req = urllib.request.Request(
                f"https://{host}/health",
                headers={"User-Agent": "bot-hosting-cf-selftest/1.0"},
            )
            with urllib.request.urlopen(req, timeout=10) as response:
                if response.status != 200:
                    raise RuntimeError(f"health HTTP {response.status}")
            _vless_probe(host, identity)
            _log(f"CF_PUBLIC_VLESS_SELFTEST_READY host={host}:443 attempt={attempt}")
            return
        except Exception as exc:
            last_error = exc
            if attempt != 6:
                time.sleep(min(2 * attempt, 5))
    raise RuntimeError(f"CF public self-test failed: {last_error}")


def start_cf_runtime(
    state_dir: Path,
    identity: dict[str, str],
    proof: str,
    host: str,
) -> CloudflareRuntime:
    origin = VlessWsOrigin(cf_origin_port(), identity, proof)
    tunnel: CloudflaredProcess | None = None
    try:
        origin.start()
        tunnel = _start_cloudflared(state_dir, host)
        _public_selftest(host, identity)
        return CloudflareRuntime(origin, tunnel)
    except Exception:
        if tunnel is not None:
            tunnel.close()
        origin.close()
        raise
