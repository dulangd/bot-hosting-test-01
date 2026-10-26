from __future__ import annotations

import base64
import contextlib
import hashlib
import ipaddress
import json
import os
import queue
import re
import secrets
import socket
import struct
import subprocess
import threading
import time
import urllib.parse
import urllib.request
import uuid
from pathlib import Path
from typing import Any

CLOUDFLARED_URL = "https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-amd64"
CF_NODE_ID = "bot-hosting-cf-01"
CF_NAME = "BotHosting-CF-01"


def _atomic_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    with open(tmp, "wb") as f:
        f.write((json.dumps(value, ensure_ascii=False, indent=2) + "\n").encode())
        f.flush()
        os.fsync(f.fileno())
    os.chmod(tmp, 0o600)
    os.replace(tmp, path)


def load_identity(state_dir: Path) -> dict[str, str]:
    path = state_dir / "cf-identity.json"
    try:
        old = json.loads(path.read_text("utf-8"))
    except Exception:
        old = {}
    value = {
        "uuid": str(old.get("uuid") or uuid.uuid4()),
        "ws_path": str(old.get("ws_path") or ("/ws-" + secrets.token_urlsafe(12))),
    }
    if not value["ws_path"].startswith("/"):
        value["ws_path"] = "/" + value["ws_path"]
    uuid.UUID(value["uuid"])
    _atomic_json(path, value)
    return value


def build_cf_endpoint(identity: dict[str, str], host: str, country: str) -> dict[str, Any]:
    cc = country if len(country) == 2 else "XX"
    name = f"{cc}-{CF_NAME}"
    query = urllib.parse.urlencode({
        "encryption": "none",
        "security": "tls",
        "type": "ws",
        "host": host,
        "path": identity["ws_path"],
        "sni": host,
        "fp": "chrome",
        "alpn": "http/1.1",
    })
    uri = (
        f"vless://{identity['uuid']}@{host}:443?"
        f"{query}#{urllib.parse.quote(name)}"
    )
    return {
        "kind": "cf",
        "node_id": CF_NODE_ID,
        "name": name,
        "host": host,
        "port": 443,
        "uri": uri,
        "proof_endpoint": f"https://{host}",
        "traffic_scope": "shared-instance",
        "traffic_owner": False,
    }


def pick_loopback_port(exclude: set[int] | None = None) -> int:
    blocked = exclude or set()
    for candidate in list(range(26000, 26300)) + list(range(46000, 46300)):
        if candidate in blocked:
            continue
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            sock.bind(("127.0.0.1", candidate))
            return candidate
        except OSError:
            pass
        finally:
            sock.close()
    raise RuntimeError("no loopback port available for Cloudflare WS service")


def _read_http_request(conn: socket.socket) -> tuple[bytes, bytes]:
    buf = bytearray()
    while b"\r\n\r\n" not in buf and len(buf) < 65536:
        chunk = conn.recv(4096)
        if not chunk:
            break
        buf.extend(chunk)
    pos = buf.find(b"\r\n\r\n")
    if pos < 0:
        raise ValueError("incomplete HTTP request")
    return bytes(buf[:pos + 4]), bytes(buf[pos + 4:])


def _parse_headers(raw: bytes) -> tuple[str, dict[str, str]]:
    text = raw.decode("iso-8859-1")
    lines = text.split("\r\n")
    request_line = lines[0]
    headers: dict[str, str] = {}
    for line in lines[1:]:
        if not line or ":" not in line:
            continue
        k, v = line.split(":", 1)
        headers[k.strip().lower()] = v.strip()
    return request_line, headers


def _ws_frame(payload: bytes, opcode: int = 2) -> bytes:
    n = len(payload)
    if n < 126:
        return bytes([0x80 | opcode, n]) + payload
    if n <= 0xFFFF:
        return bytes([0x80 | opcode, 126]) + struct.pack("!H", n) + payload
    return bytes([0x80 | opcode, 127]) + struct.pack("!Q", n) + payload


def _is_private_target(host: str) -> bool:
    try:
        ip = ipaddress.ip_address(host)
        return ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_unspecified
    except ValueError:
        return False


def _parse_vless_request(data: bytes, expected_uuid: str) -> tuple[int, str, int, bytes]:
    if len(data) < 24:
        raise ValueError("short VLESS request")
    i = 0
    version = data[i]
    i += 1
    expected = uuid.UUID(expected_uuid).bytes
    actual = data[i:i + 16]
    i += 16
    if actual != expected:
        raise ValueError("VLESS UUID mismatch")
    opt_len = data[i]
    i += 1
    i += opt_len
    if i + 4 > len(data):
        raise ValueError("invalid VLESS request")
    command = data[i]
    i += 1
    if command != 1:
        raise ValueError("only TCP CONNECT supported")
    port = struct.unpack("!H", data[i:i + 2])[0]
    i += 2
    atyp = data[i]
    i += 1
    if atyp == 1:
        if i + 4 > len(data):
            raise ValueError("bad IPv4")
        host = socket.inet_ntop(socket.AF_INET, data[i:i + 4])
        i += 4
    elif atyp == 2:
        if i >= len(data):
            raise ValueError("bad domain")
        n = data[i]
        i += 1
        if not n or i + n > len(data):
            raise ValueError("bad domain")
        host = data[i:i + n].decode("utf-8")
        i += n
    elif atyp == 3:
        if i + 16 > len(data):
            raise ValueError("bad IPv6")
        host = socket.inet_ntop(socket.AF_INET6, data[i:i + 16])
        i += 16
    else:
        raise ValueError("unsupported VLESS address type")
    if _is_private_target(host):
        raise ValueError("private target blocked")
    return version, host, port, data[i:]


class CloudflareWsServer:
    def __init__(
        self,
        port: int,
        identity: dict[str, str],
        geo: dict[str, Any],
        proofs: dict[str, str] | None = None,
    ) -> None:
        self.port = int(port)
        self.identity = identity
        self.geo = geo
        self.proofs = proofs if isinstance(proofs, dict) else {}
        self._sock: socket.socket | None = None
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    def set_proofs(self, proofs: dict[str, str]) -> None:
        self.proofs = proofs

    def start(self) -> None:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(("127.0.0.1", self.port))
        sock.listen(128)
        self._sock = sock
        self._thread = threading.Thread(target=self._serve, daemon=True, name="bot-hosting-cf-ws")
        self._thread.start()

    def close(self) -> None:
        self._stop.set()
        sock, self._sock = self._sock, None
        if sock:
            with contextlib.suppress(OSError):
                sock.close()
        thread, self._thread = self._thread, None
        if thread and thread is not threading.current_thread():
            thread.join(timeout=2)

    def _serve(self) -> None:
        assert self._sock is not None
        while not self._stop.is_set():
            try:
                conn, _ = self._sock.accept()
            except OSError:
                if self._stop.is_set():
                    return
                continue
            threading.Thread(target=self._handle, args=(conn,), daemon=True).start()

    def _http_reply(self, conn: socket.socket, status: int, body: bytes, ctype: str) -> None:
        reason = {200: "OK", 404: "Not Found", 400: "Bad Request"}.get(status, "Error")
        head = (
            f"HTTP/1.1 {status} {reason}\r\n"
            f"Content-Type: {ctype}\r\n"
            "Cache-Control: no-store\r\n"
            "Connection: close\r\n"
            f"Content-Length: {len(body)}\r\n\r\n"
        ).encode("ascii")
        conn.sendall(head + body)

    def _handle(self, conn: socket.socket) -> None:
        try:
            conn.settimeout(10)
            raw, extra = _read_http_request(conn)
            line, headers = _parse_headers(raw)
            parts = line.split(" ")
            if len(parts) < 2:
                self._http_reply(conn, 400, b"bad request\n", "text/plain")
                return
            method, target = parts[0], parts[1]
            path = urllib.parse.urlsplit(target).path

            if (
                method == "GET"
                and path == self.identity["ws_path"]
                and headers.get("upgrade", "").lower() == "websocket"
                and "upgrade" in headers.get("connection", "").lower()
                and headers.get("sec-websocket-key")
            ):
                self._upgrade(conn, headers, extra)
                return

            if method == "GET" and path == "/health":
                body = json.dumps({
                    "ok": True,
                    "service": "bot-hosting-cf-ws",
                    "provider": "bot-hosting",
                    "endpoints": 4,
                    "geo": {
                        "country": str(self.geo.get("country", "XX")).upper(),
                        "verified": bool(self.geo.get("verified")),
                        "egress_ip": str(self.geo.get("egress_ip", "")),
                    },
                }, separators=(",", ":")).encode()
                self._http_reply(conn, 200, body, "application/json")
                return

            if method == "GET" and path == "/.well-known/registry-proof":
                body = json.dumps({
                    "provider": "bot-hosting",
                    "proof_sha256": {
                        k: hashlib.sha256(str(v).encode()).hexdigest()
                        for k, v in self.proofs.items()
                    },
                }, separators=(",", ":")).encode()
                self._http_reply(conn, 200, body, "application/json")
                return

            self._http_reply(conn, 404, b"not found\n", "text/plain")
        except Exception:
            pass
        finally:
            with contextlib.suppress(OSError):
                conn.close()

    def _upgrade(self, conn: socket.socket, headers: dict[str, str], extra: bytes) -> None:
        key = headers["sec-websocket-key"]
        accept = base64.b64encode(
            hashlib.sha1((key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").encode()).digest()
        ).decode()
        conn.sendall((
            "HTTP/1.1 101 Switching Protocols\r\n"
            "Upgrade: websocket\r\n"
            "Connection: Upgrade\r\n"
            f"Sec-WebSocket-Accept: {accept}\r\n\r\n"
        ).encode("ascii"))
        conn.settimeout(None)
        self._ws_session(conn, bytearray(extra))

    def _ws_session(self, conn: socket.socket, buf: bytearray) -> None:
        remote: socket.socket | None = None
        established = False
        version = 0
        fragments: list[bytes] = []

        def send_remote_to_ws() -> None:
            assert remote is not None
            try:
                while not self._stop.is_set():
                    chunk = remote.recv(65536)
                    if not chunk:
                        break
                    conn.sendall(_ws_frame(chunk, 2))
            except OSError:
                pass
            finally:
                with contextlib.suppress(OSError):
                    conn.sendall(_ws_frame(b"", 8))

        def need(n: int) -> bool:
            while len(buf) < n:
                chunk = conn.recv(65536)
                if not chunk:
                    return False
                buf.extend(chunk)
            return True

        while not self._stop.is_set():
            if not need(2):
                break
            b0, b1 = buf[0], buf[1]
            fin, opcode, masked = bool(b0 & 0x80), b0 & 0x0F, bool(b1 & 0x80)
            length = b1 & 0x7F
            off = 2
            if length == 126:
                if not need(4):
                    break
                length = struct.unpack("!H", bytes(buf[2:4]))[0]
                off = 4
            elif length == 127:
                if not need(10):
                    break
                length = struct.unpack("!Q", bytes(buf[2:10]))[0]
                off = 10
            if length > 2 * 1024 * 1024:
                break
            mask_len = 4 if masked else 0
            if not need(off + mask_len + length):
                break
            mask = bytes(buf[off:off + 4]) if masked else b""
            off += mask_len
            payload = bytearray(buf[off:off + length])
            del buf[:off + length]
            if masked:
                for i in range(len(payload)):
                    payload[i] ^= mask[i & 3]
            data = bytes(payload)

            if opcode == 8:
                break
            if opcode == 9:
                conn.sendall(_ws_frame(data, 10))
                continue
            if opcode == 10:
                continue
            if opcode == 2:
                if fin:
                    message = data
                else:
                    fragments = [data]
                    continue
            elif opcode == 0 and fragments:
                fragments.append(data)
                if not fin:
                    continue
                message = b"".join(fragments)
                fragments = []
            else:
                continue

            if not established:
                version, host, port, payload = _parse_vless_request(
                    message,
                    self.identity["uuid"],
                )
                remote = socket.create_connection((host, port), timeout=10)
                remote.settimeout(None)
                established = True
                conn.sendall(_ws_frame(bytes([version, 0]), 2))
                if payload:
                    remote.sendall(payload)
                threading.Thread(target=send_remote_to_ws, daemon=True).start()
            elif remote is not None:
                remote.sendall(message)

        if remote is not None:
            with contextlib.suppress(OSError):
                remote.shutdown(socket.SHUT_RDWR)
            with contextlib.suppress(OSError):
                remote.close()


def ensure_cloudflared(state_dir: Path) -> Path:
    bin_dir = state_dir / "bin"
    bin_dir.mkdir(parents=True, exist_ok=True)
    path = bin_dir / "cloudflared"
    if path.is_file():
        try:
            os.chmod(path, 0o700)
            subprocess.run([str(path), "--version"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=5, check=True)
            return path
        except Exception:
            with contextlib.suppress(FileNotFoundError):
                path.unlink()

    tmp = path.with_name(path.name + ".tmp")
    req = urllib.request.Request(CLOUDFLARED_URL, headers={"User-Agent": "bot-hosting-cf/1.0"})
    with urllib.request.urlopen(req, timeout=45) as r, open(tmp, "wb") as f:
        total = 0
        while True:
            chunk = r.read(1024 * 1024)
            if not chunk:
                break
            total += len(chunk)
            if total > 100 * 1024 * 1024:
                raise RuntimeError("cloudflared download too large")
            f.write(chunk)
    if total < 5 * 1024 * 1024:
        raise RuntimeError(f"cloudflared download too small: {total}")
    os.chmod(tmp, 0o700)
    os.replace(tmp, path)
    return path


class QuickTunnel:
    def __init__(self, state_dir: Path, local_port: int) -> None:
        self.state_dir = state_dir
        self.local_port = int(local_port)
        self.process: subprocess.Popen[str] | None = None
        self.host = ""
        self._lines: queue.Queue[str] = queue.Queue()
        self._thread: threading.Thread | None = None

    def start(self, timeout: float = 35.0) -> str:
        binary = ensure_cloudflared(self.state_dir)
        self.process = subprocess.Popen(
            [
                str(binary), "tunnel", "--no-autoupdate",
                "--url", f"http://127.0.0.1:{self.local_port}",
            ],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
        )

        def reader() -> None:
            assert self.process is not None and self.process.stdout is not None
            for line in self.process.stdout:
                self._lines.put(line.rstrip())

        self._thread = threading.Thread(target=reader, daemon=True, name="cloudflared-log")
        self._thread.start()

        deadline = time.monotonic() + timeout
        pattern = re.compile(r"https://([a-z0-9-]+\.trycloudflare\.com)", re.I)
        last = ""
        while time.monotonic() < deadline:
            if self.process.poll() is not None:
                raise RuntimeError(f"cloudflared exited rc={self.process.returncode}: {last}")
            try:
                line = self._lines.get(timeout=0.5)
            except queue.Empty:
                continue
            last = line
            m = pattern.search(line)
            if m:
                self.host = m.group(1).lower()
                self._wait_public_ready(self.host, timeout=max(5.0, deadline - time.monotonic()))
                return self.host
        raise RuntimeError(f"cloudflared quick tunnel timeout: {last}")

    def _wait_public_ready(self, host: str, timeout: float = 25.0) -> None:
        deadline = time.monotonic() + timeout
        last_error: Exception | None = None
        while time.monotonic() < deadline:
            if self.process is not None and self.process.poll() is not None:
                raise RuntimeError(f"cloudflared exited rc={self.process.returncode} before public DNS ready")
            try:
                socket.getaddrinfo(host, 443, socket.AF_INET, socket.SOCK_STREAM)
                req = urllib.request.Request(
                    f"https://{host}/health",
                    headers={"User-Agent": "bot-hosting-cf-readiness/1.0"},
                )
                with urllib.request.urlopen(req, timeout=5) as response:
                    if int(response.status) == 200:
                        return
            except Exception as exc:
                last_error = exc
            time.sleep(0.5)
        raise RuntimeError(f"Cloudflare quick tunnel public endpoint not ready: {last_error}")

    def close(self) -> None:
        proc, self.process = self.process, None
        if proc is not None and proc.poll() is None:
            with contextlib.suppress(Exception):
                proc.terminate()
                proc.wait(timeout=4)
            if proc.poll() is None:
                with contextlib.suppress(Exception):
                    proc.kill()