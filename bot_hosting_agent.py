from __future__ import annotations

import base64
import contextlib
import hashlib
import http.server
import ipaddress
import json
import os
import secrets
import select
import socket
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from pathlib import Path
from typing import Any

REGISTRY_URL_DEFAULT = "https://subscription-server-v2-production.up.railway.app"
PROVIDER = "bot-hosting"
DEFAULT_CUSTOM_DOMAIN = "bth.richd.cc.cd"
HEARTBEAT_DEFAULT = 600
HTTP_TIMEOUT = 12
# Preserve the historical Registry identities already used in production.
# The direct-IP endpoint is additive; existing Default/Custom IDs are never renamed.
NODE_IDS = {
    "default": "bot-hosting-01",
    "ip": "bot-hosting-ip-01",
    "custom": "bot-hosting-domain-01",
}
BASE_NAMES = {
    "default": "BotHosting-Default-01",
    "ip": "BotHosting-IP-01",
    "custom": "BotHosting-Custom-01",
}
SUBSCRIPTION_TOKEN_FILE = "subscription-token"
SUBSCRIPTION_PATH = "/sub64/"


def _atomic_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    with open(tmp, "wb") as f:
        f.write((json.dumps(value, ensure_ascii=False, indent=2) + "\n").encode())
        f.flush()
        os.fsync(f.fileno())
    os.chmod(tmp, 0o600)
    os.replace(tmp, path)


def _read_json(path: Path, default: Any) -> Any:
    try:
        return json.loads(path.read_text("utf-8"))
    except Exception:
        return default


def _http_json(url: str, method: str = "GET", body: dict | None = None,
               token: str = "") -> tuple[int, Any]:
    raw_body = None
    headers = {"User-Agent": "bot-hosting-manager/2.0", "Accept": "application/json"}
    if body is not None:
        raw_body = json.dumps(body, separators=(",", ":")).encode()
        headers["Content-Type"] = "application/json"
    if token:
        headers["Authorization"] = f"Bearer {token}"
    req = urllib.request.Request(url, data=raw_body, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=HTTP_TIMEOUT) as r:
            status, raw = int(r.status), r.read(256 * 1024)
    except urllib.error.HTTPError as e:
        status, raw = int(e.code), e.read(256 * 1024)
    try:
        return status, json.loads(raw.decode()) if raw else None
    except Exception:
        return status, raw.decode("utf-8", "replace")[:1000]


def _text(url: str) -> str:
    req = urllib.request.Request(url, headers={"User-Agent": "bot-hosting-manager/2.0"})
    with urllib.request.urlopen(req, timeout=HTTP_TIMEOUT) as r:
        return r.read(128 * 1024).decode("utf-8", "replace")


def resolve_ipv4(host: str) -> list[str]:
    try:
        info = socket.getaddrinfo(host, None, socket.AF_INET, socket.SOCK_STREAM)
    except OSError:
        return []
    return sorted({item[4][0] for item in info})


def discover_hosts(default_host: str) -> dict[str, str]:
    hosts = {"default": default_host}
    default_ips = resolve_ipv4(default_host)
    direct = os.environ.get("RR_DIRECT_IP", "").strip()
    if direct:
        try:
            if ipaddress.ip_address(direct).version == 4:
                hosts["ip"] = direct
        except ValueError:
            pass
    elif default_ips:
        hosts["ip"] = default_ips[0]

    custom = (os.environ.get("RR_CUSTOM_DOMAIN") or DEFAULT_CUSTOM_DOMAIN).strip().strip("[]")
    if custom:
        custom_ips = resolve_ipv4(custom)
        verified = bool(custom_ips and default_ips and set(custom_ips) & set(default_ips))
        if verified or os.environ.get("RR_ALLOW_UNVERIFIED_CUSTOM_DOMAIN") == "1":
            hosts["custom"] = custom
    return hosts


def _cf_geo() -> tuple[str, str] | None:
    try:
        data = {}
        for line in _text("https://www.cloudflare.com/cdn-cgi/trace").splitlines():
            if "=" in line:
                k, v = line.split("=", 1)
                data[k] = v
        cc, ip = data.get("loc", "").upper(), data.get("ip", "")
        return (ip, cc) if ip and len(cc) == 2 else None
    except Exception:
        return None


def _ipinfo_geo() -> tuple[str, str] | None:
    try:
        status, data = _http_json("https://ipinfo.io/json")
        if status == 200 and isinstance(data, dict):
            cc, ip = str(data.get("country", "")).upper(), str(data.get("ip", ""))
            return (ip, cc) if ip and len(cc) == 2 else None
    except Exception:
        pass
    return None


def verified_country(state_dir: Path, max_age: int = 86400) -> dict[str, Any]:
    path = state_dir / "geo.json"
    cached = _read_json(path, {})
    now = int(time.time())
    try:
        if cached.get("verified") and now - int(cached.get("checked_unix", 0)) < max_age:
            return cached
    except Exception:
        pass
    cf, ipi = _cf_geo(), _ipinfo_geo()
    if cf and ipi and cf == ipi:
        value = {
            "country": cf[1], "egress_ip": cf[0], "verified": True,
            "mismatch": False, "checked_unix": now,
            "checked_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now)),
        }
        _atomic_json(path, value)
        return value
    if cached.get("verified"):
        cached["stale"] = True
        return cached
    pairs = [x for x in (cf, ipi) if x]
    value = {
        "country": "XX", "egress_ip": pairs[0][0] if pairs else "",
        "verified": False, "mismatch": bool(cf and ipi and cf != ipi),
        "checked_unix": now,
        "checked_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now)),
    }
    _atomic_json(path, value)
    return value


def _short_id(used: set[str]) -> str:
    while True:
        value = secrets.token_hex(8)
        if value.lower() not in used:
            used.add(value.lower())
            return value


def ensure_endpoint_clients(config: dict) -> dict[str, dict]:
    """Return the existing client identity for every ingress.

    Registry identity and VLESS client identity are deliberately separate.
    Bot-Hosting historically exposed the same working rust-reality client
    through both the provider hostname and the custom domain. Reusing that
    existing client preserves both working links while adding the direct-IP
    Registry record. Any extra clients left by an earlier v2 experiment are
    retained in the config, but are not required for the three ingress URIs.
    """
    clients = config["inbounds"][0]["settings"]["clients"]
    if not clients:
        raise ValueError("rust-reality config contains no clients")
    primary = clients[0]
    if not isinstance(primary, dict) or not primary.get("id"):
        raise ValueError("rust-reality primary client is invalid")
    short_ids = primary.get("shortIds", [])
    if not isinstance(short_ids, list) or not short_ids:
        raise ValueError("rust-reality primary client has no shortIds")
    return {kind: primary for kind in ("default", "ip", "custom")}


def _authority(host: str) -> str:
    try:
        ip = ipaddress.ip_address(host)
        return f"[{host}]" if ip.version == 6 else host
    except ValueError:
        return host


def _uri(client: dict, meta: dict, host: str, port: int, name: str) -> str:
    query = urllib.parse.urlencode({
        "encryption": "none", "flow": "xtls-rprx-vision", "security": "reality",
        "sni": meta["sni"], "fp": "chrome", "pbk": meta["publicKey"],
        "sid": client["shortIds"][0], "type": "tcp", "headerType": "none",
    })
    return f"vless://{client['id']}@{_authority(host)}:{port}?{query}#{urllib.parse.quote(name)}"


def build_endpoints(config: dict, meta: dict, default_host: str, port: int,
                    country: str) -> list[dict[str, Any]]:
    clients = ensure_endpoint_clients(config)
    hosts = discover_hosts(default_host)
    cc = country if len(country) == 2 else "XX"
    result = []
    for kind in ("default", "ip", "custom"):
        host = hosts.get(kind)
        if not host:
            continue
        name = f"{cc}-{BASE_NAMES[kind]}"
        result.append({
            "kind": kind, "node_id": NODE_IDS[kind], "name": name,
            "host": host, "port": port, "uri": _uri(clients[kind], meta, host, port, name),
            "traffic_scope": "shared-instance", "traffic_owner": kind == "default",
        })
    return result


def _empty_traffic() -> dict[str, Any]:
    now = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    return {"version": 1, "name": "rust-reality-shared-instance", "tracking_since": now,
            "updated_at": now, "upload_bytes": 0, "download_bytes": 0,
            "total_bytes": 0, "connections": 0}


def _traffic(state: dict) -> dict:
    up, down = int(state.get("upload_bytes", 0)), int(state.get("download_bytes", 0))
    return {"version": 1, "name": "rust-reality-shared-instance",
            "tracking_since": state["tracking_since"], "updated_at": state["updated_at"],
            "upload_bytes": up, "download_bytes": down, "total_bytes": up + down,
            "connections": int(state.get("connections", 0))}


def _consume_log(path: Path, offset: int, traffic: dict) -> int:
    try:
        if path.stat().st_size < offset:
            offset = 0
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            f.seek(offset)
            for raw in f:
                pos = raw.find("{")
                if pos < 0:
                    continue
                try:
                    event = json.loads(raw[pos:])
                except Exception:
                    continue
                if event.get("event") != "connection_completed":
                    continue
                up = int(event.get("uplink_bytes", 0) or 0)
                down = int(event.get("downlink_bytes", 0) or 0)
                if up >= 0 and down >= 0:
                    traffic["upload_bytes"] = int(traffic.get("upload_bytes", 0)) + up
                    traffic["download_bytes"] = int(traffic.get("download_bytes", 0)) + down
                    traffic["connections"] = int(traffic.get("connections", 0)) + 1
                    traffic["updated_at"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
            return f.tell()
    except FileNotFoundError:
        return 0 if offset else offset
    except OSError:
        return offset


def _proofs(path: Path, endpoints: list[dict]) -> dict[str, str]:
    values = _read_json(path, {})
    changed = False
    for ep in endpoints:
        if len(str(values.get(ep["node_id"], ""))) < 32:
            values[ep["node_id"]] = secrets.token_urlsafe(32)
            changed = True
    if changed:
        _atomic_json(path, values)
    return values


def _register(ep: dict, traffic: dict, proofs: dict[str, str]) -> int:
    base = (os.environ.get("REGISTRY_URL") or REGISTRY_URL_DEFAULT).rstrip("/")
    token = os.environ.get("REGISTRY_TOKEN", "").strip()
    body: dict[str, Any] = {
        "kind": "proxy", "node_id": ep["node_id"], "name": ep["name"],
        "provider": PROVIDER, "uri": ep["uri"], "priority": 80,
    }
    if ep.get("traffic_owner"):
        body["traffic"] = _traffic(traffic)
    if token:
        return _http_json(base + "/api/v1/register", "POST", body, token)[0]
    body.pop("kind", None)
    body["proof"] = proofs[ep["node_id"]]
    endpoint = os.environ.get("RR_REGISTRY_PROOF_ENDPOINT", "").strip()
    if endpoint:
        body["endpoint"] = endpoint
    return _http_json(base + "/api/v1/register-public", "POST", body)[0]


def _heartbeat(ep: dict, traffic: dict) -> int:
    token = os.environ.get("REGISTRY_TOKEN", "").strip()
    if not token:
        return 0
    base = (os.environ.get("REGISTRY_URL") or REGISTRY_URL_DEFAULT).rstrip("/")
    body: dict[str, Any] = {"node_id": ep["node_id"], "status": "online"}
    if ep.get("traffic_owner"):
        body["traffic"] = _traffic(traffic)
    return _http_json(base + "/api/v1/heartbeat", "POST", body, token)[0]


def subscription_token(state_dir: Path, stable_identity: str = "") -> str:
    path = state_dir / SUBSCRIPTION_TOKEN_FILE
    try:
        value = path.read_text("utf-8").strip()
        if len(value) >= 32 and all(ch.isalnum() or ch in "-_" for ch in value):
            return value
    except Exception:
        pass

    if stable_identity:
        digest = hashlib.sha256(
            ("bot-hosting-individual-subscription:" + stable_identity).encode("utf-8")
        ).digest()
        value = base64.urlsafe_b64encode(digest[:24]).decode("ascii").rstrip("=")
    else:
        value = secrets.token_urlsafe(32)

    path.write_text(value + "\n", "utf-8")
    os.chmod(path, 0o600)
    return value


def subscription_content(endpoints: list[dict[str, Any]]) -> tuple[str, str]:
    by_kind = {ep["kind"]: ep for ep in endpoints}
    missing = [kind for kind in ("default", "ip", "custom") if kind not in by_kind]
    if missing:
        raise ValueError(
            "subscription requires all 3 Bot-Hosting endpoints; missing "
            + ",".join(missing)
        )
    lines = [by_kind[kind]["uri"] for kind in ("default", "ip", "custom")]
    raw = "\n".join(lines) + "\n"
    return raw, base64.b64encode(raw.encode("utf-8")).decode("ascii")


def subscription_url(host: str, port: int, token: str) -> str:
    return f"http://{_authority(host)}:{port}{SUBSCRIPTION_PATH}{urllib.parse.quote(token, safe='')}"


class SubscriptionMux:
    """One public TCP port: HTTP subscription or raw REALITY passthrough.

    The free Bot-Hosting deployment exposes one published port. The mux owns
    that single public port, serves the stable subscription path for HTTP
    requests, and forwards every non-HTTP connection byte-for-byte to the
    loopback rust-reality listener.
    """

    def __init__(
        self,
        public_port: int,
        backend_port: int,
        endpoints: list[dict[str, Any]],
        token: str,
    ) -> None:
        self.public_port = int(public_port)
        self.backend_port = int(backend_port)
        self.endpoints = endpoints
        self.token = token
        self.raw, self.encoded = subscription_content(endpoints)
        self._sock: socket.socket | None = None
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    @property
    def url(self) -> str:
        host = os.environ.get("RR_SUB_HOST", "").strip().strip("[]")
        if not host:
            host = os.environ.get("RR_SERVER_ADDRESS", "").strip().strip("[]")
        if not host:
            host = "fi3.bot-hosting.net"
        return subscription_url(host, self.public_port, self.token)

    def start(self) -> None:
        if self._sock is not None:
            return
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
        sock.bind(("0.0.0.0", self.public_port))
        sock.listen(128)
        self._sock = sock
        self._thread = threading.Thread(
            target=self._serve,
            name="bot-hosting-subscription-mux",
            daemon=True,
        )
        self._thread.start()

    def close(self) -> None:
        self._stop.set()
        sock, self._sock = self._sock, None
        if sock is not None:
            with contextlib.suppress(OSError):
                sock.close()
        thread = self._thread
        self._thread = None
        if thread is not None and thread is not threading.current_thread():
            thread.join(timeout=2)

    @staticmethod
    def _is_http_prefix(data: bytes) -> bool:
        return data.startswith(b"GET ") or data.startswith(b"HEAD ")

    def _serve(self) -> None:
        sock = self._sock
        if sock is None:
            return
        while not self._stop.is_set():
            try:
                conn, _addr = sock.accept()
            except OSError:
                if self._stop.is_set():
                    return
                continue
            threading.Thread(
                target=self._handle,
                args=(conn,),
                name="bot-hosting-mux-conn",
                daemon=True,
            ).start()

    def _handle(self, conn: socket.socket) -> None:
        try:
            conn.settimeout(5.0)
            first = conn.recv(8, socket.MSG_PEEK)
            if self._is_http_prefix(first):
                self._handle_http(conn)
            else:
                self._handle_reality(conn)
        except (OSError, ValueError):
            pass
        finally:
            with contextlib.suppress(OSError):
                conn.close()

    def _handle_http(self, conn: socket.socket) -> None:
        request = bytearray()
        while b"\\r\\n\\r\\n" not in request and len(request) < 8192:
            chunk = conn.recv(2048)
            if not chunk:
                return
            request.extend(chunk)
        if b"\\r\\n\\r\\n" not in request:
            self._http_reply(conn, b"bad request\\n", "text/plain; charset=utf-8", 400)
            return

        try:
            line = bytes(request).split(b"\\r\\n", 1)[0].decode("ascii", "strict")
            method, target, version = line.split(" ", 2)
        except (UnicodeDecodeError, ValueError):
            self._http_reply(conn, b"bad request\\n", "text/plain; charset=utf-8", 400)
            return

        if version not in ("HTTP/1.0", "HTTP/1.1") or method not in ("GET", "HEAD"):
            self._http_reply(conn, b"method not allowed\\n", "text/plain; charset=utf-8", 405)
            return

        path = urllib.parse.urlsplit(target).path
        if path == f"{SUBSCRIPTION_PATH}{self.token}":
            body = self.encoded.encode("ascii")
            self._http_reply(conn, body, "text/plain; charset=utf-8", 200, head=(method == "HEAD"))
            return

        if path == "/health":
            body = json.dumps(
                {
                    "ok": True,
                    "service": "bot-hosting-local-mux",
                    "proxy_backend": self.backend_port,
                    "endpoints": len(self.endpoints),
                },
                separators=(",", ":"),
            ).encode()
            self._http_reply(conn, body, "application/json", 200, head=(method == "HEAD"))
            return

        self._http_reply(conn, b"not found\\n", "text/plain; charset=utf-8", 404, head=(method == "HEAD"))

    @staticmethod
    def _http_reply(
        conn: socket.socket,
        body: bytes,
        content_type: str,
        status: int,
        *,
        head: bool = False,
    ) -> None:
        reason = {
            200: "OK",
            400: "Bad Request",
            404: "Not Found",
            405: "Method Not Allowed",
        }.get(status, "Error")
        headers = (
            f"HTTP/1.1 {status} {reason}\\r\\n"
            f"Content-Type: {content_type}\\r\\n"
            "Cache-Control: no-store\\r\\n"
            "Connection: close\\r\\n"
            f"Content-Length: {len(body)}\\r\\n"
            "\\r\\n"
        ).encode("ascii")