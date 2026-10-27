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
import struct
import sys
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

WS_NODE_ID = "bot-hosting-ws-01"
WS_BASE_NAME = "BotHosting-WS-01"
CF_WS_NODE_ID = "bot-hosting-cf-ws-01"
CF_WS_BASE_NAME = "BotHosting-CF-WS-01"
CF_WS_HOST_DEFAULT = "bth-ws-cf.k1.us.ci"
WS_IDENTITY_FILE = "ws-identity.json"


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


def _sync_routing_users(config: dict, clients: list[dict], owner_uuid: str) -> None:
    """Assign every inbound UUID exactly once in rust-reality routing policy.

    ``routing.users`` is a list of policy-group objects, not a flat UUID list.
    Each group has a ``userIds`` array. Endpoint expansion adds two clients to
    the existing inbound, so the UUIDs must be synchronized into the existing
    policy group without changing the established/default client identity or
    its routing policy.
    """
    inbound_ids: list[str] = []
    seen: set[str] = set()
    for client in clients:
        if not isinstance(client, dict):
            raise ValueError("rust-reality inbound contains a non-object client")
        client_id = str(client.get("id", "")).strip()
        if not client_id:
            raise ValueError("rust-reality inbound contains a client without id")
        if client_id in seen:
            raise ValueError(
                f"duplicate inbound client UUID cannot be routed exactly once: {client_id}"
            )
        seen.add(client_id)
        inbound_ids.append(client_id)

    routing = config.setdefault("routing", {})
    if not isinstance(routing, dict):
        raise ValueError("rust-reality routing must be an object")

    groups = routing.get("users")
    if groups is None:
        groups = []
    if not isinstance(groups, list):
        raise ValueError("rust-reality routing.users must be a list of policy groups")

    owner = None
    for group in groups:
        if not isinstance(group, dict):
            raise ValueError("rust-reality routing.users contains a non-object group")
        user_ids = group.get("userIds", [])
        if not isinstance(user_ids, list):
            raise ValueError("rust-reality routing.users[].userIds must be a list")
        if owner_uuid in {str(value).strip() for value in user_ids}:
            owner = group
            break

    if owner is None and groups:
        owner = groups[0]

    if owner is None:
        owner = {
            "name": "default-users",
            "userIds": [],
            "defaultOutbound": "direct",
            "rules": [],
        }
        groups.append(owner)

    inbound_set = set(inbound_ids)
    for group in groups:
        current = group.get("userIds", [])
        group["userIds"] = [
            str(value).strip()
            for value in current
            if str(value).strip() in inbound_set
        ]

    owner["userIds"] = list(inbound_ids)
    routing["users"] = [group for group in groups if group.get("userIds")]


def ensure_endpoint_clients(config: dict) -> dict[str, dict]:
    clients = config["inbounds"][0]["settings"]["clients"]
    if not clients:
        raise ValueError("rust-reality config contains no clients")
    by_email = {str(c.get("email", "")): c for c in clients if isinstance(c, dict)}
    used = {str(s).lower() for c in clients for s in c.get("shortIds", [])}
    default_id = NODE_IDS["default"]
    if default_id not in by_email:
        first = clients[0]
        old_email = str(first.get("email", "")).strip()
        if not old_email or old_email.startswith("bot-hosting-"):
            first["email"] = default_id
        by_email[default_id] = first
    flow = str(clients[0].get("flow", "xtls-rprx-vision"))
    for kind in ("ip", "custom"):
        label = NODE_IDS[kind]
        if label not in by_email:
            client = {
                "id": str(uuid.uuid4()), "shortIds": [_short_id(used)],
                "email": label, "flow": flow,
            }
            clients.append(client)
            by_email[label] = client

    default_uuid = str(by_email[default_id].get("id", "")).strip()
    if not default_uuid:
        raise ValueError("default Bot-Hosting client has no UUID")
    _sync_routing_users(config, clients, default_uuid)
    return {kind: by_email[NODE_IDS[kind]] for kind in ("default", "ip", "custom")}


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



def _normalize_ws_path(value: str) -> str:
    value = str(value or "").strip()
    if not value:
        value = "/ws-" + secrets.token_urlsafe(12)
    if not value.startswith("/"):
        value = "/" + value
    return value


def load_ws_identity(state_dir: Path) -> dict[str, str]:
    path = state_dir / WS_IDENTITY_FILE
    old = _read_json(path, {})
    if not isinstance(old, dict):
        old = {}

    candidate = (
        os.environ.get("BOT_HOSTING_WS_UUID", "").strip()
        or str(old.get("uuid", "")).strip()
    )
    try:
        parsed = uuid.UUID(candidate) if candidate else uuid.uuid4()
    except ValueError:
        parsed = uuid.uuid4()
    if parsed.version != 4:
        parsed = uuid.uuid4()

    identity = {
        "uuid": str(parsed),
        "ws_path": _normalize_ws_path(
            os.environ.get("BOT_HOSTING_WS_PATH", "")
            or str(old.get("ws_path", ""))
        ),
    }
    _atomic_json(path, identity)
    return identity


def build_ws_endpoint(
    state_dir: Path,
    host: str,
    port: int,
    country: str,
) -> tuple[dict[str, Any], dict[str, str]]:
    identity = load_ws_identity(state_dir)
    cc = country if len(country) == 2 else "XX"
    name = f"{cc}-{WS_BASE_NAME}"
    query = urllib.parse.urlencode({
        "encryption": "none",
        "security": "none",
        "type": "ws",
        "path": identity["ws_path"],
        "host": host,
    })
    endpoint = {
        "kind": "ws",
        "node_id": WS_NODE_ID,
        "name": name,
        "host": host,
        "port": int(port),
        "uri": (
            f"vless://{identity['uuid']}@{_authority(host)}:{int(port)}"
            f"?{query}#{urllib.parse.quote(name)}"
        ),
        "traffic_scope": "ws-fallback",
        "traffic_owner": False,
        "force_public_proof": True,
        "proof_endpoint": f"http://{_authority(host)}:{int(port)}",
    }
    return endpoint, identity


def build_cf_ws_endpoint(
    identity: dict[str, str],
    country: str,
    origin_host: str,
    origin_port: int,
    cf_host: str = CF_WS_HOST_DEFAULT,
) -> dict[str, Any]:
    """Build the Cloudflare CDN WSS endpoint; origin proof stays on Bot-Hosting."""
    host = str(cf_host).strip().lower().rstrip(".")
    if not host or "/" in host or ":" in host:
        raise ValueError("invalid Cloudflare WS hostname")
    cc = country if len(country) == 2 else "XX"
    name = f"{cc}-{CF_WS_BASE_NAME}"
    query = urllib.parse.urlencode({
        "encryption": "none",
        "security": "tls",
        "sni": host,
        "type": "ws",
        "path": identity["ws_path"],
        "host": host,
        "fp": "chrome",
    })
    return {
        "kind": "cfws",
        "node_id": CF_WS_NODE_ID,
        "name": name,
        "host": host,
        "port": 443,
        "uri": (
            f"vless://{identity['uuid']}@{_authority(host)}:443"
            f"?{query}#{urllib.parse.quote(name)}"
        ),
        "traffic_scope": "ws-fallback",
        "traffic_owner": False,
        "force_public_proof": True,
        "proof_endpoint": f"http://{_authority(origin_host)}:{int(origin_port)}",
    }


def _recv_exact(sock: socket.socket, count: int) -> bytes:
    data = bytearray()
    while len(data) < count:
        chunk = sock.recv(count - len(data))
        if not chunk:
            raise EOFError("unexpected EOF")
        data.extend(chunk)
    return bytes(data)


def _ws_frame(payload: bytes, opcode: int = 2, *, masked: bool = False) -> bytes:
    payload = bytes(payload)
    first = 0x80 | (opcode & 0x0F)
    mask_flag = 0x80 if masked else 0
    length = len(payload)
    if length < 126:
        header = bytes([first, mask_flag | length])
    elif length <= 0xFFFF:
        header = bytes([first, mask_flag | 126]) + struct.pack("!H", length)
    else:
        header = bytes([first, mask_flag | 127]) + struct.pack("!Q", length)
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
    parts: list[bytes] = []
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
            parts = [payload]
            started = True
        elif opcode == 0 and started:
            parts.append(payload)
        else:
            raise ValueError("unsupported websocket opcode")
        if fin:
            return b"".join(parts)


def _parse_vless_request(data: bytes, expected_uuid: str) -> tuple[int, str, int, bytes]:
    if len(data) < 24:
        raise ValueError("short VLESS request")
    index = 0
    version = data[index]
    index += 1
    supplied = data[index:index + 16]
    index += 16
    if supplied != uuid.UUID(expected_uuid).bytes:
        raise ValueError("VLESS authentication failed")
    opt_len = data[index]
    index += 1 + opt_len
    if index + 4 > len(data):
        raise ValueError("invalid VLESS request")
    command = data[index]
    if command != 1:
        label = {2: "udp", 3: "mux"}.get(command, "unknown")
        raise ValueError(
            f"unsupported VLESS command={command} ({label}); "
            "WS fallback supports TCP CONNECT only"
        )
    index += 1
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
    return version, host, port, data[index:]


def _is_public_ip(value: str) -> bool:
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
    if not 1 <= int(port) <= 65535:
        raise ValueError("target port outside 1..65535")
    last_error: Exception | None = None
    for family, socktype, proto, _canon, sockaddr in socket.getaddrinfo(
        host, int(port), type=socket.SOCK_STREAM
    ):
        if not _is_public_ip(str(sockaddr[0])):
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


def ws_public_selftest(
    public_port: int,
    public_host: str,
    identity: dict[str, str],
    timeout: float = 10.0,
) -> None:
    sock = socket.create_connection(("127.0.0.1", int(public_port)), timeout=timeout)
    sock.settimeout(timeout)
    try:
        key = base64.b64encode(secrets.token_bytes(16)).decode("ascii")
        request = (
            f"GET {identity['ws_path']} HTTP/1.1\r\n"
            f"Host: {public_host}\r\n"
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
        status = bytes(response).split(b"\r\n", 1)[0]
        if b" 101 " not in status:
            raise RuntimeError(
                "WS upgrade through public rust-reality fallback failed: "
                + status.decode("ascii", "replace")
            )

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
        sock.sendall(_ws_frame(payload, masked=True))
        received = bytearray()
        got_vless_header = False
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline and len(received) < 256 * 1024:
            opcode, _fin, frame = _read_ws_frame(sock)
            if opcode == 8:
                break
            if opcode == 9:
                sock.sendall(_ws_frame(frame, opcode=10, masked=True))
                continue
            if opcode != 2:
                continue
            if not got_vless_header:
                if len(frame) < 2 or frame[0] != 0:
                    raise RuntimeError("invalid VLESS WS response header")
                frame = frame[2:]
                got_vless_header = True
            received.extend(frame)
            if b"HTTP/" in received:
                return
        raise RuntimeError("WS VLESS self-test did not receive target HTTP response")
    finally:
        with contextlib.suppress(OSError):
            sock.close()


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


def registry_proofs(state_dir: Path, endpoints: list[dict]) -> dict[str, str]:
    return _proofs(state_dir / "registry-proofs.json", endpoints)


def _register(ep: dict, traffic: dict, proofs: dict[str, str]) -> int:
    base = (os.environ.get("REGISTRY_URL") or REGISTRY_URL_DEFAULT).rstrip("/")
    token = (
        ""
        if ep.get("force_public_proof")
        else os.environ.get("REGISTRY_TOKEN", "").strip()
    )
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
    endpoint = str(ep.get("proof_endpoint") or "").strip()
    if not endpoint:
        endpoint = os.environ.get("RR_REGISTRY_PROOF_ENDPOINT", "").strip()
    body["endpoint"] = endpoint or f"http://{_authority(ep['host'])}:{ep['port']}"
    body["metadata"] = {
        "egress_ip": str(os.environ.get("RR_GEO_IP", "")).strip(),
        "country": str(os.environ.get("RR_GEO_COUNTRY", "")).strip().upper(),
    }
    return _http_json(base + "/api/v1/register-public", "POST", body)[0]


def _heartbeat(ep: dict, traffic: dict) -> int:
    token = (
        ""
        if ep.get("force_public_proof")
        else os.environ.get("REGISTRY_TOKEN", "").strip()
    )
    if not token:
        return 0
    base = (os.environ.get("REGISTRY_URL") or REGISTRY_URL_DEFAULT).rstrip("/")
    body: dict[str, Any] = {"node_id": ep["node_id"], "status": "online"}
    if ep.get("traffic_owner"):
        body["traffic"] = _traffic(traffic)
    return _http_json(base + "/api/v1/heartbeat", "POST", body, token)[0]


SUBSCRIPTION_TOKEN_FILE = "subscription-token"
SUBSCRIPTION_PATH = "/sub64/"


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
    order = ["default", "ip", "custom"]
    if "ws" in by_kind:
        order.append("ws")
    if "cfws" in by_kind:
        order.append("cfws")
    lines = [by_kind[kind]["uri"] for kind in order]
    raw = "\n".join(lines) + "\n"
    return raw, base64.b64encode(raw.encode("utf-8")).decode("ascii")


def subscription_url(host: str, port: int, token: str) -> str:
    return f"http://{_authority(host)}:{port}{SUBSCRIPTION_PATH}{urllib.parse.quote(token, safe='')}"


class SubscriptionMux:
    """Internal cover dispatcher for rust-reality.

    rust-reality owns the public SERVER_PORT directly. Its configured REALITY
    cover target is this loopback dispatcher. Plain HTTP fallbacks are served
    locally (subscription/proof/health); TLS fallbacks are relayed byte-for-byte
    to the real cover host. No Python socket owns the public proxy port.
    """

    def __init__(
        self,
        public_port: int,
        backend_port: int,
        endpoints: list[dict[str, Any]],
        token: str,
        proofs: dict[str, str] | None = None,
        geo: dict[str, Any] | None = None,
        cover_host: str = "",
        cover_port: int = 443,
        ws_identity: dict[str, str] | None = None,
    ) -> None:
        self.public_port = int(public_port)
        self.backend_port = int(backend_port)
        self.endpoints = endpoints
        self.token = token
        self.proofs = proofs if isinstance(proofs, dict) else {}
        self.geo = geo if isinstance(geo, dict) else {}
        self.cover_host = str(cover_host).strip()
        self.cover_port = int(cover_port)
        self.ws_identity = ws_identity if isinstance(ws_identity, dict) else None
        if not self.cover_host:
            raise ValueError("cover_host is required")
        if not 1 <= self.cover_port <= 65535:
            raise ValueError("cover_port outside 1..65535")
        self.raw, self.encoded = subscription_content(endpoints)
        self._sock: socket.socket | None = None
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    def set_endpoints(self, endpoints: list[dict[str, Any]]) -> None:
        self.endpoints = list(endpoints)
        self.raw, self.encoded = subscription_content(self.endpoints)

    @property
    def url(self) -> str:
        host = (
            os.environ.get("RR_SUB_HOST", "").strip().strip("[]")
            or os.environ.get("RR_SERVER_ADDRESS", "").strip().strip("[]")
            or "fi3.bot-hosting.net"
        )
        return subscription_url(host, self.public_port, self.token)

    def start(self) -> None:
        if self._sock is not None:
            return
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
        sock.bind(("127.0.0.1", self.backend_port))
        sock.listen(128)
        self._sock = sock
        self._thread = threading.Thread(
            target=self._serve,
            name="bot-hosting-cover-dispatcher",
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
                name="bot-hosting-cover-conn",
                daemon=True,
            ).start()

    def _handle(self, conn: socket.socket) -> None:
        try:
            conn.settimeout(5.0)
            first = bytearray()
            while len(first) < 8:
                chunk = conn.recv(8 - len(first))
                if not chunk:
                    return
                first.extend(chunk)
                if first and first[0] not in b"GH":
                    break
                if len(first) >= 5 and (
                    bytes(first).startswith(b"GET ")
                    or bytes(first).startswith(b"HEAD ")
                ):
                    break

            initial = bytes(first)
            if self._is_http_prefix(initial):
                self._handle_http(conn, initial)
            else:
                self._handle_reality(conn, initial)
        except (EOFError, ConnectionResetError, BrokenPipeError):
            # Public health probes, latency tests and clients closing before a
            # complete fallback request are normal and should not look fatal.
            return
        except OSError as exc:
            if getattr(exc, "errno", None) in {32, 54, 104}:
                return
            print(f"[cover] network issue: {exc}", file=sys.stderr, flush=True)
        except (ValueError, UnicodeError) as exc:
            print(f"[cover] protocol rejected: {exc}", file=sys.stderr, flush=True)
        finally:
            with contextlib.suppress(OSError):
                conn.close()

    def _handle_http(self, conn: socket.socket, initial: bytes = b"") -> None:
        request = bytearray(initial)
        while b"\r\n\r\n" not in request and len(request) < 65536:
            chunk = conn.recv(4096)
            if not chunk:
                return
            request.extend(chunk)

        if b"\r\n\r\n" not in request:
            self._http_reply(conn, b"bad request\n", "text/plain; charset=utf-8", 400)
            return

        header_blob, pending = bytes(request).split(b"\r\n\r\n", 1)
        try:
            lines = header_blob.decode("iso-8859-1").split("\r\n")
            method, target, version = lines[0].split(" ", 2)
        except (UnicodeDecodeError, ValueError):
            self._http_reply(conn, b"bad request\n", "text/plain; charset=utf-8", 400)
            return

        if version not in ("HTTP/1.0", "HTTP/1.1") or method not in ("GET", "HEAD"):
            self._http_reply(conn, b"method not allowed\n", "text/plain; charset=utf-8", 405)
            return

        headers: dict[str, str] = {}
        for raw_line in lines[1:]:
            if ":" not in raw_line:
                continue
            key, value = raw_line.split(":", 1)
            headers[key.strip().lower()] = value.strip()

        path = urllib.parse.urlsplit(target).path
        ws_path = str((self.ws_identity or {}).get("ws_path", ""))
        if (
            method == "GET"
            and ws_path
            and path == ws_path
            and headers.get("upgrade", "").lower() == "websocket"
            and "upgrade" in headers.get("connection", "").lower()
            and headers.get("sec-websocket-key")
        ):
            self._handle_ws(conn, headers, pending)
            return

        if path == f"{SUBSCRIPTION_PATH}{self.token}":
            body = self.encoded.encode("ascii")
            self._http_reply(conn, body, "text/plain; charset=utf-8", 200, head=(method == "HEAD"))
            return

        if path == "/.well-known/registry-proof":
            body = json.dumps(
                {
                    "provider": "bot-hosting",
                    "proof_sha256": {
                        node_id: hashlib.sha256(str(proof).encode("utf-8")).hexdigest()
                        for node_id, proof in self.proofs.items()
                    },
                },
                separators=(",", ":"),
            ).encode()
            self._http_reply(conn, body, "application/json", 200, head=(method == "HEAD"))
            return

        if path == "/health":
            body = json.dumps(
                {
                    "ok": True,
                    "service": "bot-hosting-local-mux",
                    "provider": "bot-hosting",
                    "proxy_backend": self.backend_port,
                    "public_port": self.public_port,
                    "cover_host": self.cover_host,
                    "endpoints": len(self.endpoints),
                    "websocket": bool(self.ws_identity),
                    "geo": {
                        "country": str(self.geo.get("country", "XX")).upper(),
                        "verified": bool(self.geo.get("verified")),
                        "egress_ip": str(self.geo.get("egress_ip", "")),
                    },
                },
                separators=(",", ":"),
            ).encode()
            self._http_reply(conn, body, "application/json", 200, head=(method == "HEAD"))
            return

        self._http_reply(conn, b"not found\n", "text/plain; charset=utf-8", 404, head=(method == "HEAD"))

    def _handle_ws(
        self,
        conn: socket.socket,
        headers: dict[str, str],
        pending: bytes,
    ) -> None:
        identity = self.ws_identity
        if not identity:
            raise ValueError("WS identity is not configured")
        key = headers.get("sec-websocket-key", "")
        accept = base64.b64encode(
            hashlib.sha1(
                (key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").encode()
            ).digest()
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
        if pending:
            raise ValueError("unexpected websocket payload before upgrade completed")

        first = _read_ws_message(conn)
        if first is None:
            return
        version, host, port, payload = _parse_vless_request(
            first, identity["uuid"]
        )
        remote = _connect_public(host, port)
        write_lock = threading.Lock()
        finished = threading.Event()

        def send_binary(data: bytes) -> None:
            with write_lock:
                conn.sendall(_ws_frame(data))

        def relay_back() -> None:
            try:
                while not finished.is_set():
                    data = remote.recv(64 * 1024)
                    if not data:
                        return
                    send_binary(data)
            except OSError:
                return
            finally:
                finished.set()
                with contextlib.suppress(OSError):
                    conn.shutdown(socket.SHUT_RDWR)

        try:
            send_binary(bytes([version, 0]))
            if payload:
                remote.sendall(payload)
            threading.Thread(
                target=relay_back,
                name="bot-hosting-ws-upstream",
                daemon=True,
            ).start()
            while not finished.is_set():
                message = _read_ws_message(conn)
                if message is None:
                    break
                if message:
                    remote.sendall(message)
        finally:
            finished.set()
            with contextlib.suppress(OSError):
                remote.close()

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
            f"HTTP/1.1 {status} {reason}\r\n"
            f"Content-Type: {content_type}\r\n"
            "Cache-Control: no-store\r\n"
            "Connection: close\r\n"
            f"Content-Length: {len(body)}\r\n"
            "\r\n"
        ).encode("ascii")
        conn.sendall(headers)
        if not head:
            conn.sendall(body)

    def _handle_reality(self, client: socket.socket, initial: bytes = b"") -> None:
        deadline = time.monotonic() + 5.0
        backend = None
        last_error = None
        while backend is None and time.monotonic() < deadline:
            try:
                backend = socket.create_connection(
                    (self.cover_host, self.cover_port),
                    timeout=1.5,
                )
            except OSError as exc:
                last_error = exc
                time.sleep(0.05)
        if backend is None:
            raise OSError(
                f"cover target {self.cover_host}:{self.cover_port} unavailable: {last_error}"
            )

        backend.settimeout(None)
        client.settimeout(None)
        if initial:
            backend.sendall(initial)

        sockets = [client, backend]
        try:
            while not self._stop.is_set():
                readable, _writable, exceptional = select.select(
                    sockets, [], sockets, 60.0
                )
                if exceptional:
                    return
                if not readable:
                    continue
                for src in readable:
                    data = src.recv(64 * 1024)
                    if not data:
                        peer = backend if src is client else client
                        with contextlib.suppress(OSError):
                            peer.shutdown(socket.SHUT_WR)
                        return
                    dst = backend if src is client else client
                    dst.sendall(data)
        finally:
            with contextlib.suppress(OSError):
                backend.shutdown(socket.SHUT_RDWR)
            with contextlib.suppress(OSError):
                backend.close()


def _cover(port: int, proofs: dict[str, str]) -> None:
    hashes = {k: hashlib.sha256(v.encode()).hexdigest() for k, v in proofs.items()}
    class Handler(http.server.BaseHTTPRequestHandler):
        server_version, sys_version = "nginx", ""
        def log_message(self, *_args: Any) -> None:
            return
        def do_GET(self) -> None:  # noqa: N802
            path = urllib.parse.urlparse(self.path).path
            if path == "/health":
                body, ctype = json.dumps({"ok": True, "service": "bot-hosting"}).encode(), "application/json"
            elif path == "/.well-known/registry-proof":
                body, ctype = json.dumps({"proof_sha256": hashes}).encode(), "application/json"
            else:
                body = b"<!doctype html><title>Service</title><h1>Service online</h1><p>This service is operating normally.</p>"
                ctype = "text/html; charset=utf-8"
            self.send_response(200)
            self.send_header("Content-Type", ctype)
            self.send_header("Cache-Control", "no-store")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
    with contextlib.suppress(Exception):
        http.server.ThreadingHTTPServer(("0.0.0.0", port), Handler).serve_forever(1.0)


def agent_loop(core_pid: int, state_dir: Path, log_path: Path,
               endpoints: list[dict[str, Any]]) -> None:
    traffic_path, proof_path = state_dir / "traffic.json", state_dir / "registry-proofs.json"
    traffic = _read_json(traffic_path, _empty_traffic())
    if not isinstance(traffic, dict) or "tracking_since" not in traffic:
        traffic = _empty_traffic()
    proofs = _proofs(proof_path, endpoints)
    raw_port = os.environ.get("RR_COVER_PORT", "").strip()
    if raw_port:
        with contextlib.suppress(Exception):
            cover_port = int(raw_port)
            if 1 <= cover_port <= 65535 and cover_port != int(endpoints[0]["port"]):
                threading.Thread(target=_cover, args=(cover_port, proofs), daemon=True).start()

    heartbeat_s = max(60, int(os.environ.get("HEARTBEAT_SECONDS", HEARTBEAT_DEFAULT)))
    next_registry, next_save = time.monotonic() + 4, time.monotonic() + 15
    registered, last_error, offset = False, "", 0
    while os.getppid() == core_pid:
        offset = _consume_log(log_path, offset, traffic)
        now = time.monotonic()
        if now >= next_save:
            traffic["updated_at"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
            _atomic_json(traffic_path, _traffic(traffic))
            next_save = now + 15
        if now >= next_registry:
            token = os.environ.get("REGISTRY_TOKEN", "").strip()
            errors = []
            for ep in endpoints:
                try:
                    use_heartbeat = bool(
                        token and registered and not ep.get("force_public_proof")
                    )
                    status = (
                        _heartbeat(ep, traffic)
                        if use_heartbeat
                        else _register(ep, traffic, proofs)
                    )
                    if not 200 <= status < 300:
                        errors.append(f"{ep['node_id']} HTTP {status}")
                except Exception as exc:
                    errors.append(f"{ep['node_id']} {type(exc).__name__}")
            if not errors:
                if not registered:
                    print(f"[registry] {len(endpoints)}/{len(endpoints)} Bot-Hosting endpoints registered mode={'bearer' if token else 'public-proof'}", flush=True)
                registered, last_error = True, ""
            else:
                message = "; ".join(errors)
                if message != last_error:
                    print(f"[registry] registration/heartbeat issue: {message}", flush=True)
                    last_error = message
                registered = False
            next_registry = now + heartbeat_s
        time.sleep(0.5)
    with contextlib.suppress(Exception):
        _atomic_json(traffic_path, _traffic(traffic))


def start_agent(state_dir: Path, log_path: Path, endpoints: list[dict[str, Any]], *,
                close_fds: tuple[int, ...] = ()) -> int | None:
    if os.environ.get("RR_MANAGER_AGENT", "1") == "0" or not hasattr(os, "fork"):
        return None
    core_pid = os.getpid()
    pid = os.fork()
    if pid == 0:
        for fd in close_fds:
            with contextlib.suppress(OSError):
                os.close(fd)
        try:
            agent_loop(core_pid, state_dir, log_path, endpoints)
        finally:
            os._exit(0)
    return pid