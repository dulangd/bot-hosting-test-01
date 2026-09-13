from __future__ import annotations

import contextlib
import hashlib
import http.server
import ipaddress
import json
import os
import secrets
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
NODE_IDS = {
    "default": "bot-hosting-default-01",
    "ip": "bot-hosting-ip-01",
    "custom": "bot-hosting-custom-01",
}
BASE_NAMES = {
    "default": "BotHosting-Default-01",
    "ip": "BotHosting-IP-01",
    "custom": "BotHosting-Custom-01",
}


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
                    status = _heartbeat(ep, traffic) if token and registered else _register(ep, traffic, proofs)
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
