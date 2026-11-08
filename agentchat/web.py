"""AgentChat GUI bridge — a loopback web server that serves the chat UI.

Security model:
  * Binds 127.0.0.1 only; requires a per-launch GUI session token sent as the
    X-AgentChat-Gui header, so other local browser pages cannot drive it.
  * Agent bearer tokens and Ed25519 private keys stay in this process; the
    browser only names an identity. Signing and signature verification happen
    here (or in the hub), never in the page.
"""
import argparse
import hashlib
import json
import os
import re
import secrets
import socket
import sys
import threading
import time
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse

from . import common as C

STATIC = os.path.join(os.path.dirname(os.path.abspath(__file__)), "static")
GUID_HEADER = "X-AgentChat-Gui"


def gui_meta_path() -> str:
    return os.path.join(C.home(), "gui.json")


def fingerprint(pem: str) -> str:
    body = "".join(l for l in pem.splitlines() if not l.startswith("-----"))
    try:
        return hashlib.sha256(__import__("base64").b64decode(body)).hexdigest()[:10]
    except Exception:
        return "?"


class Bridge:
    """Translates GUI API calls into hub calls as a chosen local identity."""

    def __init__(self, token: str, default_identity: str | None = None):
        self.token = token
        self.default_identity = default_identity
        # This process is started by the HUMAN (desktop app / `gui` command),
        # so it is allowed to hold the admin key. The browser never sees it.
        self.admin = C.load_admin_key(create=False)
        self.peers_cache = {"t": 0.0, "keys": {}, "roster": []}

    def creds(self):
        return C.read_json(C.credentials_path(), {})

    def cred_for(self, name):
        c = self.creds()
        rec = c.get(name)
        if not isinstance(rec, dict) or "token" not in rec:
            raise ValueError(f"unknown identity: {name}")
        return rec

    def peers(self, who):
        """Refresh the pubkey cache for signature verification (per identity)."""
        now = time.time()
        if now - self.peers_cache["t"] > 60:
            st, r = C.http_request("GET", "/v1/peers",
                                   token=self.cred_for(who)["token"], timeout=8)
            if st != 200:
                raise ValueError(r.get("error", "peers failed"))
            self.peers_cache = {
                "t": now,
                "keys": {p["name"]: p["pubkey"] for p in r["peers"]},
                "roster": [{"name": p["name"], "status": p["status"],
                            "online": p["online"], "last_seen_ms_ago": p["last_seen_ms_ago"],
                            "fingerprint": fingerprint(p["pubkey"])}
                           for p in r["peers"]],
            }
        return self.peers_cache

    # ---- API handlers; each raises ValueError(msg) for 400s

    def api_health(self):
        st, hub = C.http_request("GET", "/v1/health", timeout=5)
        names = [k for k in self.creds() if not k.startswith("__")]
        return {"hub_up": st == 200, "hub": hub if st == 200 else None,
                "identities": sorted(names), "signing": C.openssl_available(),
                "identity": self.default_identity, "admin": bool(self.admin)}

    def api_register(self, body):
        name = body.get("name", "")
        if not C.NAME_RE.match(name):
            raise ValueError("bad name")
        if name in self.creds():
            raise ValueError(f"identity '{name}' already exists on this device")
        hub_key = C.load_hub_key(create=True)
        priv, pub = C.gen_keypair()
        nonce = secrets.token_urlsafe(12)
        payload = C.sig_payload(f"register:{name}", None, None, 0, nonce, "enroll")
        st, r = C.http_request("POST", "/v1/register", body={
            "name": name, "hub_key": hub_key, "pubkey": pub,
            "nonce": nonce, "sig": C.sign(priv, payload)}, timeout=10)
        if st != 200:
            raise ValueError(f"hub refused ({st}): {r.get('error')}")
        creds = self.creds()
        creds[name] = {"token": r["token"], "priv_pem": priv, "pubkey_pem": pub}
        creds["__active__"] = name
        C.write_json(C.credentials_path(), creds)
        return {"registered": name}

    def api_rooms(self, who):
        return self.call(who, "GET", "/v1/rooms/list")

    def api_room(self, who, action, body):
        payload = {"name": body.get("name"), "room": body.get("room"),
                   "private": bool(body.get("private")), "invite": body.get("invite"),
                   "admin_key": self.admin}
        path = {"create": "/v1/rooms/create", "join": "/v1/rooms/join",
                "leave": "/v1/rooms/leave", "invite": "/v1/rooms/invite"}[action]
        return self.call(who, "POST", path, payload)

    def api_requests(self):
        st, r = C.http_request("POST", "/v1/rooms/requests",
                               body={"admin_key": self.admin}, timeout=10)
        if st != 200:
            raise ValueError(f"{r.get('error', 'hub error')} ({st})")
        return r

    def api_resolve(self, body):
        st, r = C.http_request("POST", "/v1/rooms/resolve", body={
            "admin_key": self.admin, "id": body.get("id"),
            "approve": bool(body.get("approve"))}, timeout=10)
        if st != 200:
            raise ValueError(f"{r.get('error', 'hub error')} ({st})")
        return r

    def api_peers(self, who, body):
        room = body.get("room")
        path = f"/v1/rooms/peers?room={room}" if room else "/v1/peers"
        r = self.call(who, "GET", path)
        for p in r["peers"]:
            p["fingerprint"] = fingerprint(p.pop("pubkey"))
        return r

    def api_history(self, who, body):
        room = body.get("room", "lobby")
        limit = max(1, min(int(body.get("limit", 80)), 200))
        r = self.call(who, "GET", f"/v1/rooms/history?room={room}&limit={limit}",
                      timeout=15)
        C.verify_with_keys(r["messages"], self.peers(who)["keys"])
        return r

    def api_send(self, who, body):
        text = str(body.get("text", "")).strip()
        if not text:
            raise ValueError("empty message")
        if len(text) > C.TEXT_MAX:
            raise ValueError("message too long")
        room = body.get("room") or None
        to = body.get("to") or None
        st, r = C.send_as(self.cred_for(who), who, None if to else room, to, text)
        if st != 200:
            raise ValueError(f"send refused ({st}): {r.get('error')}")
        C.verify_with_keys([r], self.peers(who)["keys"])
        return r

    def api_events(self, who, body):
        after = int(body.get("after", 0))
        wait = max(0.0, min(float(body.get("wait", 20)), 30.0))
        st, r = C.http_request("GET", f"/v1/events?after={after}&wait={wait}",
                               token=self.cred_for(who)["token"], timeout=wait + 12)
        if st != 200:
            raise ValueError(r.get("error", f"hub status {st}"))
        C.verify_with_keys(r["messages"], self.peers(who)["keys"])
        return r

    def api_status(self, who, body):
        return self.call(who, "POST", "/v1/status", {"status": str(body.get("status"))[:80]})

    def call(self, who, method, path, body=None, timeout=10):
        st, r = C.http_request(method, path, body=body,
                               token=self.cred_for(who)["token"], timeout=timeout)
        if st != 200:
            raise ValueError(f"{r.get('error', 'hub error')} ({st})")
        return r


class Handler(BaseHTTPRequestHandler):
    bridge: Bridge = None
    server_version = "agentchat-gui/1"

    def log_message(self, *a):
        pass

    def _send(self, code, data, ctype="application/json", extra=None):
        if data is None:
            data = b""
        if isinstance(data, (dict, list)):
            data = json.dumps(data).encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Content-Security-Policy",
                         "default-src 'none'; style-src 'unsafe-inline'; "
                         "script-src 'unsafe-inline'; connect-src 'self'; "
                         "img-src 'self' data:")
        self.send_header("X-Content-Type-Options", "nosniff")
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(data)

    def _gate(self):
        got = self.headers.get(GUID_HEADER, "")
        return secrets.compare_digest(got, self.bridge.token)

    def _jbody(self):
        n = int(self.headers.get("Content-Length") or 0)
        if n > 64 * 1024:
            raise ValueError("body too large")
        try:
            return json.loads(self.rfile.read(n) or b"{}")
        except json.JSONDecodeError:
            raise ValueError("invalid json")

    def do_GET(self):
        path = urlparse(self.path).path
        if path == "/":
            try:
                with open(os.path.join(STATIC, "index.html"), "rb") as f:
                    self._send(200, f.read(), "text/html; charset=utf-8")
            except FileNotFoundError:
                self._send(500, {"error": "index.html missing"})
        elif path == "/gui-meta":
            if not self._gate():
                self._send(403, {"error": "bad gui token"})
            else:
                self._send(200, self.bridge.api_health())
        else:
            self._send(404, {"error": "not found"})

    def do_POST(self):
        path = urlparse(self.path).path
        if not self._gate():
            return self._send(403, {"error": "missing or wrong gui token"})
        b = self.bridge
        try:
            body = self._jbody()
            if path == "/api/register":
                r = b.api_register(body)
            elif path == "/api/requests":
                r = b.api_requests()
            elif path == "/api/requests/resolve":
                r = b.api_resolve(body)
            else:
                who = body.get("identity") or ""
                if not C.NAME_RE.match(who):
                    raise ValueError("identity required")
                if path == "/api/rooms":
                    r = b.api_rooms(who)
                elif path == "/api/room":
                    r = b.api_room(who, body.get("action"), body)
                elif path == "/api/peers":
                    r = b.api_peers(who, body)
                elif path == "/api/history":
                    r = b.api_history(who, body)
                elif path == "/api/send":
                    r = b.api_send(who, body)
                elif path == "/api/events":
                    r = b.api_events(who, body)
                elif path == "/api/status":
                    r = b.api_status(who, body)
                else:
                    return self._send(404, {"error": "not found"})
            self._send(200, r)
        except ValueError as e:
            self._send(400, {"error": str(e)})
        except Exception as e:
            print(f"gui bridge error on {path}: {e!r}", file=sys.stderr, flush=True)
            self._send(500, {"error": "internal"})


def _pick_port(requested: int) -> int:
    if requested:
        return requested
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


def serve_gui(args) -> int:
    st, _ = C.http_request("GET", "/v1/health", timeout=1.5)
    if st != 200:
        st2, info = C.start_hub()
        if st2 != 200:
            print(json.dumps({"error": info.get("error", "hub failed")}))
            return 1

    port = _pick_port(args.port or 0)
    token = args.token or secrets.token_urlsafe(16)
    Handler.bridge = Bridge(token, getattr(args, "identity", None))
    httpd = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    httpd.daemon_threads = True

    url = f"http://127.0.0.1:{port}/#gui={token}"
    meta = {"url": url, "token": token, "port": port, "pid": os.getpid(),
            "identity": args.identity}
    C.write_json(gui_meta_path(), meta)

    print(json.dumps({"gui_url": url, "pid": os.getpid()}), flush=True)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    if not args.no_browser:
        try:
            webbrowser.open(url)
        except Exception:
            pass

    stop = threading.Event()
    import signal
    signal.signal(signal.SIGTERM, lambda *_: stop.set())
    signal.signal(signal.SIGINT, lambda *_: stop.set())
    try:
        stop.wait()
    finally:
        httpd.shutdown()
    return 0


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="Run the AgentChat GUI bridge")
    ap.add_argument("--port", type=int, default=0)
    ap.add_argument("--token", default=None)
    ap.add_argument("--identity", default=None)
    ap.add_argument("--no-browser", action="store_true")
    sys.exit(serve_gui(ap.parse_args()))
