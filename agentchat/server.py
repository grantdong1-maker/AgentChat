"""AgentChat hub — a local, authenticated chatroom server.

Stdlib only. Listens on an AF_UNIX socket (0600, same-user access only) and,
if configured, 127.0.0.1. Agents authenticate with per-agent bearer tokens
(stored only as SHA-256 hashes) and every message is Ed25519-signed; the hub
verifies signatures against the sender's registered public key before relaying.
"""
import argparse
import base64
import hashlib
import hmac
import json
import os
import re
import signal
import socket
import sys
import threading
import time
from collections import deque
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

from . import common as C

STATE_FILE = "state.json"
MSGS_FILE = "messages.jsonl"
MAX_MSGS_MEM = 5000
RATE_WINDOW = 60.0
RATE_MAX = int(os.environ.get("AGENTCHAT_RATE_MAX", "60"))  # msgs per window per agent
MAX_BODY = 64 * 1024


def log(msg: str) -> None:
    ts = time.strftime("%Y-%m-%d %H:%M:%S")
    line = f"[{ts}] {msg}"
    print(line, file=sys.stderr, flush=True)
    try:
        with open(os.path.join(C.home(), "hub.log"), "a") as f:
            f.write(line + "\n")
    except OSError:
        pass


class Hub:
    def __init__(self, use_signing: bool):
        self.lock = threading.RLock()
        self.cond = threading.Condition(self.lock)
        self.use_signing = use_signing and C.openssl_available()
        self.hub_key = C.load_hub_key(create=True)
        self.admin_key = C.load_admin_key(create=True)
        self.admin_hash = hashlib.sha256(self.admin_key.encode()).hexdigest()
        self.agents: dict[str, dict] = {}
        self.rooms: dict[str, dict] = {}
        self.requests: list[dict] = []
        self.token_map: dict[str, str] = {}   # sha256(token) -> agent name
        self.msgs: deque = deque(maxlen=MAX_MSGS_MEM)
        self.seq = 0
        self.rate: dict[str, deque] = {}
        self.started = time.time()
        self._load()
        if "lobby" not in self.rooms:
            self._create_room("lobby", private=False, creator=None)

    # ------------------------------------------------------------ persistence

    def _paths(self):
        h = C.home()
        return os.path.join(h, STATE_FILE), os.path.join(h, MSGS_FILE)

    def _load(self):
        sp, mp = self._paths()
        self.state = C.read_json(sp, {})
        self.agents = self.state.get("agents", {})
        self.rooms = self.state.get("rooms", {})
        self.requests = self.state.get("requests", [])
        self.seq = self.state.get("seq", 0)
        self.token_map = {a["token_hash"]: n for n, a in self.agents.items()}
        if os.path.exists(mp):
            with open(mp) as f:
                for line in f:
                    try:
                        m = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    self.msgs.append(m)
            # keep seq ahead of persisted history
            if self.msgs:
                self.seq = max(self.seq, self.msgs[-1]["seq"])

    def _save_state(self):
        sp, _ = self._paths()
        self.state = {"agents": self.agents, "rooms": self.rooms,
                      "requests": self.requests, "seq": self.seq}
        C.write_json(sp, self.state)

    def _append_msg(self, m: dict):
        _, mp = self._paths()
        with self.cond:
            self.seq += 1
            m["seq"] = self.seq
            self.msgs.append(m)
            with open(mp, "a") as f:
                f.write(json.dumps(m, separators=(",", ":")) + "\n")
            self.cond.notify_all()
        return m

    # ------------------------------------------------------------ helpers

    def auth(self, token: str | None) -> str | None:
        if not token:
            return None
        h = hashlib.sha256(token.encode()).hexdigest()
        with self.lock:
            return self.token_map.get(h)

    def visible(self, m: dict, who: str) -> bool:
        if m["from"] == who:
            return True
        if m.get("to"):
            return m["to"] == who
        room = self.rooms.get(m.get("room") or "")
        if room and room.get("private"):
            return who in room["members"]
        # public room: members receive it; others can fetch via history
        return who in (room or {}).get("members", [])

    def check_rate(self, who: str) -> float | None:
        """Return retry-after seconds if over limit, else None."""
        now = time.time()
        with self.lock:
            q = self.rate.setdefault(who, deque())
            while q and now - q[0] > RATE_WINDOW:
                q.popleft()
            if len(q) >= RATE_MAX:
                return RATE_WINDOW - (now - q[0]) + 0.1
            q.append(now)
            return None

    def _create_room(self, name: str, private: bool, creator: str | None):
        invite = None
        room = {
            "private": private,
            "members": [creator] if creator else [],
            "created": C.now_ms(),
            "invite_hash": None,
        }
        if private:
            invite = base64.urlsafe_b64encode(os.urandom(12)).decode()
            room["invite_hash"] = hashlib.sha256(invite.encode()).hexdigest()
        self.rooms[name] = room
        self._save_state()
        return invite

    def system_notice(self, room: str, text: str):
        m = {"ts": C.now_ms(), "from": "*system", "room": room, "to": None,
             "text": text, "nonce": "-", "sig": None, "kind": "system"}
        return self._append_msg(m)

    # ------------------------------------------------------------ API ops

    def register(self, name, hub_key, pubkey, nonce, sig):
        if not C.NAME_RE.match(name or ""):
            return 400, {"error": "invalid name (A-Za-z0-9_.- up to 32)"}
        if not hmac.compare_digest(str(hub_key or ""), self.hub_key):
            log(f"register REJECTED bad hub key for {name!r}")
            return 403, {"error": "bad hub key"}
        if name in self.agents:
            return 409, {"error": f"name '{name}' already registered"}
        if not self.use_signing:
            return 503, {"error": "hub has signing disabled; openssl required"}
        payload = C.sig_payload(f"register:{name}", None, None, 0, str(nonce), "enroll")
        try:
            ok = C.verify(str(pubkey), payload, str(sig))
        except Exception:
            ok = False
        if not ok:
            return 400, {"error": "proof-of-key signature invalid"}
        token = base64.urlsafe_b64encode(os.urandom(32)).decode()
        rec = {"token_hash": hashlib.sha256(token.encode()).hexdigest(),
               "pubkey": pubkey, "created": C.now_ms(), "last_seen": C.now_ms(),
               "status": "", "rooms": ["lobby"]}
        with self.lock:
            self.agents[name] = rec
            self.token_map[rec["token_hash"]] = name
            self.rooms["lobby"]["members"].append(name)
            self._save_state()
        log(f"agent registered: {name}")
        self.system_notice("lobby", f"{name} joined")
        return 200, {"token": token, "name": name,
                     "note": "Store this token; it is not retrievable later."}

    def check_admin(self, provided) -> bool:
        return bool(provided) and hmac.compare_digest(
            hashlib.sha256(str(provided).encode()).hexdigest(), self.admin_hash)

    def system_dm(self, to: str, text: str):
        m = {"ts": C.now_ms(), "from": "*system", "room": None, "to": to,
             "text": text, "nonce": "-", "sig": None, "kind": "system"}
        return self._append_msg(m)

    def create_room(self, who, name, private, admin_key=None):
        """Room creation is reserved for the human operator (admin key holder)."""
        if not self.check_admin(admin_key):
            return 403, {"error": "only the human operator can create rooms; "
                                  "use 'agentchat request-room' and wait for approval"}
        if not C.ROOM_RE.match(name or ""):
            return 400, {"error": "invalid room name"}
        with self.lock:
            if name in self.rooms:
                return 409, {"error": "room exists"}
            invite = self._create_room(name, bool(private), who)
            self.agents[who]["rooms"].append(name)
            self._save_state()
        log(f"room created: {name} (private={private}) by {who} (admin-approved)")
        self.system_notice(name, f"{who} created this room")
        return 200, {"room": name, "private": bool(private), "invite": invite}

    # ---- human-in-the-loop room requests

    def request_room(self, who, name, private, why):
        if not C.ROOM_RE.match(name or ""):
            return 400, {"error": "invalid room name"}
        with self.lock:
            if name in self.rooms:
                return 409, {"error": f"room '{name}' already exists"}
            dup = next((r for r in self.requests if r["room"] == name
                        and r["from"] == who), None)
            if dup:
                return 200, {"request": dup, "note": "already pending"}
            if len(self.requests) >= 30:
                return 429, {"error": "too many pending requests"}
            req = {"id": os.urandom(6).hex(), "room": name, "from": who,
                   "private": bool(private), "why": str(why or "")[:200],
                   "ts": C.now_ms()}
            self.requests.append(req)
            self._save_state()
        log(f"room request pending: {who} -> {name}")
        return 200, {"request": req,
                     "note": "the human operator sees this in the AgentChat app; "
                             "no room exists until they approve"}

    def requests_pending(self, admin_key=None):
        if not self.check_admin(admin_key):
            return 403, {"error": "admin key required"}
        with self.lock:
            return 200, {"requests": list(self.requests)}

    def resolve_request(self, admin_key, rid, approve):
        """Only the human key can create a room; approval creates it for the requester."""
        if not self.check_admin(admin_key):
            return 403, {"error": "only the human operator can approve rooms"}
        with self.lock:
            req = next((r for r in self.requests if r["id"] == rid), None)
            if not req:
                return 404, {"error": "no such pending request"}
            self.requests.remove(req)
            who = req["from"]
            if not approve:
                self._save_state()
                self.system_dm(who, f"room request '{req['room']}' was declined")
                return 200, {"declined": req["room"]}
            if req["room"] in self.rooms:
                self._save_state()
                return 409, {"error": "room already exists"}
            invite = self._create_room(req["room"], req["private"], who)
            self.agents[who]["rooms"].append(req["room"])
            self._save_state()
        self.system_notice(req["room"], f"{who} was approved for this room")
        note = f" — invite: {invite}" if invite else ""
        self.system_dm(who, f"approved: room '{req['room']}' created for you" + note)
        log(f"room approved by human: {req['room']} for {who}")
        return 200, {"room": req["room"], "for": who, "private": req["private"],
                     "invite": invite}

    def join(self, who, room, invite):
        with self.lock:
            r = self.rooms.get(room)
            if not who in self.agents:
                return 404, {"error": "agent gone"}
            if r is None:
                return 404, {"error": f"no such room: {room}"}
            if who in r["members"]:
                return 200, {"room": room, "members": r["members"]}
            if r["private"]:
                got = hashlib.sha256(str(invite or "").encode()).hexdigest()
                if not hmac.compare_digest(got, r["invite_hash"] or "x"):
                    return 403, {"error": "invite required for private room"}
            r["members"].append(who)
            self.agents[who]["rooms"].append(room)
            self._save_state()
        log(f"{who} joined {room}")
        self.system_notice(room, f"{who} joined")
        return 200, {"room": room, "members": r["members"]}

    def leave(self, who, room):
        with self.lock:
            r = self.rooms.get(room)
            if not r:
                return 404, {"error": "no such room"}
            if who in r["members"]:
                r["members"].remove(who)
            self.agents[who]["rooms"] = [x for x in self.agents[who]["rooms"] if x != room]
            self._save_state()
        self.system_notice(room, f"{who} left")
        return 200, {"left": room}

    def invite(self, who, room):
        with self.lock:
            r = self.rooms.get(room)
            if not r:
                return 404, {"error": "no such room"}
            if who not in r["members"]:
                return 403, {"error": "only members can invite"}
            if not r["private"]:
                return 200, {"room": room, "invite": None, "note": "public room"}
            inv = base64.urlsafe_b64encode(os.urandom(12)).decode()
            r["invite_hash"] = hashlib.sha256(inv.encode()).hexdigest()
            self._save_state()
            return 200, {"room": room, "invite": inv}

    def send(self, who, room, to, text, ts, nonce, sig):
        if not isinstance(text, str) or not text.strip():
            return 400, {"error": "empty text"}
        if len(text) > C.TEXT_MAX:
            return 400, {"error": f"text too long (>{C.TEXT_MAX})"}
        text = text.replace("\u241f", "?")  # keep payload separator unambiguous
        rec = self.agents.get(who)
        if not rec:
            return 404, {"error": "agent gone"}
        if to:
            if to not in self.agents:
                return 404, {"error": f"no such agent: {to}"}
            room = None
        elif room:
            if room not in self.rooms:
                return 404, {"error": f"no such room: {room}"}
            if who not in self.rooms[room]["members"]:
                return 403, {"error": f"not a member of {room}"}
        else:
            return 400, {"error": "need room or --to"}
        if self.use_signing:
            payload = C.sig_payload(who, room, to, int(ts), str(nonce), text)
            try:
                if not C.verify(rec["pubkey"], payload, str(sig)):
                    return 400, {"error": "bad message signature"}
            except Exception:
                return 500, {"error": "signing backend failed"}
        retry = self.check_rate(who)
        if retry:
            return 429, {"error": "rate limited", "retry_after": round(retry, 1)}
        m = {"ts": int(ts), "from": who, "room": room, "to": to, "text": text,
             "nonce": str(nonce), "sig": sig if self.use_signing else None,
             "kind": "dm" if to else "chat"}
        m = self._append_msg(m)
        with self.lock:
            self.agents[who]["last_seen"] = C.now_ms()
        return 200, m

    def events(self, who, after, wait):
        deadline = time.time() + min(max(wait, 0), 45)
        with self.cond:
            while True:
                batch = [m for m in self.msgs if m["seq"] > after and self.visible(m, who)]
                if batch or time.time() >= deadline:
                    self.agents[who]["last_seen"] = C.now_ms()
                    out = {"messages": batch[-100:], "cursor": self.seq}
                    return 200, out
                self.cond.wait(min(1.0, max(0.05, deadline - time.time())))

    def history(self, who, room, limit):
        with self.lock:
            r = self.rooms.get(room)
            if not r:
                return 404, {"error": "no such room"}
            if r["private"] and who not in r["members"]:
                return 403, {"error": "private room"}
        limit = max(1, min(int(limit or 50), 500))
        items = [m for m in self.msgs if m.get("room") == room]
        return 200, {"messages": items[-limit:], "total": len(items)}

    def peers(self, who, room=None):
        with self.lock:
            if room:
                r = self.rooms.get(room)
                if not r:
                    return 404, {"error": "no such room"}
                names = r["members"]
            else:
                names = list(self.agents)
            now = C.now_ms()
            out = []
            for n in names:
                a = self.agents.get(n)
                if not a:
                    continue
                out.append({"name": n, "status": a.get("status", ""),
                            "online": now - a["last_seen"] < 60_000,
                            "last_seen_ms_ago": (now - a["last_seen"]) // 1000,
                            "pubkey": a["pubkey"]})
            return 200, {"peers": out}

    def set_status(self, who, status):
        with self.lock:
            self.agents[who]["status"] = str(status)[:80]
            self.agents[who]["last_seen"] = C.now_ms()
            self._save_state()
        return 200, {"ok": True}

    def room_list(self, who):
        with self.lock:
            out = []
            for name, r in self.rooms.items():
                member = who in r["members"]
                if r["private"] and not member:
                    continue
                out.append({"room": name, "private": r["private"], "member": member,
                            "members": len(r["members"]) if not r["private"] or member else 0})
            return 200, {"rooms": out}


# ---------------------------------------------------------------- HTTP glue


class Handler(BaseHTTPRequestHandler):
    hub: Hub = None  # set by serve()
    server_version = "agentchat/1"

    def log_message(self, fmt, *args):  # quiet by default; audit via hub.log
        pass

    def _json(self, status, obj):
        body = json.dumps(obj).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _body(self):
        n = int(self.headers.get("Content-Length") or 0)
        if n > MAX_BODY:
            return None
        try:
            return json.loads(self.rfile.read(n) or b"{}")
        except (json.JSONDecodeError, ValueError):
            return None

    def _who(self):
        return self.hub.auth(self.headers.get("Authorization", "").removeprefix("Bearer ").strip() or None)

    def _route(self, method):
        u = urlparse(self.path)
        q = parse_qs(u.query)
        seg = [s for s in u.path.split("/") if s]
        who = self._who()
        body = self._body() if method == "POST" else {}
        if body is None:
            return 413, {"error": "body too large"}

        if seg == ["v1", "health"] and method == "GET":
            return 200, {"ok": True, "uptime": round(time.time() - self.hub.started),
                         "agents": len(self.hub.agents), "rooms": len(self.hub.rooms),
                         "signing": self.hub.use_signing, "seq": self.hub.seq}
        if seg == ["v1", "register"] and method == "POST":
            return self.hub.register(body.get("name"), body.get("hub_key"),
                                     body.get("pubkey"), body.get("nonce"),
                                     body.get("sig"))
        if seg == ["v1", "rooms", "requests"] and method == "POST":
            return self.hub.requests_pending(body.get("admin_key"))
        if seg == ["v1", "rooms", "resolve"] and method == "POST":
            return self.hub.resolve_request(body.get("admin_key"), body.get("id"),
                                            bool(body.get("approve")))
        if who is None:
            return 401, {"error": "missing/invalid bearer token"}

        if seg == ["v1", "rooms", "list"] and method == "GET":
            return self.hub.room_list(who)
        if seg == ["v1", "rooms", "create"] and method == "POST":
            return self.hub.create_room(who, body.get("name"),
                                        body.get("private"), body.get("admin_key"))
        if seg == ["v1", "rooms", "request"] and method == "POST":
            return self.hub.request_room(who, body.get("room"),
                                         body.get("private"), body.get("why"))
        if seg == ["v1", "rooms", "join"] and method == "POST":
            return self.hub.join(who, body.get("room"), body.get("invite"))
        if seg == ["v1", "rooms", "leave"] and method == "POST":
            return self.hub.leave(who, body.get("room"))
        if seg == ["v1", "rooms", "invite"] and method == "POST":
            return self.hub.invite(who, body.get("room"))
        if seg == ["v1", "rooms", "history"] and method == "GET":
            return self.hub.history(who, q.get("room", [None])[0], q.get("limit", [50])[0])
        if seg == ["v1", "rooms", "peers"] and method == "GET":
            return self.hub.peers(who, q.get("room", [None])[0])
        if seg == ["v1", "messages", "send"] and method == "POST":
            return self.hub.send(who, body.get("room"), body.get("to"), body.get("text"),
                                 body.get("ts") or C.now_ms(), body.get("nonce") or "-",
                                 body.get("sig"))
        if seg == ["v1", "events"] and method == "GET":
            return self.hub.events(who, int(q.get("after", ["0"])[0]),
                                   float(q.get("wait", ["0"])[0]))
        if seg == ["v1", "status"] and method == "POST":
            return self.hub.set_status(who, body.get("status"))
        if seg == ["v1", "peers"] and method == "GET":
            return self.hub.peers(who)
        return 404, {"error": "no such endpoint"}

    def do_GET(self):
        try:
            self._json(*self._route("GET"))
        except Exception as e:  # keep server alive; log the rest
            log(f"GET {self.path} crashed: {e!r}")
            self._json(500, {"error": "internal"})

    def do_POST(self):
        try:
            self._json(*self._route("POST"))
        except Exception as e:
            log(f"POST {self.path} crashed: {e!r}")
            self._json(500, {"error": "internal"})


class UnixServer(ThreadingHTTPServer):
    address_family = socket.AF_UNIX
    daemon_threads = True

    def __init__(self, path, handler):
        if os.path.exists(path):
            # refuse if a live hub answers on this exact socket, else it is stale
            probe = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            probe.settimeout(1.0)
            try:
                probe.connect(path)
            except OSError:
                probe.close()
                os.unlink(path)
                return
            probe.close()
            raise SystemExit(f"hub already running at {path}")
        super().__init__(path, handler)
        os.chmod(path, 0o600)


def serve(args) -> int:
    hub = Hub(use_signing=not args.no_signing)
    Handler.hub = hub
    if not hub.use_signing:
        log("WARNING: message signing disabled (need openssl); hub is auth-only")

    sock = C.socket_path()
    srv = UnixServer(sock, Handler)
    threads = [srv]
    if args.tcp:
        m = re.match(r"^([\d.]+):(\d+)$", args.tcp)
        if not m:
            print("--tcp must be 127.0.0.1:PORT", file=sys.stderr)
            return 2
        class TCPServer(ThreadingHTTPServer):
            daemon_threads = True
            def handle_error(self, req, client):  # don't spam tracebacks
                pass
        tcp = TCPServer((m.group(1), int(m.group(2))), Handler)
        if m.group(1) != "127.0.0.1":
            log(f"WARNING: bound to {m.group(1)} — reachable beyond loopback!")
        threads.append(tcp)

    for t in threads:
        threading.Thread(target=t.serve_forever, daemon=True).start()

    with open(C.endpoint_path(), "w") as f:
        f.write(f"unix://{sock}\n")
    with open(C.pid_path(), "w") as f:
        f.write(str(os.getpid()))
    log(f"hub listening on unix://{sock} (0600)" + (f" and tcp {args.tcp}" if args.tcp else ""))
    log(f"hub key: {C.hub_key_path()}  (agents must be able to read it to register)")

    stop = threading.Event()
    signal.signal(signal.SIGTERM, lambda *_: stop.set())
    signal.signal(signal.SIGINT, lambda *_: stop.set())
    try:
        stop.wait()
    finally:
        for t in threads:
            t.shutdown()
        try:
            os.unlink(sock)
        except OSError:
            pass
        log("hub stopped")
    return 0


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="Run the AgentChat hub")
    ap.add_argument("--tcp", help="also bind 127.0.0.1:PORT")
    ap.add_argument("--no-signing", action="store_true")
    sys.exit(serve(ap.parse_args()))
