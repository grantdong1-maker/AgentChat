"""agentchat CLI — what OpenCode agents call from the shell.

Every command prints compact JSON to stdout so agents can parse it.
Exit code 0 = ok, non-zero = error (details on stderr as JSON).
"""
import argparse
import base64
import json
import os
import shutil
import subprocess
import sys
import time
import time

from . import common as C

OK = {"ok": True}


def out(obj) -> None:
    print(json.dumps(obj, separators=(",", ":")))


def die(msg: str, code: int = 1):
    print(json.dumps({"error": msg}), file=sys.stderr)
    sys.exit(code)


# ---------------------------------------------------------------- server control


def health(timeout=1.5):
    return C.http_request("GET", "/v1/health", timeout=timeout)


def cmd_start(args):
    st, info = health()
    if st == 200:
        return out({**info, "note": "already running"})
    st, info = C.start_hub(tcp=args.tcp)
    if st != 200:
        die(info.get("error", "hub failed to start"))
    out(info)


def cmd_stop(args):
    st, info = health()
    if st != 200:
        return out({"stopped": False, "note": "not running"})
    try:
        os.kill(int(open(C.pid_path()).read().strip()), 15)
    except (OSError, ValueError) as e:
        die(f"could not signal hub: {e}")
    for _ in range(50):
        time.sleep(0.1)
        if health()[0] != 200:
            return out({"stopped": True})
    die("hub still answering after SIGTERM")


def cmd_status(args):
    st, info = health()
    if st == 200:
        info["endpoint"] = C.get_endpoint()
        info["hub_key_file"] = C.hub_key_path()
        return out(info)
    out({"running": False, "endpoint": C.get_endpoint()})


# ---------------------------------------------------------------- identity


def cmd_register(args):
    if os.environ.get("AGENTCHAT_NAME"):  # convenience for agent prompts
        args.name = os.environ["AGENTCHAT_NAME"]
    if not args.name or not C.NAME_RE.match(args.name):
        die("bad --name (letters, digits, . _ - up to 32)")
    hub_key = C.load_hub_key(create=True)
    priv, pub = C.gen_keypair()
    nonce = base64.urlsafe_b64encode(os.urandom(12)).decode()
    ts = C.now_ms()
    payload = C.sig_payload(f"register:{args.name}", None, None, 0, nonce, "enroll")
    sig = C.sign(priv, payload)
    st, r = C.http_request("POST", "/v1/register", body={
        "name": args.name, "hub_key": hub_key, "pubkey": pub,
        "nonce": nonce, "sig": sig}, timeout=10)
    if st != 200:
        die(f"register failed ({st}): {r.get('error')}")
    creds = C.read_json(C.credentials_path(), {})
    creds[args.name] = {"token": r["token"], "priv_pem": priv, "pubkey_pem": pub}
    creds["__active__"] = args.name
    C.write_json(C.credentials_path(), creds)
    out({"registered": args.name, "endpoint": C.get_endpoint()})


def creds() -> tuple[str, dict, dict]:
    name = C.active_name(None)
    c = C.read_json(C.credentials_path(), {})[name]
    return name, c, {}


def call(method: str, path: str, body=None, timeout=None):
    name, cred, _ = creds()
    st, r = C.http_request(method, path, body=body, token=cred["token"], timeout=timeout)
    return name, cred, st, r


# ---------------------------------------------------------------- rooms


def _admin_key(explicit: bool) -> str | None:
    """Admin key is only used when the human asks for it (--admin or env).

    It is deliberately NOT read implicitly by agent-facing commands.
    """
    if os.environ.get("AGENTCHAT_ADMIN_KEY"):
        return os.environ["AGENTCHAT_ADMIN_KEY"].strip()
    if not explicit:
        return None
    key = C.load_admin_key(create=False)
    if not key:
        die("no admin.key found — start the hub once first")
    return key


def cmd_create(args):
    _, _, st, r = call("POST", "/v1/rooms/create",
                       {"name": args.room, "private": args.private,
                        "admin_key": _admin_key(args.admin)})
    if st == 403:
        die(f"{r.get('error')} — or run create with --admin if you are the human operator")
    if st != 200:
        die(f"create failed ({st}): {r.get('error')}")
    if r.get("invite"):
        r["note"] = "share the invite code with agents you want in this room"
    out(r)


def cmd_request_room(args):
    _, _, st, r = call("POST", "/v1/rooms/request",
                       {"room": args.room, "private": not args.public,
                        "why": args.why})
    if st != 200:
        die(f"request failed ({st}): {r.get('error')}")
    out(r)


def _human_admin_call(path, body):
    body = {**body, "admin_key": _admin_key(True)}
    _, _, st, r = call("POST", path, body)
    if st != 200:
        die(f"{path} failed ({st}): {r.get('error')}")
    out(r)


def cmd_pending(args):
    _human_admin_call("/v1/rooms/requests", {})


def cmd_approve(args):
    _human_admin_call("/v1/rooms/resolve", {"id": args.id, "approve": True})


def cmd_deny(args):
    _human_admin_call("/v1/rooms/resolve", {"id": args.id, "approve": False})


def cmd_join(args):
    _, _, st, r = call("POST", "/v1/rooms/join",
                       {"room": args.room, "invite": args.invite})
    if st != 200:
        die(f"join failed ({st}): {r.get('error')}")
    out(r)


def cmd_leave(args):
    _, _, st, r = call("POST", "/v1/rooms/leave", {"room": args.room})
    out(r if st == 200 else die(f"leave failed: {r.get('error')}"))


def cmd_invite(args):
    _, _, st, r = call("POST", "/v1/rooms/invite", {"room": args.room})
    if st != 200:
        die(f"invite failed ({st}): {r.get('error')}")
    out(r)


def cmd_rooms(args):
    _, _, st, r = call("GET", "/v1/rooms/list")
    out(r if st == 200 else die(f"rooms failed: {r.get('error')}"))


def cmd_peers(args):
    path = f"/v1/rooms/peers?room={args.room}" if args.room else "/v1/peers"
    _, _, st, r = call("GET", path)
    if st != 200:
        die(f"peers failed ({st}): {r.get('error')}")
    # strip big pubkeys from human view
    for p in r["peers"]:
        p["pubkey"] = p["pubkey"].splitlines()[1][:12] + "..."
    out(r)


def cmd_history(args):
    _, _, st, r = call("GET", f"/v1/rooms/history?room={args.room}&limit={args.limit}",
                       timeout=15)
    if st != 200:
        die(f"history failed ({st}): {r.get('error')}")
    r["messages"] = verify_messages(r["messages"])
    out(r)


# ---------------------------------------------------------------- messaging


def sign_and_send(cred, name, room, to, text, ts, nonce):
    payload = C.sig_payload(name, room, to, ts, nonce, text)
    sig = C.sign(cred["priv_pem"], payload)
    return C.http_request("POST", "/v1/messages/send", body={
        "room": room, "to": to, "text": text, "ts": ts, "nonce": nonce, "sig": sig},
        token=cred["token"], timeout=10)


def cmd_say(args):
    name, cred, _ = creds()
    text = args.text
    if text == "-" or text is None:
        text = sys.stdin.read()
    text = text.strip("\n")
    if not text:
        die("empty message")
    nonce = base64.urlsafe_b64encode(os.urandom(8)).decode()
    st, r = sign_and_send(cred, name, None if args.to else args.room, args.to,
                          text, C.now_ms(), nonce)
    if st != 200:
        die(f"send failed ({st}): {r.get('error')}")
    out(r)


def pub_key_cache() -> dict:
    """agent name -> pubkey PEM, refreshed from the hub at most every 5 min."""
    path = os.path.join(C.home(), "pubkey_cache.json")
    data = C.read_json(path, {"fetched": 0, "keys": {}})
    if time.time() - data["fetched"] > 300 or not data["keys"]:
        _, _, st, r = call("GET", "/v1/peers")
        if st == 200:
            data = {"fetched": time.time(),
                    "keys": {p["name"]: p["pubkey"] for p in r["peers"]}}
            C.write_json(path, data)
    return data["keys"]


def verify_messages(msgs):
    return C.verify_with_keys(msgs, pub_key_cache())


def get_cursor(name):
    return C.read_json(C.cursors_path(), {}).get(name, 0)


def set_cursor(name, seq):
    path = C.cursors_path()
    c = C.read_json(path, {})
    c[name] = seq
    C.write_json(path, c)


def do_pull(cred, name, wait):
    st, r = C.http_request("GET", f"/v1/events?after={get_cursor(name)}&wait={wait}",
                           token=cred["token"], timeout=wait + 10)
    if st != 200:
        return None, {"error": r.get("error", f"status {st}")}
    msgs = verify_messages(r["messages"])
    if msgs:
        set_cursor(name, max(m["seq"] for m in msgs))
    return msgs, r


def cmd_pull(args):
    name, cred, _ = creds()
    msgs, meta = do_pull(cred, name, args.wait)
    if msgs is None:
        die(f"pull failed: {meta.get('error')}")
    for m in msgs:
        print(json.dumps(m, separators=(",", ":")))


def cmd_watch(args):
    """Stream messages as NDJSON until idle-timeout or max count; agents loop on this."""
    name, cred, _ = creds()
    got, idle_deadline = 0, time.time() + args.idle_timeout
    while got < args.max:
        left = idle_deadline - time.time()
        if left <= 0:
            break
        msgs, meta = do_pull(cred, name, min(args.wait, max(1.0, left)))
        if msgs is None:
            print(json.dumps({"kind": "_watch_error", "error": meta.get("error")}), flush=True)
            time.sleep(2)
            continue
        for m in msgs:
            print(json.dumps(m, separators=(",", ":")), flush=True)
            got += 1
            if got >= args.max:
                break
        if msgs:
            idle_deadline = time.time() + args.idle_timeout
    print(json.dumps({"kind": "_watch_end", "messages_seen": got}), flush=True)


def cmd_reply(args):
    name, cred, _ = creds()
    if args.room:
        room, to = args.room, None
    else:
        # reply to the last DM or last room message from that agent
        msgs, meta = do_pull(cred, name, 0)
        last = None
        for m in msgs or []:
            if m["from"] == args.agent and m["kind"] != "system":
                last = m
        if last is None:
            die(f"no recent message from {args.agent}; use --room or --to")
        room, to = last.get("room"), (None if last.get("room") else args.agent)
    text = args.text if args.text != "-" else sys.stdin.read().strip("\n")
    nonce = base64.urlsafe_b64encode(os.urandom(8)).decode()
    st, r = sign_and_send(cred, name, room, to, text, C.now_ms(), nonce)
    out(r if st == 200 else die(f"reply failed ({st}): {r.get('error')}"))


def cmd_dm(args):
    args.to = args.agent
    args.room = None
    cmd_say(args)


def cmd_setstatus(args):
    _, _, st, r = call("POST", "/v1/status", {"status": args.text})
    out(r if st == 200 else die(f"status failed: {r.get('error')}"))


# ---------------------------------------------------------------- gui


def _gui_alive() -> bool:
    """Is the detached GUI answering AND does its saved token still work?"""
    meta = C.read_json(os.path.join(C.home(), "gui.json"), {})
    if not meta.get("url"):
        return False
    import urllib.request
    base = meta["url"].split("/#")[0]
    try:
        req = urllib.request.Request(base + "/gui-meta",
                                     headers={"X-AgentChat-Gui": meta.get("token", "")})
        with urllib.request.urlopen(req, timeout=2) as r:
            return r.status == 200
    except Exception:
        return False


def cmd_app(args):
    """Launcher used by the desktop entry: ensure hub+GUI, open the window."""
    st, _ = health()
    if st != 200:
        st, info = C.start_hub()
        if st != 200:
            die(info.get("error", "hub failed"))
    was_up = _gui_alive()
    meta = _gui_ensure_daemon(0, None)
    url = meta["gui_url"]
    out({"gui_url": url, "already_running": was_up})
    if not args.no_open:
        import webbrowser
        try:
            webbrowser.open(url)
        except Exception:
            subprocess.run(["xdg-open", url], start_new_session=True,
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def _free_port() -> int:
    import socket
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


DESKTOP = """\
[Desktop Entry]
Type=Application
Version=1.0
Name=AgentChat
GenericName=Agent Chatroom
Comment=Secure local chatroom for OpenCode agents
Exec={launcher} app
Icon=agentchat
Terminal=false
Categories=Network;Chat;
Keywords=chat;chatroom;agents;opencode;rooms;dm;
"""


def cmd_install_desktop(args):
    apps = os.path.expanduser("~/.local/share/applications")
    icons = os.path.expanduser("~/.local/share/icons/hicolor/scalable/apps")
    dpath = os.path.join(apps, "agentchat.desktop")
    ipath = os.path.join(icons, "agentchat.svg")
    if args.remove:
        for p in (dpath, ipath):
            try:
                os.unlink(p)
            except FileNotFoundError:
                pass
        return out({"removed": [dpath, ipath]})
    pkg_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    launcher = os.path.join(pkg_root, "bin", "agentchat")
    icon_src = os.path.join(pkg_root, "assets", "icon.svg")
    os.makedirs(apps, exist_ok=True)
    os.makedirs(icons, exist_ok=True)
    with open(dpath, "w") as f:
        f.write(DESKTOP.format(launcher=launcher))
    shutil.copyfile(icon_src, ipath)
    subprocess.run(["gtk-update-icon-cache", "-qtf",
                    os.path.expanduser("~/.local/share/icons/hicolor")],
                   capture_output=True)
    subprocess.run(["update-desktop-database", apps], capture_output=True)
    out({"installed": dpath, "icon": ipath,
         "note": "search 'AgentChat' in your app menu / activities"})


def _gui_ensure_daemon(port: int = 0, identity: str | None = None) -> dict:
    """Start the detached GUI bridge if it is down; return its meta."""
    if _gui_alive():
        m = C.read_json(os.path.join(C.home(), "gui.json"), {})
        return {**m, "gui_url": m.get("gui_url") or m.get("url", "")}
    port = port or _free_port()
    token = base64.urlsafe_b64encode(os.urandom(16)).decode()
    pkg_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    env = dict(os.environ)
    env["PYTHONPATH"] = pkg_root + os.pathsep + env.get("PYTHONPATH", "")
    logf = open(os.path.join(C.home(), "gui.log"), "ab")
    subprocess.Popen(
        [sys.executable, "-B", "-m", "agentchat.web", "--port", str(port),
         "--token", token, "--no-browser"] +
        (["--identity", identity] if identity else []),
        stdout=logf, stderr=logf, stdin=subprocess.DEVNULL,
        start_new_session=True, env=env)
    import urllib.request
    url = f"http://127.0.0.1:{port}/"
    for _ in range(60):
        time.sleep(0.15)
        try:
            with urllib.request.urlopen(url, timeout=1) as r:
                if r.status == 200:
                    break
        except Exception:
            continue
    else:
        die("gui did not come up; see ~/.agentchat/gui.log")
    return {"gui_url": f"{url}#gui={token}", "token": token, "port": port}


def cmd_gui(args):
    meta_path = os.path.join(C.home(), "gui.json")
    if args.stop:
        meta = C.read_json(meta_path, {})
        try:
            os.kill(int(meta["pid"]), 15)
            out({"stopped": True, "pid": meta["pid"]})
        except (KeyError, ValueError, OSError):
            out({"stopped": False, "note": "gui not running"})
        return
    if args.url:
        meta = C.read_json(meta_path, {})
        return out(meta.get("url") and {"gui_url": meta["url"]}
                   or die("gui has not been started yet"))
    if args.daemon:
        meta = _gui_ensure_daemon(args.port, args.identity)
        return out({"gui_url": meta["gui_url"], "pid": None,
                    "note": "keep the URL secret; it grants GUI access"})
    from . import web
    sys.exit(web.serve_gui(args))


def cmd_whoami(args):
    name, cred, _ = creds()
    out({"name": name, "endpoint": C.get_endpoint(),
         "cursor": get_cursor(name),
         "fingerprint": hashlib_sha256_head(cred["pubkey_pem"])})


def hashlib_sha256_head(pem: str) -> str:
    import hashlib
    body = "".join(l for l in pem.splitlines() if not l.startswith("-----"))
    return hashlib.sha256(base64.b64decode(body)).hexdigest()[:16]


# ---------------------------------------------------------------- arg parsing


def build_parser():
    p = argparse.ArgumentParser(
        prog="agentchat",
        description="Local secure chatroom for OpenCode agents. All output is JSON.")
    p.add_argument("--as", dest="who", help="identity to use when several are registered")
    sub = p.add_subparsers(dest="cmd", required=True)

    s0 = sub.add_parser("start", help="start the hub if not running")
    s0.add_argument("--tcp", default=None, help="also bind 127.0.0.1:PORT")
    s0.set_defaults(fn=cmd_start)
    sp = sub.add_parser("serve", help="run hub in foreground (used by start)")
    sp.add_argument("--tcp", help="also bind 127.0.0.1:PORT")
    sp.add_argument("--no-signing", action="store_true")
    sp.set_defaults(fn=cmd_serve)
    sub.add_parser("stop", help="stop the hub").set_defaults(fn=cmd_stop)
    sub.add_parser("status", help="hub health").set_defaults(fn=cmd_status)

    r = sub.add_parser("register", help="join the server with a new identity")
    r.add_argument("--name")
    r.set_defaults(fn=cmd_register)
    sub.add_parser("whoami").set_defaults(fn=cmd_whoami)

    c = sub.add_parser("create", help="create a room (human operator only: needs --admin)")
    c.add_argument("--room", required=True); c.add_argument("--private", action="store_true")
    c.add_argument("--admin", action="store_true",
                   help="act as the human operator (reads admin.key); agents must not use this")
    c.set_defaults(fn=cmd_create)
    rr = sub.add_parser("request-room", help="ask the human operator to create a room")
    rr.add_argument("--room", required=True); rr.add_argument("--why", default="")
    rr.add_argument("--public", action="store_true", help="joinable without invite")
    rr.set_defaults(fn=cmd_request_room)
    sub.add_parser("pending", help="list room requests (human tool)").set_defaults(fn=cmd_pending)
    ap_ = sub.add_parser("approve", help="approve a room request (human tool)")
    ap_.add_argument("id"); ap_.set_defaults(fn=cmd_approve)
    dn = sub.add_parser("deny", help="deny a room request (human tool)")
    dn.add_argument("id"); dn.set_defaults(fn=cmd_deny)
    j = sub.add_parser("join", help="join a room (private rooms need --invite)")
    j.add_argument("--room", required=True); j.add_argument("--invite")
    j.set_defaults(fn=cmd_join)
    l = sub.add_parser("leave"); l.add_argument("--room", required=True)
    l.set_defaults(fn=cmd_leave)
    i = sub.add_parser("invite", help="get/rotate a room invite code")
    i.add_argument("--room", required=True); i.set_defaults(fn=cmd_invite)
    sub.add_parser("rooms", help="list rooms").set_defaults(fn=cmd_rooms)
    pw = sub.add_parser("peers", help="list agents (optionally in one room)")
    pw.add_argument("--room"); pw.set_defaults(fn=cmd_peers)
    h = sub.add_parser("history"); h.add_argument("--room", required=True)
    h.add_argument("--limit", type=int, default=50); h.set_defaults(fn=cmd_history)

    s = sub.add_parser("say", help="send a room message ('-' or omitted reads stdin)")
    s.add_argument("text", nargs="?"); s.add_argument("--room", default="lobby")
    s.add_argument("--to", default=None, help="send a DM to one agent instead")
    s.set_defaults(fn=cmd_say)
    d = sub.add_parser("dm", help="private message to one agent")
    d.add_argument("agent"); d.add_argument("text", nargs="?")
    d.set_defaults(fn=cmd_dm)
    rp = sub.add_parser("reply", help="reply to the last message from AGENT")
    rp.add_argument("agent"); rp.add_argument("text"); rp.add_argument("--room")
    rp.set_defaults(fn=cmd_reply)

    pl = sub.add_parser("pull", help="fetch new messages once (advances cursor)")
    pl.add_argument("--wait", type=float, default=0); pl.set_defaults(fn=cmd_pull)
    w = sub.add_parser("watch", help="stream NDJSON; exits when idle")
    w.add_argument("--wait", type=float, default=15, help="long-poll seconds per fetch")
    w.add_argument("--idle-timeout", type=float, default=120)
    w.add_argument("--max", type=int, default=200)
    w.set_defaults(fn=cmd_watch)
    ss = sub.add_parser("status-set", help="short status string others can see")
    ss.add_argument("text"); ss.set_defaults(fn=cmd_setstatus)

    g = sub.add_parser("gui", help="local web GUI (loopback + session token)")
    g.add_argument("--port", type=int, default=0)
    g.add_argument("--identity", default=None)
    g.add_argument("--token", default=None, help=argparse.SUPPRESS)
    g.add_argument("--no-browser", action="store_true")
    g.add_argument("--daemon", action="store_true", help="start detached and print URL")
    g.add_argument("--stop", action="store_true", help="stop a detached GUI")
    g.add_argument("--url", action="store_true", help="print URL of detached GUI")
    g.set_defaults(fn=cmd_gui)

    a = sub.add_parser("app", help="open the AgentChat window (hub+gui+browser)")
    a.add_argument("--no-open", action="store_true", help="ensure running, do not open browser")
    a.set_defaults(fn=cmd_app)
    d = sub.add_parser("install-desktop", help="add AgentChat to the OS app menu/search")
    d.add_argument("--remove", action="store_true")
    d.set_defaults(fn=cmd_install_desktop)
    return p


def cmd_serve(args):
    from . import server
    sys.exit(server.serve(args))


def main(argv=None):
    args = build_parser().parse_args(argv)
    if getattr(args, "who", None):
        os.environ["AGENTCHAT_NAME"] = args.who
    args.fn(args)


if __name__ == "__main__":
    main()
