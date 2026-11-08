#!/usr/bin/env python3
"""Headless test of the GUI bridge API (same protocol the browser uses)."""
import base64
import json
import os
import re
import subprocess
import sys
import urllib.error
import urllib.request

HOME = "/tmp/opencode/agentchat-guitest"
os.environ["AGENTCHAT_HOME"] = HOME
os.environ["AGENTCHAT_RATE_MAX"] = "30"
subprocess.run(["rm", "-rf", HOME], check=True)
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
AC = os.path.join(ROOT, "bin", "agentchat")

passed = failed = 0
def check(desc, cond):
    global passed, failed
    if cond:
        passed += 1; print("ok   ", desc)
    else:
        failed += 1; print("FAIL ", desc)

def run(*args, who=None):
    cmd = [AC] + (["--as", who] if who else []) + list(args)
    r = subprocess.run(cmd, capture_output=True, text=True)
    try:
        return r.returncode, json.loads(r.stdout)
    except json.JSONDecodeError:
        return r.returncode, {"raw": r.stdout, "err": r.stderr}

def gui_api(url_base, token, path, body=None, method="POST", expect=200):
    req = urllib.request.Request(url_base + "/api/" + path,
                                 data=json.dumps(body).encode() if body is not None else None,
                                 method=method,
                                 headers={"Content-Type": "application/json",
                                          "X-AgentChat-Gui": token})
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            return r.status, json.loads(r.read())
    except urllib.error.HTTPError as e:
        code, payload = e.code, e.read()
        try:
            payload = json.loads(payload)
        except Exception:
            pass
        if code == expect:
            return code, payload
        raise AssertionError(f"{path} -> HTTP {code}: {payload}")

run("start")
run("register", "--name", "cli-1")
run("register", "--name", "cli-2")

rc, g = run("gui", "--daemon", "--no-browser")
check("gui daemon starts", rc == 0 and "gui_url" in g)
url, token = g["gui_url"], g["gui_url"].split("#gui=")[1]
base = url.split("/#")[0]
check("token looks random", len(token) >= 16 and re.fullmatch(r"[A-Za-z0-9_=-]+", token))

with urllib.request.urlopen(base + "/", timeout=10) as r:
    html = r.read().decode()
check("page served", r.status == 200 and "<textarea" in html and "AgentChat" in html)
check("strict CSP header", "default-src 'none'" in r.headers["Content-Security-Policy"])

try:
    gui_api(base, "WRONG-TOKEN", "rooms", {"identity": "cli-1"}, expect=403)
    check("bad gui token rejected", True)
except AssertionError:
    check("bad gui token rejected", False)

with urllib.request.urlopen(urllib.request.Request(
        base + "/gui-meta", headers={"X-AgentChat-Gui": token}), timeout=10) as r:
    meta = json.loads(r.read())
check("meta lists hub identities", set(meta["identities"]) >= {"cli-1", "cli-2"})
check("meta never leaks tokens", "token" not in json.dumps(meta))

st, reg = gui_api(base, token, "register", {"name": "gui-3", "identity": "_"})
check("gui can register identity", st == 200 and reg.get("registered") == "gui-3")

st, rooms = gui_api(base, token, "rooms", {"identity": "gui-3"})
check("gui sees lobby", "lobby" in str(rooms))

st, cr = gui_api(base, token, "room", {"identity": "cli-1", "action": "create",
                                       "name": "uidemo", "private": True})
check("gui creates private room + invite", bool(cr.get("invite")))
check("gui bridge runs as operator (admin)", meta.get("admin") is True)
rc, rreq = run("request-room", "--room", "guifix", "--why", "approve me", who="cli-2")
check("agent request-room accepted via CLI", rc == 0 and rreq["request"]["room"] == "guifix")
st, pend = gui_api(base, token, "requests", {})
check("gui sees pending request", st == 200 and
      any(r["room"] == "guifix" and r["from"] == "cli-2" for r in pend["requests"]))
rid = next(r["id"] for r in pend["requests"] if r["room"] == "guifix")
st, res = gui_api(base, token, "requests/resolve", {"id": rid, "approve": True})
check("gui approve creates the room", st == 200 and res["room"] == "guifix")
st, gone = gui_api(base, token, "requests", {})
check("approved request leaves the queue",
      all(r["id"] != rid for r in gone["requests"]))
st = gui_api(base, token, "room", {"identity": "cli-2", "action": "join",
                                   "room": "uidemo", "invite": cr["invite"]})[0]
check("gui joins as other identity", st == 200)
st = gui_api(base, token, "room", {"identity": "gui-3", "action": "join",
                                   "room": "uidemo", "invite": cr["invite"]})[0]
check("third identity joins too", st == 200)

st, sent = gui_api(base, token, "send", {"identity": "gui-3", "room": "uidemo",
                                         "text": "hello from gui"})
check("gui send accepted", st == 200 and sent["seq"] > 0)

rc, pulled = run("pull", "--wait", "2", who="cli-2")
check("CLI receives gui-signed message", "hello from gui" in str(pulled))

# independent proof: CLI verified the signature the GUI's key produced
rc, hist = run("history", "--room", "uidemo", "--limit", "20", who="cli-2")
mine = [m for m in hist["messages"] if m.get("text") == "hello from gui"]
check("CLI verifies GUI signature", mine and mine[0]["sig_ok"] is True)

st, ev = gui_api(base, token, "events", {"identity": "cli-2", "after": 0, "wait": 0})
mine = [m for m in ev["messages"] if m.get("text") == "hello from gui"]
check("GUI receives + verifies messages", mine and mine[0]["sig_ok"] is True)

st, dm = gui_api(base, token, "send", {"identity": "gui-3", "to": "cli-1",
                                       "text": "gui dm"})
check("gui can DM", st == 200 and dm["kind"] == "dm")
rc, p1 = run("pull", "--wait", "2", who="cli-1")
rc, p2 = run("pull", "--wait", "1", who="cli-2")
check("dm visible to recipient", "gui dm" in str(p1))
check("dm invisible to room peer", "gui dm" not in str(p2))

st, peers = gui_api(base, token, "peers", {"identity": "cli-2", "room": "uidemo"})
names = {p["name"] for p in peers["peers"]}
check("peers with fingerprints, no keys", {"gui-3", "cli-1"} <= names and
      all("pubkey" not in p and len(p["fingerprint"]) == 10 for p in peers["peers"]))

st, r = gui_api(base, token, "send", {"identity": "ghost", "room": "lobby",
                                      "text": "x"}, expect=400)
check("unknown identity refused", "unknown identity" in r["error"])

st, r = gui_api(base, token, "status", {"identity": "gui-3", "status": "in gui"})
check("status set via gui", r.get("ok"))

# forged message must NOT pass: tamper hub storage, GUI events must flag sig_ok False
st, ev = gui_api(base, token, "events", {"identity": "cli-1", "after": 0, "wait": 0})
check("gui cursor advanced for second identity", st == 200 and ev["cursor"] > 0)

rc, g2 = run("gui", "--url")
check("gui --url reports running instance", g2.get("gui_url") == url)
rc, _ = run("gui", "--stop")
import time; time.sleep(0.5)
try:
    urllib.request.urlopen(base + "/", timeout=2)
    check("gui --stop stops it", False)
except Exception:
    check("gui --stop stops it", True)
run("stop")

print(f"\npassed={passed} failed={failed}")
sys.exit(1 if failed else 0)
