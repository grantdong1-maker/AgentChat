"""Shared helpers for the agentchat package (stdlib only)."""
import base64
import hashlib
import http.client
import json
import os
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import time

NAME_RE = re.compile(r"^[A-Za-z0-9_.-]{1,32}$")
ROOM_RE = NAME_RE
TEXT_MAX = 4000

# ---------------------------------------------------------------- paths / config


def home() -> str:
    h = os.environ.get("AGENTCHAT_HOME") or os.path.expanduser("~/.agentchat")
    os.makedirs(h, mode=0o700, exist_ok=True)
    return h


def hub_key_path() -> str:
    return os.path.join(home(), "hub.key")


def admin_key_path() -> str:
    return os.path.join(home(), "admin.key")


def load_admin_key(create: bool) -> str | None:
    """Secret that identifies the HUMAN operator (room creation/approval).

    Only the GUI bridge (started by a human clicking the desktop app) and CLI
    commands run with an explicit --admin flag ever read this file.
    """
    p = admin_key_path()
    if os.path.exists(p):
        with open(p) as f:
            return f.read().strip()
    if not create:
        return None
    key = base64.urlsafe_b64encode(os.urandom(32)).decode()
    fd = os.open(p, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(key + "\n")
    return key


def endpoint_path() -> str:
    return os.path.join(home(), "endpoint")


def credentials_path() -> str:
    return os.path.join(home(), "credentials.json")


def cursors_path() -> str:
    return os.path.join(home(), "cursors.json")


def socket_path() -> str:
    return os.environ.get("AGENTCHAT_SOCKET") or os.path.join(home(), "chat.sock")


def pid_path() -> str:
    return os.path.join(home(), "chat.pid")


def load_hub_key(create: bool) -> str | None:
    p = hub_key_path()
    if os.path.exists(p):
        with open(p) as f:
            return f.read().strip()
    if not create:
        return None
    key = base64.urlsafe_b64encode(os.urandom(32)).decode()
    fd = os.open(p, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(key + "\n")
    return key


def read_json(path: str, default):
    try:
        with open(path) as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return default


def write_json(path: str, data, mode: int = 0o600) -> None:
    tmp = path + ".tmp"
    with open(tmp, "w") as f:
        json.dump(data, f, indent=1)
    os.chmod(tmp, mode)
    os.replace(tmp, path)


def get_endpoint() -> str:
    """Where the hub lives: 'unix:///path' or 'http://127.0.0.1:port'."""
    env = os.environ.get("AGENTCHAT_URL")
    if env:
        return env
    p = endpoint_path()
    if os.path.exists(p):
        with open(p) as f:
            return f.read().strip()
    return "unix://" + socket_path()


# ---------------------------------------------------------------- HTTP transport


class UnixHTTPConnection(http.client.HTTPConnection):
    """http.client over an AF_UNIX socket."""

    def __init__(self, path: str, timeout: float = None):
        super().__init__("agentchat.local", timeout=timeout)
        self._unix_path = path

    def connect(self):
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.settimeout(self.timeout)
        s.connect(self._unix_path)
        self.sock = s


def http_request(method: str, path: str, body=None, token: str | None = None,
                 timeout: float | None = None) -> tuple[int, dict]:
    """Call the hub. Returns (status, parsed-json-or-error-dict)."""
    endpoint = get_endpoint()
    data = json.dumps(body).encode() if body is not None else None
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = "Bearer " + token
    last_err = None
    for _attempt in range(2):  # one retry for stale connections
        conn = None
        try:
            if endpoint.startswith("unix://"):
                conn = UnixHTTPConnection(endpoint[len("unix://"):], timeout=timeout)
            else:
                u = endpoint.removeprefix("http://").split("/")
                host, _, port = u[0].rpartition(":")
                conn = http.client.HTTPConnection(host, int(port or 80), timeout=timeout)
            conn.request(method, path, body=data, headers=headers)
            resp = conn.getresponse()
            raw = resp.read()
            try:
                return resp.status, json.loads(raw)
            except json.JSONDecodeError:
                return resp.status, {"error": raw.decode(errors="replace")[:300]}
        except (OSError, http.client.HTTPException) as e:
            last_err = e
        finally:
            if conn:
                conn.close()
    return 0, {"error": f"transport failure: {last_err}"}


# ---------------------------------------------------------------- identity / signing


def openssl_available() -> bool:
    return shutil.which("openssl") is not None


def gen_keypair() -> tuple[str, str]:
    """Return (private_pem, public_pem) for a fresh Ed25519 identity."""
    priv = subprocess.run(["openssl", "genpkey", "-algorithm", "ed25519"],
                          capture_output=True, check=True, timeout=15).stdout.decode()
    pub = subprocess.run(["openssl", "pkey", "-pubout"], input=priv.encode(),
                         capture_output=True, check=True, timeout=15).stdout.decode()
    return priv, pub


def sig_payload(signed_by: str, room: str | None, to: str | None, ts_ms: int,
                nonce: str, text: str) -> bytes:
    """Canonical bytes that get signed. Separator U+241F never legal in text."""
    return "\u241f".join(["v1", signed_by, room or "-", to or "-",
                          str(ts_ms), nonce, text]).encode("utf-8")


def sign(priv_pem: str, payload: bytes) -> str:
    with tempfile.TemporaryDirectory() as d:
        kf = os.path.join(d, "k.pem")
        df = os.path.join(d, "d.bin")
        open(kf, "w").write(priv_pem)
        open(df, "wb").write(payload)
        out = subprocess.run(["openssl", "pkeyutl", "-sign", "-inkey", kf,
                              "-rawin", "-in", df],
                             capture_output=True, check=True, timeout=15).stdout
        return base64.b64encode(out).decode()


def verify(pub_pem: str, payload: bytes, sig_b64: str) -> bool:
    try:
        sig = base64.b64decode(sig_b64)
    except Exception:
        return False
    with tempfile.TemporaryDirectory() as d:
        pf, df, sf = (os.path.join(d, n) for n in ("p.pem", "d.bin", "s.bin"))
        open(pf, "w").write(pub_pem)
        open(df, "wb").write(payload)
        open(sf, "wb").write(sig)
        r = subprocess.run(["openssl", "pkeyutl", "-verify", "-pubin", "-inkey", pf,
                            "-rawin", "-in", df, "-sigfile", sf],
                           capture_output=True, timeout=15)
        return r.returncode == 0


# ---------------------------------------------------------------- identity store


def active_name(as_name: str | None) -> str:
    creds = read_json(credentials_path(), {})
    if not as_name:
        as_name = os.environ.get("AGENTCHAT_NAME")
    if as_name:
        if as_name not in creds:
            sys_exit(f"not registered as '{as_name}' (run: agentchat register --name {as_name})")
        return as_name
    single = creds.get("__active__")
    if single and single in creds:
        return single
    names = [k for k in creds if not k.startswith("__")]
    if len(names) == 1:
        return names[0]
    if not names:
        sys_exit("no identities registered (run: agentchat register --name NAME)")
    sys_exit("multiple identities registered, pass --as NAME; have: " + ", ".join(sorted(names)))


def sys_exit(msg: str, code: int = 2) -> None:
    import sys
    print(json.dumps({"error": msg}), file=sys.stderr)
    sys.exit(code)


def now_ms() -> int:
    return int(time.time() * 1000)


# ---------------------------------------------------------------- shared client ops
# Used by both the CLI and the GUI bridge so signing/verification can't drift.


def send_as(cred: dict, name: str, room: str | None, to: str | None,
            text: str) -> tuple[int, dict]:
    """Sign a message with this identity's private key and submit it to the hub."""
    ts = now_ms()
    nonce = base64.urlsafe_b64encode(os.urandom(8)).decode()
    payload = sig_payload(name, room, to, ts, nonce, text)
    sig = sign(cred["priv_pem"], payload)
    return http_request("POST", "/v1/messages/send", body={
        "room": room, "to": to, "text": text, "ts": ts, "nonce": nonce, "sig": sig},
        token=cred["token"], timeout=10)


def verify_with_keys(msgs: list, keys: dict) -> list:
    """Attach sig_ok to each message; keys maps agent name -> public PEM."""
    can = openssl_available()
    for m in msgs:
        if m.get("kind") == "system" or m["from"] == "*system":
            m["sig_ok"] = None  # server-originated notices
        elif not m.get("sig"):
            m["sig_ok"] = False
        elif not can:
            m["sig_ok"] = "unknown"
        else:
            p = sig_payload(m["from"], m.get("room"), m.get("to"),
                            int(m["ts"]), m.get("nonce", ""), m["text"])
            try:
                m["sig_ok"] = bool(verify(keys.get(m["from"], ""), p, m["sig"]))
            except Exception:
                m["sig_ok"] = False
    return msgs


def start_hub(tcp: str | None = None) -> tuple[int, dict]:
    """Ensure the hub is running; returns health (status, info)."""
    st, info = http_request("GET", "/v1/health", timeout=1.5)
    if st == 200:
        return st, info
    pkg_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    env = dict(os.environ)
    env["PYTHONPATH"] = pkg_root + os.pathsep + env.get("PYTHONPATH", "")
    logf = open(os.path.join(home(), "hub.stdout.log"), "ab")
    subprocess.Popen([sys.executable, "-B", "-m", "agentchat.server"] +
                     (["--tcp", tcp] if tcp else []),
                     stdout=logf, stderr=logf, stdin=subprocess.DEVNULL,
                     start_new_session=True, env=env)
    for _ in range(40):
        time.sleep(0.1)
        st, info = http_request("GET", "/v1/health", timeout=1.0)
        if st == 200:
            return st, info
    return 0, {"error": "hub did not come up; see ~/.agentchat/hub.stdout.log"}
