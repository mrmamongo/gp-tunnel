"""Shared logic for the gp CLI (gp.py) and the MCP server (server.py).

Ports the openconnect protocol handling from src-tauri/src/protocol.rs and the
docker glue from src-tauri/src/docker.rs to Python. Contains no secrets: the
password is decrypted from the GUI credential store (Windows DPAPI) and never
logged or printed.
"""

from __future__ import annotations

import base64
import ctypes
import json
import os
import re
import socket
import struct
import subprocess
import sys
import tempfile
import time
from pathlib import Path

CONTAINER = "gp-relay"
SOCKS_PORT = 1080
DEFAULT_PORTAL = "gp.domru.ru"
DEFAULT_GATEWAY = "gpm.domru.ru"
DEFAULT_CHECK_HOST = "ticket.ertelecom.ru"
IMAGE = "ghcr.io/mrmamongo/gp-relay:latest"

_APPDATA = Path(os.environ.get("APPDATA") or tempfile.gettempdir())
CRED_PATH = _APPDATA / "com.globalprotect.remote-gui" / "credentials.json"
SESSION_DIR = Path(
    os.environ.get("GP_SESSION_DIR") or _APPDATA / "com.globalprotect.remote-gui"
)
STATE_PATH = SESSION_DIR / "gp-session.json"
RESPONSE_PATH = SESSION_DIR / "gp-response.json"
DISCONNECT_PATH = SESSION_DIR / "gp-disconnect.req"
LOG_PATH = SESSION_DIR / "gp-session.log"

CREATE_NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0)
# docker-compose.yml sits at the repo root when mcp/ runs from a checkout.
REPO_COMPOSE_FILE = Path(__file__).parent.parent / "docker-compose.yml"


# ── credentials (Windows DPAPI) ───────────────────────────────────────


def _dpapi_unprotect_ctypes(ciphertext: bytes) -> bytes:
    """CryptUnprotectData via ctypes — stdlib only, no PowerShell needed."""

    class DATA_BLOB(ctypes.Structure):
        _fields_ = [
            ("cbData", ctypes.c_ulong),
            ("pbData", ctypes.POINTER(ctypes.c_char)),
        ]

    crypt32 = ctypes.windll.crypt32
    kernel32 = ctypes.windll.kernel32
    buf = ctypes.create_string_buffer(ciphertext, len(ciphertext))
    blob_in = DATA_BLOB(len(ciphertext), ctypes.cast(buf, ctypes.POINTER(ctypes.c_char)))
    blob_out = DATA_BLOB()
    CRYPTPROTECT_UI_FORBIDDEN = 0x1
    if not crypt32.CryptUnprotectData(
        ctypes.byref(blob_in),
        None,
        None,
        None,
        None,
        CRYPTPROTECT_UI_FORBIDDEN,
        ctypes.byref(blob_out),
    ):
        raise ctypes.WinError()
    try:
        return ctypes.string_at(blob_out.pbData, blob_out.cbData)
    finally:
        kernel32.LocalFree(blob_out.pbData)


def _dpapi_unprotect_powershell(ciphertext: bytes) -> bytes:
    b64 = base64.b64encode(ciphertext).decode("ascii")
    script = (
        "Add-Type -AssemblyName System.Security\n"
        f"$bytes = [Convert]::FromBase64String('{b64}')\n"
        "$dec = [Security.Cryptography.ProtectedData]::Unprotect("
        "$bytes, $null, 'CurrentUser')\n"
        "[Console]::OutputEncoding = [Text.Encoding]::UTF8\n"
        "[Console]::Out.Write([Text.Encoding]::UTF8.GetString($dec))\n"
    )
    proc = subprocess.run(
        [
            "powershell",
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-Command",
            script,
        ],
        capture_output=True,
        timeout=30,
    )
    if proc.returncode != 0:
        raise RuntimeError("DPAPI decryption via PowerShell failed")
    return proc.stdout.decode("utf-8", errors="strict")


def dpapi_unprotect(ciphertext: bytes) -> bytes:
    if os.name == "nt":
        try:
            return _dpapi_unprotect_ctypes(ciphertext)
        except Exception:
            return _dpapi_unprotect_powershell(ciphertext)
    return _dpapi_unprotect_powershell(ciphertext)


class CredsError(RuntimeError):
    pass


def load_creds(portal: str = "") -> dict:
    """Load portal/username/password from the GUI credential store.

    Environment overrides: GP_PORTAL, GP_USERNAME, GP_PASSWORD. The password
    comes only from DPAPI-protected credentials.json or GP_PASSWORD — it is
    never taken from the MCP caller.
    """
    data: dict = {}
    if CRED_PATH.exists():
        try:
            data = json.loads(CRED_PATH.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise CredsError(f"credentials.json unreadable: {exc}")

    result = {
        "portal": portal or os.environ.get("GP_PORTAL") or data.get("portal") or DEFAULT_PORTAL,
        "username": os.environ.get("GP_USERNAME") or data.get("username") or "",
        "password": os.environ.get("GP_PASSWORD") or "",
    }
    if not result["password"]:
        b64 = data.get("protectedPassword")
        if b64:
            try:
                result["password"] = dpapi_unprotect(base64.b64decode(b64)).decode("utf-8")
            except Exception as exc:
                raise CredsError(f"DPAPI decryption failed: {exc}")
    validate_portal(result["portal"])
    if not result["username"]:
        raise CredsError(
            "no username: run the GUI once or set GP_USERNAME"
        )
    if not result["password"]:
        raise CredsError(
            f"no saved password in {CRED_PATH} — connect once in the GUI with "
            "«Запомнить пароль», or set GP_PASSWORD"
        )
    return result


# ── validation (mirrors protocol.rs / lib.rs) ─────────────────────────


def validate_token(value: str, field: str) -> None:
    if not value:
        raise ValueError(f"{field} must not be empty")
    if len(value) > 255:
        raise ValueError(f"{field} is too long")
    if not all(c.isascii() and (c.isalnum() or c in "._:/-[]") for c in value):
        raise ValueError(f"{field} contains unsupported characters")


def validate_portal(portal: str) -> None:
    validate_token(portal, "portal")
    if portal.startswith("-"):
        raise ValueError("portal must not start with '-'")


def validate_response(value: str) -> None:
    if not value or len(value) > 4096 or any(c in "\r\n\0" for c in value):
        raise ValueError("response must be a non-empty single line")


def validate_host(host: str) -> None:
    if not host or len(host) > 253:
        raise ValueError("host is invalid")
    if not all(c.isascii() and (c.isalnum() or c in ".-_") for c in host):
        raise ValueError("host contains unsupported characters")


# ── openconnect protocol parsing (port of protocol.rs) ────────────────

KIND_USERNAME = "username"
KIND_PASSWORD = "password"
KIND_MFA = "mfa"
KIND_CHALLENGE = "challenge"
KIND_GATEWAY = "gateway"
KIND_TEXT = "text"


def find_ascii_ci(haystack: str, needle: str) -> int:
    return haystack.lower().find(needle.lower())


def parse_gateway_choices(text: str) -> list[str] | None:
    """Parse 'GATEWAY: [gp.domru.ru|gpm.domru.ru|gpo.domru.ru]:' into a list."""
    key = find_ascii_ci(text, "gateway")
    if key < 0:
        return None
    rest = text[key:]
    open_ = rest.find("[")
    if open_ < 0:
        return None
    close = rest.find("]", open_ + 1)
    if close < 0:
        return None
    choices = [
        item.strip().strip("\"'")
        for item in rest[open_ + 1 : close].split("|")
    ]
    choices = [c for c in choices if c and len(c) <= 253]
    return choices or None


def detect_prompt(text: str) -> str | None:
    lower = text.lower()
    if "gateway:" in lower or ("select" in lower and "gateway" in lower):
        if parse_gateway_choices(text) is not None:
            return KIND_GATEWAY
    if (
        "one-time" in lower
        or "one time" in lower
        or "otp" in lower
        or "verification code" in lower
        or "authentication code" in lower
        or "token code" in lower
        or "passcode" in lower
        or "mfa" in lower
        or "одноразов" in lower
        or "код подтверждения" in lower
        or "код:" in lower
    ):
        return KIND_MFA
    if "password" in lower or "passphrase" in lower or "пароль" in lower:
        return KIND_PASSWORD
    if "username" in lower or "user name" in lower or "логин" in lower:
        return KIND_USERNAME
    if ("authgroup" in lower or "auth group" in lower or "gateway" in lower) and (
        ":" in lower
        or "choose" in lower
        or "select" in lower
        or "enter" in lower
        or "please" in lower
    ):
        return KIND_TEXT
    if "challenge:" in lower:
        return KIND_CHALLENGE
    if (
        "(yes/no" in lower
        or "[yes/no" in lower
        or "do you want to continue(y/n)?" in lower
        or "reason for disconnect" in lower
        or "disconnect reason" in lower
    ):
        return KIND_TEXT
    return None


def detect_interactive_prompt(text: str) -> str | None:
    """A bare 'Challenge:' inherits the meaning of the server line above it."""
    lines = [l.strip() for l in text.splitlines() if l.strip()]
    if not lines:
        return None
    kind = detect_prompt(lines[-1])
    if kind is None:
        return None
    if kind != KIND_CHALLENGE:
        return kind
    if len(lines) < 2:
        return KIND_CHALLENGE
    prev = detect_prompt(lines[-2])
    if prev == KIND_PASSWORD:
        return KIND_PASSWORD
    if prev == KIND_MFA:
        return KIND_MFA
    return KIND_CHALLENGE


STATUS_CONNECTED = "connected"
STATUS_FAILED = "failed"


def parse_openconnect_status(text: str) -> str | None:
    lower = text.lower()
    if (
        "authentication failed" in lower
        or "login failed" in lower
        or (
            "failed to connect" in lower
            and "failed to connect esp tunnel; using https instead" not in lower
        )
        or "could not connect" in lower
        or "unable to connect" in lower
        or "connection failed" in lower
        or "failed to establish" in lower
    ):
        return STATUS_FAILED
    if (
        "esp session established" in lower
        or "established dtls connection" in lower
        or "vpn tunnel established" in lower
        or "vpn tunnel connected" in lower
        or "esp tunnel connected" in lower
        or ("configured as" in lower and "ssl connected" in lower)
        or "connected as" in lower
    ):
        return STATUS_CONNECTED
    return None


def prompt_complete(line: str) -> bool:
    return line.endswith(":") or line.endswith("?") or line.endswith("]")


def last_line(text: str) -> str:
    for line in reversed(text.splitlines()):
        if line.strip():
            return line.strip()
    return ""


# ── docker helpers (port of docker.rs) ────────────────────────────────


def docker(*args: str, timeout: int = 30, input_bytes: bytes | None = None):
    return subprocess.run(
        ["docker", *args],
        capture_output=True,
        timeout=timeout,
        input=input_bytes,
        creationflags=CREATE_NO_WINDOW,
    )


def docker_text(*args: str, timeout: int = 30) -> subprocess.CompletedProcess:
    proc = docker(*args, timeout=timeout)
    proc.stdout = proc.stdout.decode("utf-8", errors="replace") if proc.stdout else ""
    proc.stderr = proc.stderr.decode("utf-8", errors="replace") if proc.stderr else ""
    return proc


def container_exists() -> bool:
    proc = docker_text("inspect", "-f", "{{.State.Running}}", CONTAINER, timeout=15)
    return proc.returncode == 0


def container_running() -> bool:
    proc = docker_text("inspect", "-f", "{{.State.Running}}", CONTAINER, timeout=15)
    return proc.returncode == 0 and proc.stdout.strip() == "true"


def openconnect_running() -> bool:
    """pgrep probe — False only when the probe says 'stopped'."""
    if not container_running():
        return False
    proc = docker_text(
        "exec",
        CONTAINER,
        "sh",
        "-c",
        "pgrep -x openconnect >/dev/null; code=$?; "
        'if [ "$code" = 0 ]; then echo running; '
        'elif [ "$code" = 1 ]; then echo stopped; '
        'else exit "$code"; fi',
        timeout=10,
    )
    return proc.returncode == 0 and proc.stdout.strip() == "running"


def openconnect_pid() -> str | None:
    proc = docker_text(
        "exec", CONTAINER, "sh", "-c", "pgrep -x openconnect | head -1", timeout=10
    )
    out = proc.stdout.strip()
    return out if out.isdigit() else None


def tun0_ip() -> str | None:
    proc = docker_text("exec", CONTAINER, "ip", "-4", "addr", "show", "tun0", timeout=10)
    if proc.returncode != 0:
        return None
    m = re.search(r"inet\s+(\d+\.\d+\.\d+\.\d+)", proc.stdout)
    return m.group(1) if m else None


def ensure_container(compose_file: Path | None = None) -> str:
    """Make sure gp-relay is up. Returns what happened."""
    if container_running():
        return "running"
    if container_exists():
        proc = docker_text("start", CONTAINER, timeout=30)
        if proc.returncode == 0:
            return "started"
        raise RuntimeError(f"docker start failed: {proc.stderr.strip()[:300]}")
    if compose_file and compose_file.exists():
        proc = docker_text(
            "compose", "-f", str(compose_file), "up", "-d", timeout=300
        )
        if proc.returncode == 0:
            return "composed"
        raise RuntimeError(f"docker compose up failed: {proc.stderr.strip()[:300]}")
    raise RuntimeError(
        f"container {CONTAINER} does not exist — run `docker compose up -d` first"
    )


def signal_stop() -> None:
    docker_text("exec", CONTAINER, "pkill", "-INT", "-x", "openconnect", timeout=10)


def force_stop() -> None:
    docker_text("rm", "-f", CONTAINER, timeout=15)


def vpn_stopped() -> bool:
    """True when no openconnect process remains (or the probe cannot run)."""
    if not container_running():
        return True
    proc = docker_text(
        "exec", CONTAINER, "sh", "-c", "pgrep -x openconnect >/dev/null", timeout=10
    )
    return proc.returncode != 0


# ── SOCKS5 (no external deps; socks5h semantics — remote DNS) ─────────


def _recv_exact(sock: socket.socket, n: int) -> bytes:
    data = b""
    while len(data) < n:
        chunk = sock.recv(n - len(data))
        if not chunk:
            raise OSError("socks proxy closed connection")
        data += chunk
    return data


SOCKS_REPLY = {
    0: "ok",
    1: "general failure",
    2: "connection not allowed",
    3: "network unreachable",
    4: "host unreachable",
    5: "connection refused",
    6: "TTL expired",
    7: "command not supported",
    8: "address type not supported",
}


def socks_probe(port: int = SOCKS_PORT, timeout: float = 2.0) -> bool:
    """Handshake-only probe (same as socks_probe in docker.rs)."""
    try:
        with socket.create_connection(("127.0.0.1", port), timeout) as s:
            s.settimeout(timeout)
            s.sendall(b"\x05\x01\x00")
            return _recv_exact(s, 2) == b"\x05\x00"
    except OSError:
        return False


def socks_connect(
    host: str, port: int = 443, socks_port: int = SOCKS_PORT, timeout: float = 8.0
) -> tuple[bool, str]:
    """SOCKS5 CONNECT host:port through the relay. Returns (ok, detail)."""
    validate_host(host)
    try:
        with socket.create_connection(("127.0.0.1", socks_port), timeout) as s:
            s.settimeout(timeout)
            s.sendall(b"\x05\x01\x00")
            if _recv_exact(s, 2) != b"\x05\x00":
                return False, "proxy rejected no-auth handshake"
            encoded = host.encode("idna")
            s.sendall(
                b"\x05\x01\x00\x03"
                + bytes([len(encoded)])
                + encoded
                + struct.pack(">H", port)
            )
            head = _recv_exact(s, 4)
            rep = head[1]
            atyp = head[3]
            if atyp == 0x01:
                _recv_exact(s, 4)
            elif atyp == 0x04:
                _recv_exact(s, 16)
            elif atyp == 0x03:
                _recv_exact(s, _recv_exact(s, 1)[0])
            _recv_exact(s, 2)
            if rep == 0:
                return True, f"tcp connect {host}:{port} via socks ok"
            return False, f"proxy reply: {SOCKS_REPLY.get(rep, f'code {rep}')}"
    except (OSError, ValueError) as exc:
        return False, str(exc)


# ── session state files (driver <-> MCP/CLI handshake) ───────────────


def _atomic_write(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")
    os.replace(tmp, path)


def read_state() -> dict | None:
    try:
        return json.loads(STATE_PATH.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None


def write_state(payload: dict) -> None:
    payload["updated_at"] = time.time()
    _atomic_write(STATE_PATH, payload)


def pid_alive(pid) -> bool:
    try:
        pid = int(pid)
    except (TypeError, ValueError):
        return False
    if pid <= 0:
        return False
    if os.name == "nt":
        kernel32 = ctypes.windll.kernel32
        PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
        handle = kernel32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
        if not handle:
            return False
        try:
            code = ctypes.c_ulong()
            if not kernel32.GetExitCodeProcess(handle, ctypes.byref(code)):
                return False
            STILL_ACTIVE = 259
            return code.value == STILL_ACTIVE
        finally:
            kernel32.CloseHandle(handle)
    try:
        os.kill(pid, 0)
        return True
    except OSError:
        return False


def session_alive(state: dict | None = None) -> bool:
    state = state if state is not None else read_state()
    if not state:
        return False
    if state.get("state") not in ("starting", "connecting", "prompt", "connected"):
        return False
    return pid_alive(state.get("pid"))


def submit_response(request_id: str, value: str) -> None:
    validate_response(value)
    _atomic_write(RESPONSE_PATH, {"id": request_id, "value": value})


def take_response(request_id: str) -> str | None:
    """Driver side: consume a pending response matching request_id."""
    try:
        payload = json.loads(RESPONSE_PATH.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    if payload.get("id") != request_id:
        try:
            RESPONSE_PATH.unlink()
        except OSError:
            pass
        return None
    try:
        RESPONSE_PATH.unlink()
    except OSError:
        pass
    return payload.get("value")


def request_disconnect() -> None:
    SESSION_DIR.mkdir(parents=True, exist_ok=True)
    DISCONNECT_PATH.write_text(str(time.time()), encoding="utf-8")


def disconnect_requested() -> bool:
    return DISCONNECT_PATH.exists()


def clear_disconnect_request() -> None:
    try:
        DISCONNECT_PATH.unlink()
    except OSError:
        pass


def wait_state(
    since: float, timeout: float, interesting: tuple[str, ...]
) -> dict | None:
    """Poll the state file until updated_at > since and state is interesting."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        state = read_state()
        if (
            state
            and state.get("updated_at", 0) > since
            and state.get("state") in interesting
        ):
            return state
        time.sleep(0.3)
    return read_state()


# ── session driver lifecycle / high-level ops ─────────────────────────


def spawn_driver(portal: str = "", gateway: str = DEFAULT_GATEWAY) -> int:
    """Start gp_driver.py detached. The driver owns the VPN session."""
    argv = [
        sys.executable,
        str(Path(__file__).parent / "gp_driver.py"),
        "--gateway",
        gateway or DEFAULT_GATEWAY,
    ]
    if portal:
        argv += ["--portal", portal]
    kwargs: dict = dict(
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    if os.name == "nt":
        kwargs["creationflags"] = (
            CREATE_NO_WINDOW
            | getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
            | getattr(subprocess, "DETACHED_PROCESS", 0)
        )
    else:
        kwargs["start_new_session"] = True
    proc = subprocess.Popen(argv, **kwargs)
    return proc.pid


def disconnect_vpn(grace: float = 8.0, sigint_wait: float = 5.0) -> tuple[bool, list[str]]:
    """Ctrl-C via the session driver, then SIGINT, then docker rm -f.

    Mirrors vpn_disconnect/stop_session in the GUI. Returns (stopped, log).
    """
    log: list[str] = []
    state = read_state()
    if session_alive(state):
        log.append("asking session driver to stop (Ctrl-C)…")
        request_disconnect()
        deadline = time.time() + grace
        while time.time() < deadline and not vpn_stopped():
            time.sleep(0.2)
    if not vpn_stopped():
        log.append("SIGINT openconnect…")
        signal_stop()
        deadline = time.time() + sigint_wait
        while time.time() < deadline and not vpn_stopped():
            time.sleep(0.2)
    if not vpn_stopped():
        log.append(f"openconnect still alive — docker rm -f {CONTAINER}")
        force_stop()
        time.sleep(1.0)
    stopped = vpn_stopped()
    if state and stopped:
        state.update({"state": "disconnected", "message": "Отключён", "prompt": None})
        write_state(state)
    return stopped, log


def status_report() -> list[str]:
    running = container_running()
    oc = openconnect_running() if running else False
    ip = tun0_ip() if running else None
    socks = socks_probe(SOCKS_PORT)
    lines = [
        f"container:  {'running' if running else 'not running'} ({CONTAINER})",
        f"openconnect: {'running' if oc else 'not running'}",
        f"tun0:       {ip or '—'}",
        f"socks5:     127.0.0.1:{SOCKS_PORT} {'ok' if socks else 'no handshake'}",
        f"creds:      {'found' if CRED_PATH.exists() else 'MISSING'} ({CRED_PATH})",
    ]
    state = read_state()
    if state:
        alive = pid_alive(state.get("pid"))
        line = f"session:    {state.get('state')} (driver pid {state.get('pid')}{'' if alive else ', dead'})"
        if state.get("prompt"):
            line += f" — waiting: {state['prompt'].get('kind')}"
        lines.append(line)
        if state.get("message"):
            lines.append(f"  {state['message']}")
    else:
        lines.append("session:    none")
    return lines
