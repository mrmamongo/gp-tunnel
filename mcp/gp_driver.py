"""gp_driver.py — owns one openconnect session inside the gp-relay container.

Runs `docker exec -i gp-relay socat - 'EXEC:"openconnect --protocol=gp <portal>",pty,...'`
— the same path the GUI uses (src-tauri/src/lib.rs run_session). The driver
process must stay alive for the whole VPN session: when it dies, docker exec
exits, the PTY disappears and openconnect terminates.

Modes:
  --interactive   prompts are answered on this terminal (CLI `gp connect`)
  (default)       prompts are published to gp-session.json and answered via
                  gp-response.json (used by the MCP server / `gp answer`)

State file protocol (gp_core.SESSION_DIR):
  gp-session.json    driver publishes {pid, state, message, prompt, tun0}
  gp-response.json   client submits {id, value} for the pending prompt
  gp-disconnect.req  presence asks the driver to send Ctrl-C (ETX) gracefully
"""

from __future__ import annotations

import argparse
import codecs
import os
import queue
import subprocess
import sys
import threading
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

import gp_core as core

PROMPT_TIMEOUT = 600.0  # seconds a pending prompt waits for an answer
BURST_QUIET = 0.08      # like run_session: a prompt ends an output burst
ANALYSIS_CAP = 32768
HEARTBEAT = 2.0


class Abort(Exception):
    pass


class Reporter:
    """Publishes driver state to gp-session.json and the session log."""

    def __init__(self, verbose: bool = False):
        self.verbose = verbose
        core.SESSION_DIR.mkdir(parents=True, exist_ok=True)
        self._log = open(core.LOG_PATH, "a", encoding="utf-8", errors="replace")
        self._state = {
            "pid": os.getpid(),
            "state": "starting",
            "message": "Запуск…",
            "prompt": None,
            "tun0": None,
            "connected_since": None,
        }
        self.publish()

    def publish(self, **fields):
        self._state.update(fields)
        core.write_state(dict(self._state))
        if self.verbose and "message" in fields:
            print(f"[{self._state['state']}] {fields['message']}", flush=True)

    def heartbeat(self):
        core.write_state(dict(self._state))

    def raw(self, text: str):
        try:
            self._log.write(text)
            self._log.flush()
        except OSError:
            pass

    def note(self, line: str):
        self.raw(f"\n>>> [{line}]\n")

    def close(self):
        try:
            self._log.close()
        except OSError:
            pass


class FileResponder:
    """Detached mode: publish the prompt, wait for gp-response.json."""

    def __init__(self, driver: "SessionDriver"):
        self.driver = driver

    def ask(self, prompt: dict) -> str:
        rep = self.driver.reporter
        rep.publish(state="prompt", prompt=prompt, message=prompt["message"])
        deadline = time.time() + PROMPT_TIMEOUT
        while time.time() < deadline:
            if core.disconnect_requested():
                raise Abort("disconnect requested")
            if self.driver.child.poll() is not None:
                raise Abort("openconnect exited")
            value = core.take_response(prompt["id"])
            if value is not None:
                rep.note(f"ANSWER {prompt['kind']}")
                rep.publish(
                    state="connecting", prompt=None, message="Подключение…"
                )
                return value
            time.sleep(0.15)
        raise Abort("prompt timed out")


class InteractiveResponder:
    """CLI foreground mode: ask the user on this terminal."""

    def __init__(self, driver: "SessionDriver"):
        self.driver = driver

    def ask(self, prompt: dict) -> str:
        rep = self.driver.reporter
        rep.publish(state="prompt", prompt=prompt, message=prompt["message"])
        choices = prompt.get("choices") or []
        if choices:
            print("Варианты:")
            for i, c in enumerate(choices, 1):
                print(f"  {i}) {c}")
        try:
            value = input(f"{prompt['message']} ").strip()
        except EOFError:
            raise Abort("no input")
        if choices:
            if value.isdigit() and 1 <= int(value) <= len(choices):
                value = choices[int(value) - 1]
            if value not in choices:
                raise Abort(f"выберите шлюз из списка: {'|'.join(choices)}")
        core.validate_response(value)
        rep.note(f"ANSWER {prompt['kind']}")
        rep.publish(state="connecting", prompt=None, message="Подключение…")
        return value


class SessionDriver:
    def __init__(self, portal, username, password, gateway, interactive=False):
        self.portal = portal
        self.gateway = gateway
        self.interactive = interactive
        self.auth = {"username": username, "password": password}
        self.username_sent = False
        self.password_sent = False
        self.gateway_started = False
        self.reporter = Reporter(verbose=interactive)
        self.responder = (
            InteractiveResponder(self) if interactive else FileResponder(self)
        )
        self.child: subprocess.Popen | None = None
        self.output: queue.Queue[str] = queue.Queue()

    # ── auto-auth (port of AutomaticAuth) ─────────────────────────────

    def _begin_gateway(self):
        if not self.gateway_started:
            self.gateway_started = True
            self.username_sent = False
            self.password_sent = False

    def _auto_take(self, kind: str, choices: list[str] | None) -> str | None:
        if kind == core.KIND_USERNAME and not self.username_sent:
            self.username_sent = True
            return self.auth["username"]
        if kind == core.KIND_PASSWORD and not self.password_sent:
            self.password_sent = True
            return self.auth["password"]
        if kind == core.KIND_GATEWAY and self.gateway in (choices or []):
            self._begin_gateway()
            return self.gateway
        return None

    def _send(self, value: str):
        core.validate_response(value)
        assert self.child and self.child.stdin
        self.child.stdin.write(value.encode("utf-8") + b"\n")
        self.child.stdin.flush()

    def _ctrl_c(self):
        try:
            if self.child and self.child.stdin:
                self.child.stdin.write(b"\x03")
                self.child.stdin.flush()
        except OSError:
            pass

    def _redact(self, text: str) -> str:
        for secret in (self.auth["password"], self.auth["username"]):
            if secret:
                text = text.replace(secret, "••••")
        return text[:240]

    # ── subprocess ────────────────────────────────────────────────────

    def _reader(self, stream):
        decoder = codecs.getincrementaldecoder("utf-8")("replace")
        while True:
            chunk = stream.read(4096)
            if not chunk:
                break
            text = decoder.decode(chunk)
            if text:
                self.reporter.raw(text)
                self.output.put(text)

    def _spawn(self):
        exec_addr = (
            f'EXEC:"openconnect --protocol=gp {self.portal}"'
            ",pty,stderr,setsid,ctty,sigint,sane,echo=0"
        )
        self.child = subprocess.Popen(
            ["docker", "exec", "-i", core.CONTAINER, "socat", "-", exec_addr],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            bufsize=0,
            creationflags=core.CREATE_NO_WINDOW,
        )
        threading.Thread(
            target=self._reader, args=(self.child.stdout,), daemon=True
        ).start()
        threading.Thread(
            target=self._reader, args=(self.child.stderr,), daemon=True
        ).start()

    # ── graceful stop (port of stop_session) ─────────────────────────

    def _stop(self, grace=3.0) -> bool:
        self._ctrl_c()
        deadline = time.time() + grace
        while time.time() < deadline:
            if self.child.poll() is not None or core.vpn_stopped():
                break
            time.sleep(0.1)
        if not core.vpn_stopped():
            core.signal_stop()
            deadline = time.time() + 4.0
            while time.time() < deadline and not core.vpn_stopped():
                time.sleep(0.1)
        try:
            self.child.terminate()
        except OSError:
            pass
        return core.vpn_stopped()

    # ── main loop (port of run_session) ───────────────────────────────

    def run(self) -> int:
        rep = self.reporter
        core.clear_disconnect_request()
        try:
            self._spawn()
        except OSError as exc:
            rep.publish(state="failed", message=f"Не удалось запустить openconnect: {exc}")
            return 2

        analysis = ""
        last_chunk = time.time()
        connected = False
        failure = None
        rc = 1
        next_heartbeat = time.time() + HEARTBEAT
        rep.publish(state="connecting", message="Подключение…")

        try:
            while True:
                if core.disconnect_requested():
                    core.clear_disconnect_request()
                    rep.publish(
                        state="disconnecting", message="Отключение…", prompt=None
                    )
                    ok = self._stop()
                    rep.publish(
                        state="disconnected" if ok else "failed",
                        message="Отключён" if ok else "Не удалось подтвердить отключение",
                        prompt=None,
                    )
                    return 0 if ok else 1

                read_any = False
                while True:
                    try:
                        analysis += self.output.get_nowait()
                        read_any = True
                    except queue.Empty:
                        break
                if read_any:
                    last_chunk = time.time()
                if len(analysis) > ANALYSIS_CAP:
                    analysis = analysis[-8192:]

                if analysis and time.time() - last_chunk >= BURST_QUIET:
                    status = core.parse_openconnect_status(analysis)
                    line = core.last_line(analysis)
                    if status == core.STATUS_CONNECTED and not connected:
                        connected = True
                        ip = core.tun0_ip()
                        rep.note(f"CONNECTED tun0={ip}")
                        rep.publish(
                            state="connected",
                            message="Подключён",
                            prompt=None,
                            tun0=ip,
                            connected_since=time.time(),
                        )
                    elif status == core.STATUS_FAILED:
                        failure = "Ошибка авторизации или подключения к VPN"

                    if not connected and core.prompt_complete(line):
                        kind = core.detect_interactive_prompt(analysis)
                        if kind:
                            choices = (
                                core.parse_gateway_choices(line)
                                if kind == core.KIND_GATEWAY
                                else None
                            )
                            value = self._auto_take(kind, choices)
                            if value is None:
                                prompt = self._make_prompt(kind, line, analysis, choices)
                                rep.note(f"PROMPT {kind}: {prompt['message']}")
                                value = self.responder.ask(prompt)
                                while choices and value not in choices:
                                    rep.note(f"INVALID CHOICE: {value}")
                                    value = self.responder.ask(prompt)
                                if kind == core.KIND_GATEWAY:
                                    self._begin_gateway()
                                elif kind == core.KIND_USERNAME:
                                    self.auth["username"] = value
                                elif kind == core.KIND_PASSWORD:
                                    self.auth["password"] = value
                            else:
                                rep.note(f"AUTO {kind}")
                            self._send(value)
                    if core.prompt_complete(line) or status is not None:
                        analysis = ""

                poll = self.child.poll()
                if poll is not None:
                    if not core.vpn_stopped():
                        self._stop()
                    if connected and core.vpn_stopped():
                        rep.publish(
                            state="disconnected",
                            message="Сессия завершена",
                            prompt=None,
                        )
                        rc = 0
                    elif failure:
                        rep.publish(state="failed", message=failure, prompt=None)
                    elif poll == 0:
                        rep.publish(
                            state="disconnected",
                            message="Сессия завершена",
                            prompt=None,
                        )
                        rc = 0
                    else:
                        rep.publish(
                            state="failed",
                            message="OpenConnect завершился с ошибкой. "
                            "Проверьте хост и данные входа.",
                            prompt=None,
                        )
                    return rc

                if time.time() >= next_heartbeat:
                    rep.heartbeat()
                    next_heartbeat = time.time() + HEARTBEAT
                time.sleep(0.03)

        except Abort as exc:
            rep.note(f"ABORT: {exc}")
            rep.publish(state="disconnecting", message="Отмена…", prompt=None)
            ok = self._stop()
            rep.publish(
                state="disconnected" if ok else "failed",
                message=f"Отменено: {exc}" if ok else f"Отмена: {exc}; VPN ещё активен",
                prompt=None,
            )
            return 1
        except KeyboardInterrupt:
            rep.publish(
                state="disconnecting", message="Отключение…", prompt=None
            )
            ok = self._stop()
            rep.publish(
                state="disconnected" if ok else "failed",
                message="Отключён" if ok else "Не удалось подтвердить отключение",
                prompt=None,
            )
            return 130
        finally:
            rep.close()

    _PROMPT_LABELS = {
        core.KIND_USERNAME: "Повторите логин",
        core.KIND_PASSWORD: "Повторите пароль",
        core.KIND_MFA: "Одноразовый код",
        core.KIND_CHALLENGE: "Ответ на запрос сервера",
        core.KIND_GATEWAY: "Шлюз",
        core.KIND_TEXT: "Ответ сервера",
    }

    def _make_prompt(self, kind, line, analysis, choices) -> dict:
        message = self._PROMPT_LABELS.get(kind, "Ответ сервера")
        if kind in (core.KIND_TEXT, core.KIND_CHALLENGE):
            server_message = line
            if kind == core.KIND_CHALLENGE:
                lines = [l.strip() for l in analysis.splitlines() if l.strip()]
                if len(lines) >= 2:
                    server_message = lines[-2]
            message = self._redact(server_message)
        return {
            "id": f"{os.getpid()}-{int(time.time() * 1000)}",
            "kind": kind,
            "message": message,
            "choices": choices or [],
        }


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--portal", default="", help="override portal from credentials")
    ap.add_argument("--gateway", default=os.environ.get("GP_GATEWAY", core.DEFAULT_GATEWAY))
    ap.add_argument("--interactive", action="store_true",
                    help="answer prompts on this terminal (CLI mode)")
    args = ap.parse_args()

    try:
        creds = core.load_creds(portal=args.portal or None)
    except Exception as exc:
        Reporter().publish(state="failed", message=str(exc))
        print(f"error: {exc}", file=sys.stderr)
        return 2

    driver = SessionDriver(
        portal=creds["portal"],
        username=creds["username"],
        password=creds["password"],
        gateway=args.gateway,
        interactive=args.interactive,
    )
    try:
        return driver.run()
    finally:
        # keep `password` out of reach as early as possible
        driver.auth["password"] = ""


if __name__ == "__main__":
    sys.exit(main())
