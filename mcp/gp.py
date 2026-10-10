#!/usr/bin/env python3
"""gp — CLI for the gp-relay VPN tunnel (GlobalProtect via openconnect in docker).

Commands:
  status                 container / openconnect / tun0 / SOCKS probe / session
  connect [--detach]     interactive connect; auto-answers password and picks
                         the preferred gateway, asks OTP on the terminal
                         (--detach: driver runs in background, prompts via
                         `gp answer`)
  disconnect             Ctrl-C/SIGINT openconnect in the container
  check [host] [port]    SOCKS5 CONNECT via 127.0.0.1:1080 (default
                         ticket.ertelecom.ru:443)
  answer <value>         answer a pending prompt of a detached session

Credentials come from %APPDATA%/com.globalprotect.remote-gui/credentials.json
(DPAPI) — same store the GUI writes. Overrides: GP_PORTAL, GP_USERNAME,
GP_PASSWORD, GP_GATEWAY, GP_SESSION_DIR. OTP is never stored; it is always
asked from the user at connect time.
"""

from __future__ import annotations

import argparse
import os
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

import gp_core as core

COMPOSE_FILE = core.REPO_COMPOSE_FILE


def cmd_status(args) -> int:
    print("\n".join(core.status_report()))
    return 0 if core.openconnect_running() else 1


def cmd_check(args) -> int:
    t0 = time.time()
    ok, detail = core.socks_connect(args.host, args.port)
    dt = time.time() - t0
    print(f"{args.host}:{args.port} via socks5h://127.0.0.1:{core.SOCKS_PORT}: "
          f"{'OK' if ok else 'FAIL'} ({dt:.1f}s) — {detail}")
    return 0 if ok else 1


def _follow_detached() -> int:
    """Poll the session file; forward prompts to this terminal."""
    seen_prompt = None
    while True:
        state = core.read_state()
        if not state:
            print("error: driver did not publish state", file=sys.stderr)
            return 2
        st = state.get("state")
        if st == "prompt":
            prompt = state["prompt"] or {}
            if prompt.get("id") != seen_prompt:
                seen_prompt = prompt.get("id")
                choices = prompt.get("choices") or []
                if choices:
                    print("Варианты:")
                    for i, c in enumerate(choices, 1):
                        print(f"  {i}) {c}")
                try:
                    value = input(f"{prompt.get('message', 'Ответ')} ").strip()
                except (EOFError, KeyboardInterrupt):
                    core.request_disconnect()
                    print("\naborting")
                    return 130
                if choices:
                    if value.isdigit() and 1 <= int(value) <= len(choices):
                        value = choices[int(value) - 1]
                    if value not in choices:
                        print(f"нужно выбрать из: {'|'.join(choices)}")
                        continue
                try:
                    core.submit_response(prompt["id"], value)
                except ValueError as exc:
                    print(f"error: {exc}")
                    continue
        elif st in ("connected", "failed", "disconnected"):
            print(f"{st}: {state.get('message', '')}")
            if state.get("tun0"):
                print(f"tun0 = {state['tun0']}")
            return 0 if st == "connected" else 1
        elif not core.pid_alive(state.get("pid")):
            print("error: driver exited", file=sys.stderr)
            return 2
        time.sleep(0.3)


def cmd_connect(args) -> int:
    state = core.read_state()
    if core.session_alive(state):
        print(f"session already active: {state.get('state')} — "
              f"{state.get('message', '')}")
        if state.get("state") == "prompt":
            print("answer it with: gp answer <value>")
        return 1
    if core.openconnect_running():
        print("openconnect is already running in the container "
              "(started by the GUI or another client)")
        return 1
    if not core.CRED_PATH.exists() and not os.environ.get("GP_PASSWORD"):
        print(f"error: no credentials at {core.CRED_PATH}\n"
              "connect once in the GUI with «Запомнить пароль», "
              "or set GP_USERNAME/GP_PASSWORD", file=sys.stderr)
        return 2
    try:
        what = core.ensure_container(COMPOSE_FILE)
    except Exception as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    if what != "running":
        print(f"container {core.CONTAINER}: {what}")

    if args.detach:
        pid = core.spawn_driver(args.portal, args.gateway)
        print(f"driver pid {pid} — log: {core.LOG_PATH}")
        return _follow_detached()

    from gp_driver import SessionDriver

    try:
        creds = core.load_creds(portal=args.portal or None)
    except Exception as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    driver = SessionDriver(
        portal=creds["portal"],
        username=creds["username"],
        password=creds["password"],
        gateway=args.gateway,
        interactive=True,
    )
    return driver.run()


def cmd_disconnect(args) -> int:
    stopped, log = core.disconnect_vpn()
    for line in log:
        print(line)
    print("VPN stopped" if stopped else "error: could not confirm VPN stopped")
    return 0 if stopped else 1


def cmd_answer(args) -> int:
    state = core.read_state()
    if not core.session_alive(state) or state.get("state") != "prompt":
        print("no pending prompt")
        return 1
    prompt = state["prompt"]
    try:
        core.submit_response(prompt["id"], args.value)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    print(f"answer sent ({prompt.get('kind')})")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(prog="gp", description=__doc__.splitlines()[0])
    sub = ap.add_subparsers(dest="cmd", required=True)

    sub.add_parser("status", help="tunnel status").set_defaults(fn=cmd_status)

    p = sub.add_parser("connect", help="connect the VPN")
    p.add_argument("--portal", default=os.environ.get("GP_PORTAL", ""))
    p.add_argument("--gateway", default=os.environ.get("GP_GATEWAY", core.DEFAULT_GATEWAY))
    p.add_argument("--detach", action="store_true",
                   help="run the session driver in the background")
    p.set_defaults(fn=cmd_connect)

    sub.add_parser("disconnect", help="disconnect the VPN").set_defaults(fn=cmd_disconnect)

    p = sub.add_parser("check", help="probe a host through the SOCKS tunnel")
    p.add_argument("host", nargs="?", default=os.environ.get("GP_CHECK_HOST", core.DEFAULT_CHECK_HOST))
    p.add_argument("port", nargs="?", type=int, default=443)
    p.set_defaults(fn=cmd_check)

    p = sub.add_parser("answer", help="answer a pending prompt (detached session)")
    p.add_argument("value")
    p.set_defaults(fn=cmd_answer)

    args = ap.parse_args()
    try:
        return args.fn(args)
    except KeyboardInterrupt:
        print("\naborted")
        return 130
    except Exception as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
