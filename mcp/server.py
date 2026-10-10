"""MCP stdio server 'gp': управление gp-relay VPN туннелем (GlobalProtect).

Tools:
  gp_status      — контейнер / openconnect / tun0 / SOCKS / сессия
  gp_connect     — интерактивное подключение через socat-PTY (как в GUI):
                   пароль из DPAPI-хранилища, шлюз выбирается автоматически,
                   OTP возвращается как pending-промпт — спроси у пользователя
                   и вызови gp_connect снова с otp="<код>"
  gp_disconnect  — Ctrl-C/SIGINT openconnect в контейнере
  gp_check       — SOCKS5 CONNECT к host:port через 127.0.0.1:1080

Секреты не проходят через MCP: пароль расшифровывает дочерний драйвер
(gp_driver.py) из %APPDATA%/com.globalprotect.remote-gui/credentials.json.
"""

import os
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from mcp.server.mcpserver import MCPServer

import gp_core as core  # noqa: E402

INTERESTING = ("prompt", "connected", "failed", "disconnected")

mcp = MCPServer("gp")


def _render(state: dict | None) -> str:
    if not state:
        return f"driver did not publish state — see log: {core.LOG_PATH}"
    lines = [
        f"state: {state.get('state')}",
        f"message: {state.get('message', '')}",
    ]
    if state.get("tun0"):
        lines.append(f"tun0: {state['tun0']}")
    prompt = state.get("prompt")
    if prompt:
        lines.append(f"prompt_kind: {prompt.get('kind')}")
        lines.append(f"prompt_message: {prompt.get('message')}")
        if prompt.get("choices"):
            lines.append("choices: " + " | ".join(prompt["choices"]))
        lines.append("")
        lines.append(
            'Ask the user for the answer (usually a one-time code from the '
            'authenticator app) and call gp_connect again with otp="<answer>". '
            "Never invent or guess the code."
        )
    elif state.get("state") == "connected":
        lines.append(f"proxy: socks5h://127.0.0.1:{core.SOCKS_PORT}")
    lines.append(f"log: {core.LOG_PATH}")
    return "\n".join(lines)


@mcp.tool()
def gp_status() -> str:
    """Статус туннеля: контейнер gp-relay, openconnect, tun0 IP, SOCKS-проба,
    состояние сессии драйвера."""
    try:
        return "\n".join(core.status_report())
    except Exception as exc:
        return f"error: {exc}"


@mcp.tool()
def gp_connect(portal: str = "", gateway: str = "", otp: str = "") -> str:
    """Подключить VPN-туннель.

    Запускает драйвер сессии (docker exec + socat PTY + openconnect — тот же
    путь, что и GUI). Логин/пароль подставляются из сохранённых кредов, шлюз
    выбирается автоматически (по умолчанию gpm.domru.ru).

    Если сервер запросил ввод (OTP и т.п.), тулза возвращает
    state: prompt — спроси пользователя и вызови gp_connect ещё раз с
    otp="<ответ>". MCP не должен сам придумывать OTP.

    Args:
        portal: адрес портала (по умолчанию из сохранённых кредов / gp.domru.ru)
        gateway: предпочитаемый шлюз (по умолчанию gpm.domru.ru / GP_GATEWAY)
        otp: ответ на pending-промпт от пользователя (одноразовый код и т.п.)
    """
    try:
        state = core.read_state()
        if core.session_alive(state):
            st = state.get("state")
            if st == "prompt":
                prompt = state.get("prompt") or {}
                if otp:
                    try:
                        core.submit_response(prompt["id"], otp)
                    except ValueError as exc:
                        return f"error: {exc}"
                    state = core.wait_state(
                        state.get("updated_at", 0), 60, INTERESTING
                    )
                return _render(state)
            if st in ("starting", "connecting"):
                state = core.wait_state(
                    state.get("updated_at", 0), 30, INTERESTING
                )
                return _render(state)
            if st == "connected" and core.openconnect_running():
                return _render(state)
            # stale driver state — fall through to a fresh connect

        if core.openconnect_running():
            return (
                "openconnect is already running in the container "
                "(started by the GUI or another client)\n\n"
                + "\n".join(core.status_report())
            )

        if not core.CRED_PATH.exists() and not (
            os.environ.get("GP_USERNAME") and os.environ.get("GP_PASSWORD")
        ):
            return (
                f"error: no credentials at {core.CRED_PATH}\n"
                "Connect once in the GP Relay GUI with «Запомнить пароль», "
                "or set GP_USERNAME/GP_PASSWORD for the server process."
            )
        what = core.ensure_container(core.REPO_COMPOSE_FILE)
        since = time.time()
        pid = core.spawn_driver(portal=portal, gateway=gateway)
        state = core.wait_state(since, 60, INTERESTING)
        header = f"container {core.CONTAINER}: {what}; driver pid {pid}\n"
        return header + _render(state)
    except Exception as exc:
        return f"error: {exc}"


@mcp.tool()
def gp_disconnect() -> str:
    """Разорвать VPN: Ctrl-C через драйвер сессии, затем SIGINT openconnect
    в контейнере (как в GUI), при необходимости docker rm -f."""
    try:
        stopped, log = core.disconnect_vpn()
        log.append(
            "VPN stopped" if stopped else "error: could not confirm VPN stopped"
        )
        return "\n".join(log)
    except Exception as exc:
        return f"error: {exc}"


@mcp.tool()
def gp_check(host: str = "", port: int = 443) -> str:
    """Проверить TCP-достижимость host:port через SOCKS-туннель
    (socks5h://127.0.0.1:1080 — DNS резолвится на стороне прокси).

    Args:
        host: целевой хост (по умолчанию GP_CHECK_HOST / ticket.ertelecom.ru)
        port: целевой порт (по умолчанию 443)
    """
    host = host or os.environ.get("GP_CHECK_HOST", core.DEFAULT_CHECK_HOST)
    try:
        t0 = time.time()
        ok, detail = core.socks_connect(host, port)
        dt = time.time() - t0
        return (
            f"{host}:{port} via socks5h://127.0.0.1:{core.SOCKS_PORT}: "
            f"{'OK' if ok else 'FAIL'} ({dt:.1f}s) — {detail}"
        )
    except Exception as exc:
        return f"error: {exc}"


if __name__ == "__main__":
    mcp.run()
