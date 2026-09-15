// docker_exec / socks_probe — кирпичи для docker-пути (путь А).
// docker_exec: любой docker CLI-вызов (inspect/run/rm/exec...), вывод наружу строкой.
use std::process::Command as OsCommand;
use std::sync::atomic::{AtomicU64, Ordering};
use tauri::State;

use crate::AppState;

static DOCKER_CALL_ID: AtomicU64 = AtomicU64::new(0);

#[tauri::command]
pub fn docker_exec(args: Vec<String>) -> Result<String, String> {
    for a in &args {
        if a.is_empty() || a.len() > 8192 || a.contains('\0') {
            return Err(format!("docker_exec: invalid argument {a:?}"));
        }
    }
    let mut command = OsCommand::new("docker");
    #[cfg(target_os = "windows")]
    {
        use std::os::windows::process::CommandExt;
        const CREATE_NO_WINDOW: u32 = 0x0800_0000;
        command.creation_flags(CREATE_NO_WINDOW);
    }
    let output = command
        .args(&args)
        .output()
        .map_err(|e| format!("docker failed to start: {e}"))?;
    let id = DOCKER_CALL_ID.fetch_add(1, Ordering::Relaxed);
    let _ = id;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
        return Err(format!("docker {}: {}", output.status, stderr));
    }
    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

/// Проверка SOCKS5-прокси: TCP-коннект до 127.0.0.1:port (dante отвечает).
#[tauri::command]
pub fn socks_probe(port: u16) -> Result<String, String> {
    use std::net::TcpStream;
    use std::time::Duration;
    let addr = format!("127.0.0.1:{port}");
    match TcpStream::connect_timeout(
        &addr
            .parse()
            .map_err(|e| format!("bad address {addr}: {e}"))?,
        Duration::from_secs(3),
    ) {
        Ok(_) => Ok("ok".into()),
        Err(e) => Err(format!("socks {addr} unreachable: {e}")),
    }
}

// ——— docker-статус машины: жив ли контейнер и туннель ———

#[tauri::command]
pub fn docker_vpn_status(_state: State<'_, AppState>) -> Result<String, String> {
    // лёгкий дешёвый статус: не трогаем сессию, только docker inspect
    docker_exec(vec![
        "inspect".into(),
        "-f".into(),
        "{{.State.Running}}".into(),
        "gp-relay".into(),
    ])
    .map(|s| s.trim().to_string())
    .or_else(|_| Ok("false".into()))
}

#[allow(dead_code)]
fn docker_cmd_placeholder(_state: &AppState) {}
