// docker_exec / socks_probe — кирпичи для docker-пути (путь А).
// docker_exec: любой docker CLI-вызов (inspect/run/rm/exec...), вывод наружу строкой.
use std::process::Command as OsCommand;
use std::sync::atomic::{AtomicU64, Ordering};
use tauri::State;

use crate::AppState;

// Docker-контекст вшит в бинарь: приложение остаётся самодостаточным (один exe),
// docker/ и docker-compose.yml в комплекте больше не нужны. Если образ не
// удаётся стянуть из реестра — собираем его из этих же строк на месте.
const EMBEDDED_DOCKERFILE: &str = include_str!("../../docker/Dockerfile");
const EMBEDDED_DANTE_CONF: &str = include_str!("../../docker/dante.conf");
const EMBEDDED_ENTRY_SH: &str = include_str!("../../docker/entry.sh");

/// Образ в реестре (его тянет GUI по умолчанию).
#[allow(dead_code)]
pub const DEFAULT_IMAGE: &str = "ghcr.io/mrmamongo/gp-relay:latest";

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

// ——— образ: тянем из реестра, при неудаче собираем из вшитого контекста ———

fn embedded_context_tar() -> Result<Vec<u8>, String> {
    let mut builder = tar::Builder::new(Vec::new());
    let files: [(&str, &str, u32); 3] = [
        ("Dockerfile", EMBEDDED_DOCKERFILE, 0o644),
        ("dante.conf", EMBEDDED_DANTE_CONF, 0o644),
        ("entry.sh", EMBEDDED_ENTRY_SH, 0o755),
    ];
    for (name, body, mode) in files {
        let mut header = tar::Header::new_gnu();
        header.set_size(body.len() as u64);
        header.set_mode(mode);
        header.set_cksum();
        builder
            .append_data(&mut header, name, body.as_bytes())
            .map_err(|error| format!("не удалось упаковать {name}: {error}"))?;
    }
    builder
        .into_inner()
        .map_err(|error| format!("не удалось собрать docker-контекст: {error}"))
}

#[tauri::command]
pub fn docker_image_present(image: String) -> bool {
    docker_exec(vec!["image".into(), "inspect".into(), image]).is_ok()
}

/// Гарантирует наличие образа: present → ничего, иначе pull, при неудаче — build
/// из вшитого в exe docker-контекста (сеть/реестр не нужны, кроме apk-пакетов).
#[tauri::command]
pub fn docker_ensure_image(image: String, local_tag: String) -> Result<String, String> {
    if docker_image_present(image.clone()) {
        return Ok("present".into());
    }
    match docker_exec(vec!["pull".into(), image.clone()]) {
        Ok(_) => return Ok("pulled".into()),
        Err(pull_error) => {
            let context = embedded_context_tar()?;
            let mut command = OsCommand::new("docker");
            #[cfg(target_os = "windows")]
            {
                use std::os::windows::process::CommandExt;
                const CREATE_NO_WINDOW: u32 = 0x0800_0000;
                command.creation_flags(CREATE_NO_WINDOW);
            }
            let mut child = command
                .args([
                    "build",
                    "-q",
                    "-t",
                    local_tag.as_str(),
                    "-t",
                    image.as_str(),
                    "-",
                ])
                .stdin(std::process::Stdio::piped())
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::piped())
                .spawn()
                .map_err(|error| format!("не удалось запустить docker build: {error}"))?;
            {
                use std::io::Write;
                let mut stdin = child
                    .stdin
                    .take()
                    .ok_or("docker build stdin недоступен")?;
                stdin
                    .write_all(&context)
                    .map_err(|error| format!("не удалось передать docker-контекст: {error}"))?;
            }
            let output = child
                .wait_with_output()
                .map_err(|error| format!("docker build не завершился: {error}"))?;
            if output.status.success() {
                return Ok("built".into());
            }
            let stderr = String::from_utf8_lossy(&output.stderr);
            Err(format!(
                "образ недоступен: pull не удался ({pull_error}), сборка из вшитого контекста тоже: {}",
                stderr.trim()
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn embedded_context_tar_contains_docker_context() {
        let context = embedded_context_tar().expect("tar");
        let mut archive = tar::Archive::new(context.as_slice());
        let names: Vec<String> = archive
            .entries()
            .expect("entries")
            .map(|entry| entry.expect("entry").path().expect("path").display().to_string())
            .collect();
        assert!(names.iter().any(|name| name.contains("Dockerfile")), "{names:?}");
        assert!(names.iter().any(|name| name.contains("dante.conf")), "{names:?}");
        assert!(names.iter().any(|name| name.contains("entry.sh")), "{names:?}");

        let mut archive = tar::Archive::new(context.as_slice());
        let mut dockerfile = String::new();
        for entry in archive.entries().expect("entries") {
            let mut entry = entry.expect("entry");
            let path = entry.path().expect("path").display().to_string();
            if path.contains("Dockerfile") {
                use std::io::Read;
                entry.read_to_string(&mut dockerfile).expect("read");
            }
        }
        // Контекст в бинаре обязан совпадать с рабочим docker-контекстом репозитория.
        assert_eq!(dockerfile, EMBEDDED_DOCKERFILE);
        assert!(dockerfile.contains("socat"), "образ должен содержать socat");
    }
}
