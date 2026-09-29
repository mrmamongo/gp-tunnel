use std::{
    io::{Read, Write},
    net::{TcpListener, TcpStream},
    process::{Command, Output, Stdio},
    sync::atomic::{AtomicBool, Ordering},
    thread,
    time::{Duration, Instant},
};
pub const CONTAINER: &str = "gp-relay";
const IMAGE: &str = "ghcr.io/mrmamongo/gp-relay:latest";

fn launch_error(error: std::io::Error) -> String {
    match error.kind() {
        std::io::ErrorKind::NotFound => "Docker не найден.\nУстановите Docker Desktop или проверьте его установку, затем перезапустите GP Relay.".into(),
        std::io::ErrorKind::PermissionDenied => "Нет доступа к Docker.\nПроверьте права на запуск Docker Desktop и повторите подключение.".into(),
        _ => "Не удалось запустить Docker.\nОткройте Docker Desktop, проверьте его состояние и повторите подключение.".into(),
    }
}

fn command_error(stderr: &str) -> String {
    let lower = stderr.to_lowercase();
    if lower.contains("access is denied")
        || lower.contains("permission denied")
        || lower.contains("отказано в доступе")
    {
        return "Нет доступа к Docker.\nОткройте Docker Desktop и проверьте, доступен ли он вашей учётной записи. Затем повторите подключение.".into();
    }
    if lower.contains("cannot connect to the docker daemon")
        || lower.contains("is the docker daemon running")
        || lower.contains("error during connect")
        || lower.contains("failed to connect to the docker api")
    {
        return "Docker недоступен.\nОткройте Docker Desktop, дождитесь его запуска и нажмите «Подключить» ещё раз.".into();
    }
    format!(
        "Docker: {}",
        stderr.trim().chars().take(350).collect::<String>()
    )
}

pub fn command() -> Command {
    let mut cmd = Command::new("docker");
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        cmd.creation_flags(0x0800_0000);
    }
    cmd
}

/// Drain pipes concurrently so a full stderr pipe cannot block cancellation.
pub fn run(
    args: &[&str],
    input: Option<Vec<u8>>,
    cancel: &AtomicBool,
    timeout: Duration,
) -> Result<Output, String> {
    let mut cmd = command();
    cmd.args(args);
    run_process(cmd, input, cancel, timeout)
}

fn run_process(
    mut cmd: Command,
    input: Option<Vec<u8>>,
    cancel: &AtomicBool,
    timeout: Duration,
) -> Result<Output, String> {
    if cancel.load(Ordering::SeqCst) {
        return Err("Подключение отменено".into());
    }
    let mut child = cmd
        .stdin(if input.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(launch_error)?;
    fn drain(mut pipe: impl Read) -> Vec<u8> {
        let mut tail = Vec::new();
        let mut buf = [0; 8192];
        while let Ok(n) = pipe.read(&mut buf) {
            if n == 0 {
                break;
            }
            tail.extend_from_slice(&buf[..n]);
            if tail.len() > 65536 {
                tail.drain(..tail.len() - 65536);
            }
        }
        tail
    }
    let stdout = child.stdout.take().unwrap();
    let stderr = child.stderr.take().unwrap();
    let out = thread::spawn(move || drain(stdout));
    let err = thread::spawn(move || drain(stderr));
    let writer = input.map(|bytes| {
        let mut stdin = child.stdin.take().unwrap();
        thread::spawn(move || stdin.write_all(&bytes))
    });
    let deadline = Instant::now() + timeout;
    let status = loop {
        if cancel.load(Ordering::SeqCst) || Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            return Err(if cancel.load(Ordering::SeqCst) {
                "Подключение отменено"
            } else {
                "Docker не ответил вовремя.\nДождитесь запуска Docker Desktop и повторите подключение. Если ошибка повторяется, перезапустите Docker Desktop."
            }
            .into());
        }
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) => thread::sleep(Duration::from_millis(50)),
            Err(error) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(error.to_string());
            }
        }
    };
    if let Some(writer) = writer {
        let _ = writer.join();
    }
    Ok(Output {
        status,
        stdout: out.join().unwrap_or_default(),
        stderr: err.join().unwrap_or_default(),
    })
}
fn checked(
    args: &[&str],
    input: Option<Vec<u8>>,
    cancel: &AtomicBool,
    seconds: u64,
) -> Result<String, String> {
    let output = run(args, input, cancel, Duration::from_secs(seconds))?;
    if !output.status.success() {
        return Err(command_error(&String::from_utf8_lossy(&output.stderr)));
    }
    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}
fn embedded_context_tar() -> Result<Vec<u8>, String> {
    let mut builder = tar::Builder::new(Vec::new());
    for (name, body, mode) in [
        ("Dockerfile", include_str!("../../docker/Dockerfile"), 0o644),
        ("dante.conf", include_str!("../../docker/dante.conf"), 0o644),
        ("entry.sh", include_str!("../../docker/entry.sh"), 0o755),
    ] {
        let body = body.replace("\r\n", "\n");
        let mut header = tar::Header::new_gnu();
        header.set_size(body.len() as u64);
        header.set_mode(mode);
        header.set_cksum();
        builder
            .append_data(&mut header, name, body.as_bytes())
            .map_err(|e| e.to_string())?;
    }
    builder.into_inner().map_err(|e| e.to_string())
}
#[derive(Debug, PartialEq)]
enum ContainerAction {
    Reuse,
    Start,
    Recreate,
    Create,
}
fn container_action(
    info: Option<&serde_json::Value>,
    port: u16,
    vpn_active: bool,
) -> Result<ContainerAction, String> {
    let Some(info) = info else {
        return Ok(ContainerAction::Create);
    };
    if vpn_active {
        return Err(
            "В контейнере уже работает VPN. Завершите прежнюю сессию перед подключением.".into(),
        );
    }
    let bindings = info
        .pointer("/HostConfig/PortBindings/1080~1tcp")
        .and_then(|v| v.as_array());
    let matches = bindings.is_some_and(|a| {
        a.len() == 1 && a[0]["HostIp"] == "127.0.0.1" && a[0]["HostPort"] == port.to_string()
    });
    if !matches {
        return Ok(ContainerAction::Recreate);
    }
    if info["State"]["Running"] == true {
        Ok(ContainerAction::Reuse)
    } else {
        Ok(ContainerAction::Start)
    }
}
fn inspect(cancel: &AtomicBool) -> Result<Option<serde_json::Value>, String> {
    let ids = checked(
        &[
            "ps",
            "-a",
            "--filter",
            "name=^/gp-relay$",
            "--format",
            "{{.ID}}",
        ],
        None,
        cancel,
        10,
    )?;
    if ids.trim().is_empty() {
        return Ok(None);
    }
    let data = checked(&["inspect", CONTAINER], None, cancel, 10)?;
    let values: Vec<serde_json::Value> = serde_json::from_str(&data).map_err(|e| e.to_string())?;
    values
        .into_iter()
        .next()
        .map(Some)
        .ok_or("Docker вернул пустой статус контейнера".into())
}
pub fn vpn_stopped() -> Result<bool, String> {
    let cancel = AtomicBool::new(false);
    let Some(info) = inspect(&cancel)? else {
        return Ok(true);
    };
    if info["State"]["Running"] != true {
        return Ok(true);
    }
    let output = run(
        &["exec", CONTAINER, "sh", "-c", "pgrep -x openconnect >/dev/null; code=$?; if [ \"$code\" = 0 ]; then echo running; elif [ \"$code\" = 1 ]; then echo stopped; else exit \"$code\"; fi"],
        None,
        &cancel,
        Duration::from_secs(5),
    )?;
    process_probe_result(output.status.success(), &output.stdout)
}

fn process_probe_result(success: bool, stdout: &[u8]) -> Result<bool, String> {
    match (success, String::from_utf8_lossy(stdout).trim()) {
        (true, "running") => Ok(false),
        (true, "stopped") => Ok(true),
        _ => Err("Не удалось проверить завершение VPN".into()),
    }
}
pub fn prepare(port: u16, cancel: &AtomicBool) -> Result<(), String> {
    let info = inspect(cancel)?;
    let active = if info.as_ref().is_some_and(|v| v["State"]["Running"] == true) {
        !vpn_stopped()?
    } else {
        false
    };
    let action = container_action(info.as_ref(), port, active)?;
    if action == ContainerAction::Reuse {
        return Ok(());
    }
    let own_port = info.as_ref().is_some_and(|v| {
        v["State"]["Running"] == true
            && v.pointer("/HostConfig/PortBindings/1080~1tcp")
                .and_then(|v| v.as_array())
                .is_some_and(|a| a.iter().any(|b| b["HostPort"] == port.to_string()))
    });
    if !own_port {
        check_port_available(port)?;
    }
    if action == ContainerAction::Start {
        checked(&["start", CONTAINER], None, cancel, 30)?;
        return Ok(());
    }
    let present = run(
        &["image", "inspect", IMAGE],
        None,
        cancel,
        Duration::from_secs(10),
    )?
    .status
    .success();
    if !present && checked(&["pull", IMAGE], None, cancel, 300).is_err() {
        if cancel.load(Ordering::SeqCst) {
            return Err("Подключение отменено".into());
        }
        checked(
            &["build", "-q", "-t", IMAGE, "-t", "gp-relay:latest", "-"],
            Some(embedded_context_tar()?),
            cancel,
            600,
        )?;
    }
    if action == ContainerAction::Recreate {
        if !vpn_stopped()? {
            return Err("В контейнере появилась активная VPN-сессия".into());
        }
        checked(&["rm", "-f", CONTAINER], None, cancel, 15)?;
    }
    let binding = format!("127.0.0.1:{port}:1080");
    checked(
        &[
            "run",
            "-d",
            "--name",
            CONTAINER,
            "--cap-add",
            "NET_ADMIN",
            "--device",
            "/dev/net/tun",
            "-p",
            &binding,
            "--restart",
            "unless-stopped",
            IMAGE,
        ],
        None,
        cancel,
        45,
    )?;
    Ok(())
}
pub fn check_port_available(port: u16) -> Result<(), String> {
    TcpListener::bind(("127.0.0.1", port))
        .map(drop)
        .map_err(|_| format!("Порт {port} занят или недоступен. Укажите другой порт."))
}
pub fn signal_stop() {
    let _ = run(
        &["exec", CONTAINER, "pkill", "-INT", "-x", "openconnect"],
        None,
        &AtomicBool::new(false),
        Duration::from_secs(5),
    );
}
pub fn force_stop() -> Result<(), String> {
    checked(&["rm", "-f", CONTAINER], None, &AtomicBool::new(false), 10).map(|_| ())
}
pub fn socks_probe(port: u16) -> Result<(), String> {
    let timeout = Duration::from_millis(800);
    let mut stream = TcpStream::connect_timeout(&([127, 0, 0, 1], port).into(), timeout)
        .map_err(|e| e.to_string())?;
    stream
        .set_read_timeout(Some(timeout))
        .map_err(|e| e.to_string())?;
    stream
        .set_write_timeout(Some(timeout))
        .map_err(|e| e.to_string())?;
    stream.write_all(&[5, 1, 0]).map_err(|e| e.to_string())?;
    let mut response = [0; 2];
    stream
        .read_exact(&mut response)
        .map_err(|e| e.to_string())?;
    if response != [5, 0] {
        return Err("Порт не отвечает как SOCKS5".into());
    }
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn unavailable_engine_explains_how_to_recover_without_showing_pipe_paths() {
        for stderr in [
            "failed to connect to the docker API at npipe:////./pipe/dockerDesktopLinuxEngine; check if the path is correct and if the daemon is running: open //./pipe/dockerDesktopLinuxEngine: The system cannot find the file specified.",
            "Cannot connect to the Docker daemon at unix:///var/run/docker.sock. Is the docker daemon running?",
            "error during connect: open //./pipe/dockerDesktopLinuxEngine: The system cannot find the file specified.",
        ] {
            let message = command_error(stderr);
            assert!(message.starts_with("Docker недоступен."));
            assert!(message.contains("дождитесь его запуска"));
            assert!(message.contains("«Подключить»"));
            assert!(!message.contains("pipe"));
        }
    }
    #[test]
    fn missing_cli_and_denied_access_have_distinct_instructions() {
        assert!(
            launch_error(std::io::ErrorKind::NotFound.into()).contains("Установите Docker Desktop")
        );
        let message = command_error(
            "error during connect: open //./pipe/dockerDesktopLinuxEngine: Access is denied.",
        );
        assert!(message.starts_with("Нет доступа к Docker."));
        assert!(!message.contains("Установите"));
        assert!(
            command_error("unexpected container failure").contains("unexpected container failure")
        );
    }
    #[test]
    fn process_fixture() {
        if std::env::var("GP_RELAY_TEST_CHILD").as_deref() != Ok("pipes") {
            return;
        }
        let data = vec![b'x'; 131072];
        std::io::stdout().write_all(&data).unwrap();
        std::io::stderr().write_all(&data).unwrap();
        thread::sleep(Duration::from_secs(10));
    }
    fn fixture_command() -> Command {
        let mut cmd = Command::new(std::env::current_exe().unwrap());
        cmd.args(["--exact", "docker::tests::process_fixture", "--nocapture"])
            .env("GP_RELAY_TEST_CHILD", "pipes");
        #[cfg(windows)]
        {
            use std::os::windows::process::CommandExt;
            cmd.creation_flags(0x0800_0000);
        }
        cmd
    }
    #[test]
    fn subprocess_timeout_is_bounded_even_with_full_pipes() {
        let start = Instant::now();
        let result = run_process(
            fixture_command(),
            None,
            &AtomicBool::new(false),
            Duration::from_millis(600),
        );
        assert!(result.unwrap_err().contains("вовремя"));
        assert!(start.elapsed() < Duration::from_secs(5));
    }
    #[test]
    fn running_subprocess_can_be_cancelled() {
        let cancel = std::sync::Arc::new(AtomicBool::new(false));
        let trigger = cancel.clone();
        let worker = thread::spawn(move || {
            thread::sleep(Duration::from_millis(250));
            trigger.store(true, Ordering::SeqCst);
        });
        let result = run_process(fixture_command(), None, &cancel, Duration::from_secs(10));
        assert!(result.unwrap_err().contains("отменено"));
        worker.join().unwrap();
    }
    #[test]
    fn docker_exec_failure_is_not_a_stopped_vpn() {
        assert_eq!(process_probe_result(true, b"stopped\n"), Ok(true));
        assert_eq!(process_probe_result(true, b"running\n"), Ok(false));
        assert!(process_probe_result(false, b"").is_err());
        assert!(process_probe_result(true, b"").is_err());
    }
    fn info(running: bool, ip: &str, port: &str) -> serde_json::Value {
        serde_json::json!({"State":{"Running":running},"HostConfig":{"PortBindings":{"1080/tcp":[{"HostIp":ip,"HostPort":port}]}}})
    }
    #[test]
    fn chooses_safe_container_action() {
        assert_eq!(
            container_action(None, 1080, false).unwrap(),
            ContainerAction::Create
        );
        assert_eq!(
            container_action(Some(&info(false, "127.0.0.1", "1080")), 1080, false).unwrap(),
            ContainerAction::Start
        );
        assert_eq!(
            container_action(Some(&info(true, "127.0.0.1", "1080")), 1080, false).unwrap(),
            ContainerAction::Reuse
        );
        assert_eq!(
            container_action(Some(&info(true, "0.0.0.0", "1080")), 1080, false).unwrap(),
            ContainerAction::Recreate
        );
        assert_eq!(
            container_action(Some(&info(false, "127.0.0.1", "1080")), 2080, false).unwrap(),
            ContainerAction::Recreate
        );
        assert!(container_action(Some(&info(true, "127.0.0.1", "1080")), 2080, true).is_err());
    }
    #[test]
    fn embedded_context_is_complete_and_uses_unix_newlines() {
        let bytes = embedded_context_tar().unwrap();
        let mut archive = tar::Archive::new(bytes.as_slice());
        let mut names = Vec::new();
        for entry in archive.entries().unwrap() {
            let mut entry = entry.unwrap();
            names.push(entry.path().unwrap().to_string_lossy().into_owned());
            let mut body = String::new();
            entry.read_to_string(&mut body).unwrap();
            assert!(!body.contains('\r'));
        }
        assert_eq!(names, ["Dockerfile", "dante.conf", "entry.sh"]);
    }
    #[test]
    fn socks_probe_requires_protocol_handshake() {
        for (reply, expected) in [([5, 0], true), ([72, 84], false)] {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let port = listener.local_addr().unwrap().port();
            let server = thread::spawn(move || {
                let (mut stream, _) = listener.accept().unwrap();
                let mut request = [0; 3];
                stream.read_exact(&mut request).unwrap();
                assert_eq!(request, [5, 1, 0]);
                stream.write_all(&reply).unwrap();
            });
            assert_eq!(socks_probe(port).is_ok(), expected);
            server.join().unwrap();
        }
    }
}
