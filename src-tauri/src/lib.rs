mod credentials;
mod docker;
mod protocol;
mod tray;

use protocol::{
    decode_utf8_chunk, detect_interactive_prompt, disconnect_bytes, parse_gateway_choices,
    parse_openconnect_status, validate_token, OpenConnectStatus,
};
use serde::{Deserialize, Serialize};
use std::{
    io::{Read, Write},
    process::{Child, ChildStdin, Stdio},
    sync::{
        atomic::{AtomicBool, Ordering},
        mpsc::{self, Receiver, Sender},
        Arc, Mutex,
    },
    thread,
    time::{Duration, Instant},
};
use tauri::{AppHandle, Emitter, Manager, State};

#[derive(Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ConnectionConfig {
    portal: String,
    socks_port: u16,
}
#[derive(Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AuthInput {
    username: String,
    password: String,
    remember_password: bool,
}
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(crate) enum PromptKind {
    Username,
    Password,
    Mfa,
    Challenge,
    Gateway,
    Text,
}
#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Prompt {
    request_id: String,
    kind: PromptKind,
    message: String,
    choices: Vec<String>,
}
#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Snapshot {
    revision: u64,
    state: String,
    message: String,
    active: bool,
    cleanup_required: bool,
    portal: String,
    socks_port: u16,
    prompt: Option<Prompt>,
}
impl Default for Snapshot {
    fn default() -> Self {
        Self {
            revision: 0,
            state: "idle".into(),
            message: "Не подключён".into(),
            active: false,
            cleanup_required: false,
            portal: String::new(),
            socks_port: 1080,
            prompt: None,
        }
    }
}
struct Runtime {
    snapshot: Snapshot,
    operation: u64,
    cancel: Arc<AtomicBool>,
    responses: Option<Sender<(String, String)>>,
    quitting: bool,
}
impl Default for Runtime {
    fn default() -> Self {
        Self {
            snapshot: Snapshot::default(),
            operation: 0,
            cancel: Arc::new(AtomicBool::new(false)),
            responses: None,
            quitting: false,
        }
    }
}
impl Runtime {
    fn update(&mut self, id: u64, edit: impl FnOnce(&mut Runtime)) -> Option<Snapshot> {
        if self.operation != id {
            return None;
        }
        edit(self);
        if self.cancel.load(Ordering::SeqCst) && self.snapshot.active {
            self.snapshot.state = "disconnecting".into();
            self.snapshot.message = "Отключение…".into();
            self.snapshot.prompt = None;
        }
        self.snapshot.revision += 1;
        Some(self.snapshot.clone())
    }
}
#[derive(Clone, Default)]
pub struct AppState {
    inner: Arc<Mutex<Runtime>>,
}

fn publish(app: &AppHandle, state: &AppState, id: u64, edit: impl FnOnce(&mut Runtime)) {
    let mut runtime = state.inner.lock().unwrap();
    let Some(snapshot) = runtime.update(id, edit) else {
        return;
    };
    let _ = app.emit("vpn://status", snapshot);
    drop(runtime);
    tray::refresh(app);
}
fn phase(app: &AppHandle, state: &AppState, id: u64, name: &str, message: &str) {
    publish(app, state, id, |r| {
        r.snapshot.state = name.into();
        r.snapshot.message = message.into();
    });
}
fn finish(
    app: &AppHandle,
    state: &AppState,
    id: u64,
    result: Result<(), String>,
    cleanup_required: bool,
) {
    publish(app, state, id, |r| {
        r.snapshot.active = false;
        r.snapshot.cleanup_required = cleanup_required;
        r.snapshot.prompt = None;
        r.responses = None;
        match result {
            Ok(()) => {
                r.snapshot.state = "idle".into();
                r.snapshot.message = "Не подключён".into();
            }
            Err(message) => {
                r.snapshot.state = "error".into();
                r.snapshot.message = message;
                r.quitting = false;
            }
        }
    });
    let exit = {
        let r = state.inner.lock().unwrap();
        r.operation == id && r.quitting && !r.snapshot.active && !r.snapshot.cleanup_required
    };
    if exit {
        app.exit(0);
    }
}

fn validate_response(value: &str) -> Result<(), String> {
    if value.is_empty()
        || value.len() > 4096
        || value.chars().any(|c| matches!(c, '\r' | '\n' | '\0'))
    {
        return Err("Введите непустое значение одной строкой".into());
    }
    Ok(())
}
fn validate_config(config: &ConnectionConfig) -> Result<(), String> {
    validate_token(&config.portal, "Хост")?;
    if config.portal.starts_with('-') {
        return Err("Некорректный адрес портала".into());
    }
    if config.socks_port == 0 {
        return Err("Порт должен быть от 1 до 65535".into());
    }
    Ok(())
}
fn write_response(stdin: &mut ChildStdin, value: &str) -> Result<(), String> {
    validate_response(value)?;
    stdin
        .write_all(format!("{value}\n").as_bytes())
        .and_then(|_| stdin.flush())
        .map_err(|_| "Не удалось передать ответ VPN".into())
}

#[tauri::command]
fn vpn_connect(
    app: AppHandle,
    state: State<'_, AppState>,
    settings: ConnectionConfig,
    auth: AuthInput,
) -> Result<(), String> {
    validate_config(&settings)?;
    validate_response(&auth.username)?;
    validate_response(&auth.password)?;
    if auth.username.len() > 255 {
        return Err("Логин слишком длинный".into());
    }
    let state = state.inner().clone();
    let (tx, rx) = mpsc::channel();
    let (id, cancel) = {
        let mut r = state.inner.lock().unwrap();
        if r.snapshot.active || r.snapshot.cleanup_required || r.quitting {
            return Err("Сначала завершите текущую сессию".into());
        }
        r.operation += 1;
        r.cancel = Arc::new(AtomicBool::new(false));
        r.responses = Some(tx);
        r.snapshot.active = true;
        r.snapshot.portal = settings.portal.clone();
        r.snapshot.socks_port = settings.socks_port;
        r.snapshot.prompt = None;
        (r.operation, r.cancel.clone())
    };
    phase(&app, &state, id, "preparing", "Подготовка подключения…");
    thread::spawn(move || {
        if !auth.remember_password {
            if let Err(error) = credentials::credential_delete(app.clone()) {
                finish(&app, &state, id, Err(error), false);
                return;
            }
        }
        match docker::prepare(settings.socks_port, &cancel) {
            Err(error) => {
                finish(
                    &app,
                    &state,
                    id,
                    if cancel.load(Ordering::SeqCst) {
                        Ok(())
                    } else {
                        Err(error)
                    },
                    false,
                );
            }
            Ok(()) if cancel.load(Ordering::SeqCst) => finish(&app, &state, id, Ok(()), false),
            Ok(()) => {
                phase(&app, &state, id, "connecting", "Подключение…");
                let result = run_session(&app, &state, id, &settings, auth, &cancel, rx);
                match result {
                    Ok(()) => finish(&app, &state, id, Ok(()), false),
                    Err((error, uncertain)) => finish(&app, &state, id, Err(error), uncertain),
                }
            }
        }
    });
    Ok(())
}

struct AutomaticAuth {
    input: AuthInput,
    username_sent: bool,
    password_sent: bool,
    gateway_started: bool,
}
impl AutomaticAuth {
    fn begin_gateway(&mut self) {
        // Selecting a gateway proves that portal authentication succeeded.
        // Allow one fresh submission there, but never reset for retries or MFA.
        if !self.gateway_started {
            self.gateway_started = true;
            self.username_sent = false;
            self.password_sent = false;
        }
    }
    fn take(&mut self, kind: &PromptKind) -> Option<String> {
        match kind {
            PromptKind::Username if !self.username_sent => {
                self.username_sent = true;
                Some(self.input.username.clone())
            }
            PromptKind::Password if !self.password_sent => {
                self.password_sent = true;
                Some(self.input.password.clone())
            }
            _ => None,
        }
    }
}
fn read_output(mut reader: impl Read + Send + 'static, tx: Sender<String>) {
    thread::spawn(move || {
        let mut bytes = [0; 4096];
        let mut pending = Vec::new();
        while let Ok(n) = reader.read(&mut bytes) {
            if n == 0 {
                break;
            }
            let text = decode_utf8_chunk(&mut pending, &bytes[..n]);
            if tx.send(text).is_err() {
                break;
            }
        }
    });
}
fn stop_session(child: &mut Child, stdin: &mut ChildStdin) -> Result<(), String> {
    let _ = stdin.write_all(disconnect_bytes());
    let _ = stdin.flush();
    let until = Instant::now() + Duration::from_secs(3);
    while Instant::now() < until {
        if child.try_wait().ok().flatten().is_some() {
            break;
        }
        thread::sleep(Duration::from_millis(100));
    }
    if docker::vpn_stopped().unwrap_or(false) {
        let _ = child.kill();
        let _ = child.wait();
        return Ok(());
    }
    docker::signal_stop();
    let until = Instant::now() + Duration::from_secs(4);
    while Instant::now() < until {
        if child.try_wait().ok().flatten().is_some() {
            break;
        }
        thread::sleep(Duration::from_millis(100));
    }
    if !docker::vpn_stopped().unwrap_or(false) {
        let _ = docker::force_stop();
    }
    let confirmed = docker::vpn_stopped().unwrap_or(false);
    let _ = child.kill();
    let _ = child.wait();
    if confirmed {
        Ok(())
    } else {
        Err(
            "Не удалось подтвердить отключение VPN. Проверьте Docker и повторите отключение."
                .into(),
        )
    }
}

fn run_session(
    app: &AppHandle,
    state: &AppState,
    id: u64,
    settings: &ConnectionConfig,
    auth: AuthInput,
    cancel: &AtomicBool,
    responses: Receiver<(String, String)>,
) -> Result<(), (String, bool)> {
    let exec = format!(
        "EXEC:\"openconnect --protocol=gp {}\",pty,stderr,setsid,ctty,sigint,sane,echo=0",
        settings.portal
    );
    let mut child = docker::command()
        .args(["exec", "-i", docker::CONTAINER, "socat", "-", &exec])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|_| ("Не удалось запустить OpenConnect".into(), false))?;
    let mut stdin = child.stdin.take().unwrap();
    let (tx, output) = mpsc::channel();
    read_output(child.stdout.take().unwrap(), tx.clone());
    read_output(child.stderr.take().unwrap(), tx);
    let mut automatic = AutomaticAuth {
        input: auth,
        username_sent: false,
        password_sent: false,
        gateway_started: false,
    };
    let mut analysis = String::new();
    let mut last_chunk = Instant::now();
    let mut pending: Option<Prompt> = None;
    let mut prompt_number = 0;
    let mut connected = false;
    let mut failure: Option<String> = None;
    loop {
        if cancel.load(Ordering::SeqCst) {
            return stop_session(&mut child, &mut stdin).map_err(|e| (e, true));
        }
        while let Ok((request, value)) = responses.try_recv() {
            if let Some(prompt) = pending.as_ref().filter(|p| p.request_id == request) {
                if let Err(error) = write_response(&mut stdin, &value) {
                    stop_session(&mut child, &mut stdin).map_err(|e| (e, true))?;
                    return Err((error, false));
                }
                match prompt.kind {
                    PromptKind::Username => automatic.input.username = value,
                    PromptKind::Password => automatic.input.password = value,
                    PromptKind::Gateway => automatic.begin_gateway(),
                    _ => {}
                }
                pending = None;
                analysis.clear();
                publish(app, state, id, |r| {
                    r.snapshot.prompt = None;
                    r.snapshot.message = "Подключение…".into();
                    r.snapshot.state = "connecting".into();
                });
            }
        }
        let mut read_any = false;
        while let Ok(text) = output.try_recv() {
            analysis.push_str(&text);
            read_any = true;
        }
        if read_any {
            last_chunk = Instant::now();
        }
        if analysis.len() > 32768 {
            analysis = analysis
                .chars()
                .rev()
                .take(8192)
                .collect::<String>()
                .chars()
                .rev()
                .collect();
        }
        // Wait for the end of a burst, including prompts without a final newline.
        if !analysis.is_empty() && last_chunk.elapsed() >= Duration::from_millis(80) {
            match parse_openconnect_status(&analysis) {
                Some(OpenConnectStatus::Connected) if !connected => {
                    connected = true;
                    failure = None;
                    pending = None;
                    let mut message = "Подключён".to_string();
                    if automatic.input.remember_password && !cancel.load(Ordering::SeqCst) {
                        if credentials::save(
                            app,
                            settings.portal.clone(),
                            automatic.input.username.clone(),
                            automatic.input.password.clone(),
                        )
                        .is_err()
                        {
                            message = "Подключён. Не удалось сохранить пароль.".into();
                        }
                    }
                    publish(app, state, id, |r| {
                        r.snapshot.state = "connected".into();
                        r.snapshot.message = message;
                        r.snapshot.prompt = None;
                    });
                }
                Some(OpenConnectStatus::Failed) => {
                    failure = Some("Ошибка авторизации или подключения к VPN".into());
                }
                _ => {}
            }
            let last_line = analysis
                .lines()
                .rev()
                .find(|l| !l.trim().is_empty())
                .unwrap_or("")
                .trim();
            if !connected && pending.is_none() && prompt_complete(last_line) {
                if let Some(kind) = detect_interactive_prompt(&analysis) {
                    if let Some(value) = automatic.take(&kind) {
                        if let Err(error) = write_response(&mut stdin, &value) {
                            stop_session(&mut child, &mut stdin).map_err(|e| (e, true))?;
                            return Err((error, false));
                        }
                    } else {
                        prompt_number += 1;
                        let message = match kind {
                            PromptKind::Username => "Повторите логин",
                            PromptKind::Password => "Повторите пароль",
                            PromptKind::Mfa => "Одноразовый код",
                            PromptKind::Challenge => "Ответ на запрос сервера",
                            PromptKind::Gateway => "Шлюз",
                            PromptKind::Text => "Ответ сервера",
                        };
                        let choices = if kind == PromptKind::Gateway {
                            parse_gateway_choices(last_line).unwrap_or_default()
                        } else {
                            Vec::new()
                        };
                        // Only generic server challenges are shown; redact credentials from them.
                        let message = if matches!(kind, PromptKind::Text | PromptKind::Challenge) {
                            let server_message = if kind == PromptKind::Challenge {
                                analysis
                                    .lines()
                                    .rev()
                                    .map(str::trim)
                                    .filter(|l| !l.is_empty())
                                    .nth(1)
                                    .unwrap_or(message)
                            } else {
                                last_line
                            };
                            server_message
                                .replace(&automatic.input.password, "••••")
                                .replace(&automatic.input.username, "••••")
                                .chars()
                                .take(240)
                                .collect()
                        } else {
                            message.to_string()
                        };
                        let prompt = Prompt {
                            request_id: format!("{id}-{prompt_number}"),
                            kind,
                            message,
                            choices,
                        };
                        pending = Some(prompt.clone());
                        publish(app, state, id, |r| {
                            r.snapshot.prompt = Some(prompt);
                            r.snapshot.state = "connecting".into();
                            r.snapshot.message = "Ожидается ввод".into();
                        });
                    }
                }
            }
            if prompt_complete(last_line) || parse_openconnect_status(&analysis).is_some() {
                analysis.clear();
            }
        }
        match child.try_wait() {
            Ok(Some(status)) => {
                if !docker::vpn_stopped().unwrap_or(false) {
                    stop_session(&mut child, &mut stdin).map_err(|e| (e, true))?;
                }
                if cancel.load(Ordering::SeqCst) {
                    return Ok(());
                }
                return if let Some(error) = failure {
                    Err((error, false))
                } else if status.success() {
                    Ok(())
                } else {
                    Err((
                        "OpenConnect завершился с ошибкой. Проверьте хост и данные входа.".into(),
                        false,
                    ))
                };
            }
            Err(_) => {
                stop_session(&mut child, &mut stdin).map_err(|e| (e, true))?;
                return Err(("Не удалось получить состояние VPN".into(), false));
            }
            Ok(None) => {}
        }
        thread::sleep(Duration::from_millis(30));
    }
}
fn prompt_complete(line: &str) -> bool {
    line.ends_with(':') || line.ends_with('?') || line.ends_with(']')
}

#[tauri::command]
fn vpn_status(state: State<'_, AppState>) -> Snapshot {
    state.inner.lock().unwrap().snapshot.clone()
}
#[tauri::command]
fn vpn_submit_prompt(
    state: State<'_, AppState>,
    request_id: String,
    value: String,
) -> Result<(), String> {
    validate_response(&value)?;
    let r = state.inner.lock().unwrap();
    let p = r
        .snapshot
        .prompt
        .as_ref()
        .filter(|p| p.request_id == request_id)
        .ok_or("Запрос уже завершён")?;
    if r.cancel.load(Ordering::SeqCst) {
        return Err("Подключение отменяется".into());
    }
    if !p.choices.is_empty() && !p.choices.contains(&value) {
        return Err("Выберите шлюз из списка".into());
    }
    r.responses
        .as_ref()
        .ok_or("Нет активной сессии")?
        .send((request_id, value))
        .map_err(|_| "Сессия завершилась".into())
}
#[tauri::command]
fn vpn_disconnect(app: AppHandle, state: State<'_, AppState>) {
    request_stop(&app, state.inner(), false);
}

pub(crate) fn request_stop(app: &AppHandle, state: &AppState, quit: bool) {
    let (id, cleanup, idle) = {
        let mut r = state.inner.lock().unwrap();
        r.quitting |= quit;
        if r.snapshot.active {
            r.cancel.store(true, Ordering::SeqCst);
            (r.operation, false, false)
        } else if r.snapshot.cleanup_required {
            r.snapshot.active = true;
            (r.operation, true, false)
        } else {
            (r.operation, false, true)
        }
    };
    if idle {
        if quit {
            app.exit(0);
        }
        return;
    }
    phase(app, state, id, "disconnecting", "Отключение…");
    if cleanup {
        let app = app.clone();
        let state = state.clone();
        thread::spawn(move || {
            docker::signal_stop();
            if !docker::vpn_stopped().unwrap_or(false) {
                let _ = docker::force_stop();
            }
            let stopped = docker::vpn_stopped().unwrap_or(false);
            finish(
                &app,
                &state,
                id,
                if stopped {
                    Ok(())
                } else {
                    Err("Не удалось подтвердить отключение VPN. Проверьте Docker.".into())
                },
                !stopped,
            );
        });
    }
}
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SocksStatus {
    port: u16,
    listening: bool,
}
#[tauri::command]
async fn socks_status(state: State<'_, AppState>) -> Result<SocksStatus, String> {
    let port = state.inner.lock().unwrap().snapshot.socks_port;
    tauri::async_runtime::spawn_blocking(move || SocksStatus {
        port,
        listening: docker::socks_probe(port).is_ok(),
    })
    .await
    .map_err(|e| e.to_string())
}

pub fn run() {
    #[cfg(debug_assertions)]
    eprintln!("GP Relay: initializing");
    let app = tauri::Builder::default()
        .plugin(tauri_plugin_single_instance::init(|app, _, _| {
            tray::show(app);
        }))
        .manage(AppState::default())
        .manage(tray::PanelState::default())
        .setup(|app| {
            #[cfg(debug_assertions)]
            eprintln!("GP Relay: creating tray");
            tray::setup(app.handle())?;
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            vpn_connect,
            vpn_disconnect,
            vpn_status,
            vpn_submit_prompt,
            socks_status,
            credentials::credential_load,
            credentials::credential_delete,
            tray::panel_hide,
            tray::panel_resize
        ])
        .on_window_event(|window, event| {
            tray::window_event(window, event);
        })
        .build(tauri::generate_context!())
        .expect("Не удалось запустить GP Relay");
    #[cfg(debug_assertions)]
    eprintln!("GP Relay: ready");
    app.run(|app, event| {
        if let tauri::RunEvent::ExitRequested { api, .. } = event {
            let state = app.state::<AppState>();
            let needs_cleanup = {
                let r = state.inner.lock().unwrap();
                r.snapshot.active || r.snapshot.cleanup_required
            };
            if needs_cleanup {
                api.prevent_exit();
                request_stop(app, &state, true);
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn automatic_auth_is_once_per_kind_and_authentication_stage() {
        let mut auth = AutomaticAuth {
            input: AuthInput {
                username: "u".into(),
                password: "p".into(),
                remember_password: false,
            },
            username_sent: false,
            password_sent: false,
            gateway_started: false,
        };
        assert_eq!(auth.take(&PromptKind::Username).as_deref(), Some("u"));
        assert!(auth.take(&PromptKind::Username).is_none());
        assert_eq!(auth.take(&PromptKind::Password).as_deref(), Some("p"));
        assert!(auth.take(&PromptKind::Password).is_none());
        assert!(auth.take(&PromptKind::Mfa).is_none());
        assert!(auth.take(&PromptKind::Challenge).is_none());
        assert!(auth.take(&PromptKind::Password).is_none());
        auth.begin_gateway();
        assert_eq!(auth.take(&PromptKind::Password).as_deref(), Some("p"));
        assert_eq!(auth.take(&PromptKind::Username).as_deref(), Some("u"));
        assert!(auth.take(&PromptKind::Password).is_none());
        auth.begin_gateway();
        assert!(auth.take(&PromptKind::Password).is_none());
    }
    #[test]
    fn config_rejects_zero_port_and_options() {
        for (portal, port, valid) in [
            ("gp.domru.ru", 1080, true),
            ("gp.domru.ru", 65535, true),
            ("gp.domru.ru", 0, false),
            ("--help", 1080, false),
            ("x;whoami", 1080, false),
        ] {
            assert_eq!(
                validate_config(&ConnectionConfig {
                    portal: portal.into(),
                    socks_port: port
                })
                .is_ok(),
                valid
            );
        }
    }
    #[test]
    fn responses_cannot_inject_a_second_line() {
        assert!(validate_response("a\nb").is_err());
        assert!(validate_response("secret").is_ok());
    }
    #[test]
    fn partial_prompts_are_not_submitted() {
        assert!(!prompt_complete("Passwo"));
        assert!(prompt_complete("Password:"));
    }
    #[test]
    fn cancellation_wins_over_late_connection_events() {
        let mut runtime = Runtime::default();
        runtime.operation = 7;
        runtime.snapshot.active = true;
        runtime.cancel.store(true, Ordering::SeqCst);
        let snapshot = runtime
            .update(7, |r| {
                r.snapshot.state = "connected".into();
            })
            .unwrap();
        assert_eq!(snapshot.state, "disconnecting");
        assert!(snapshot.prompt.is_none());
    }
    #[test]
    fn previous_session_cannot_overwrite_current_state() {
        let mut runtime = Runtime::default();
        runtime.operation = 2;
        assert!(runtime
            .update(1, |r| r.snapshot.state = "error".into())
            .is_none());
        assert_eq!(runtime.snapshot.state, "idle");
        assert_eq!(runtime.snapshot.revision, 0);
    }
}
