use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use serde::{Deserialize, Serialize};
mod docker;
use docker::{
    docker_ensure_image, docker_exec, docker_image_present, docker_vpn_status, socks_probe,
};
use std::fs;
use std::io::{self, Read, Write};
use std::process::{Child, ChildStdin, ExitStatus, Stdio};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tauri::{AppHandle, Emitter, Manager, State};

#[cfg(target_os = "windows")]
use std::os::windows::process::CommandExt;
#[cfg(target_os = "windows")]
use windows_sys::Win32::Foundation::LocalFree;
#[cfg(target_os = "windows")]
use windows_sys::Win32::Security::Cryptography::{
    CryptProtectData, CryptUnprotectData, CRYPTPROTECT_UI_FORBIDDEN, CRYPT_INTEGER_BLOB,
};

#[cfg(target_os = "windows")]
const CREATE_NO_WINDOW: u32 = 0x0800_0000;

const OUTPUT_EVENT: &str = "session-output";
const STATUS_EVENT: &str = "session-status";
/// Имя контейнера-релея: GUI поднимает его сам и в нём же запускает openconnect.
const RELAY_CONTAINER: &str = "gp-relay";
/// SOCKS5 даёт dante внутри контейнера: GUI порт не открывает и не закрывает.
const RELAY_SOCKS_PORT: u16 = 1080;
const CREDENTIAL_FILE: &str = "credentials.json";

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct StoredCredential {
    username: String,
    protected_password: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct CredentialPayload {
    username: String,
    password: String,
}

#[cfg(target_os = "windows")]
fn dpapi_protect(plaintext: &[u8]) -> Result<Vec<u8>, String> {
    let input = CRYPT_INTEGER_BLOB {
        cbData: plaintext.len().try_into().map_err(|_| "credential is too large")?,
        pbData: plaintext.as_ptr() as *mut u8,
    };
    let mut output = CRYPT_INTEGER_BLOB { cbData: 0, pbData: std::ptr::null_mut() };
    let ok = unsafe {
        CryptProtectData(
            &input,
            std::ptr::null(),
            std::ptr::null(),
            std::ptr::null(),
            std::ptr::null(),
            CRYPTPROTECT_UI_FORBIDDEN,
            &mut output,
        )
    };
    if ok == 0 {
        return Err(format!("DPAPI encryption failed: {}", std::io::Error::last_os_error()));
    }
    let bytes = unsafe { std::slice::from_raw_parts(output.pbData, output.cbData as usize).to_vec() };
    unsafe { LocalFree(output.pbData as *mut std::ffi::c_void) };
    Ok(bytes)
}

#[cfg(target_os = "windows")]
fn dpapi_unprotect(ciphertext: &[u8]) -> Result<Vec<u8>, String> {
    let input = CRYPT_INTEGER_BLOB {
        cbData: ciphertext.len().try_into().map_err(|_| "credential is too large")?,
        pbData: ciphertext.as_ptr() as *mut u8,
    };
    let mut output = CRYPT_INTEGER_BLOB { cbData: 0, pbData: std::ptr::null_mut() };
    let ok = unsafe {
        CryptUnprotectData(
            &input,
            std::ptr::null_mut(),
            std::ptr::null(),
            std::ptr::null(),
            std::ptr::null(),
            CRYPTPROTECT_UI_FORBIDDEN,
            &mut output,
        )
    };
    if ok == 0 {
        return Err(format!("DPAPI decryption failed: {}", std::io::Error::last_os_error()));
    }
    let bytes = unsafe { std::slice::from_raw_parts(output.pbData, output.cbData as usize).to_vec() };
    unsafe { LocalFree(output.pbData as *mut std::ffi::c_void) };
    Ok(bytes)
}

fn credential_path(app: &AppHandle) -> Result<std::path::PathBuf, String> {
    app.path()
        .app_data_dir()
        .map(|directory| directory.join(CREDENTIAL_FILE))
        .map_err(|error| format!("could not resolve app data directory: {error}"))
}

#[tauri::command]
fn credential_save(app: AppHandle, username: String, password: String) -> Result<(), String> {
    if username.trim().is_empty() || username.len() > 255 {
        return Err("username is invalid".into());
    }
    if password.is_empty() || password.len() > 4096 {
        return Err("password is invalid".into());
    }
    let path = credential_path(&app)?;
    let parent = path.parent().ok_or("credential directory is invalid")?;
    fs::create_dir_all(parent).map_err(|error| format!("could not create credential directory: {error}"))?;
    let protected_password = BASE64.encode(dpapi_protect(password.as_bytes())?);
    let record = StoredCredential { username, protected_password };
    let encoded = serde_json::to_vec(&record).map_err(|error| format!("could not encode credential: {error}"))?;
    fs::write(path, encoded).map_err(|error| format!("could not save credential: {error}"))
}

#[tauri::command]
fn credential_load(app: AppHandle) -> Result<Option<CredentialPayload>, String> {
    let path = credential_path(&app)?;
    let encoded = match fs::read(path) {
        Ok(encoded) => encoded,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(format!("could not read credential: {error}")),
    };
    let record: StoredCredential = serde_json::from_slice(&encoded)
        .map_err(|error| format!("could not decode credential: {error}"))?;
    let ciphertext = BASE64.decode(record.protected_password)
        .map_err(|error| format!("credential base64 is invalid: {error}"))?;
    let password = String::from_utf8(dpapi_unprotect(&ciphertext)?)
        .map_err(|_| "decrypted credential is not UTF-8".to_string())?;
    Ok(Some(CredentialPayload { username: record.username, password }))
}

#[tauri::command]
fn credential_delete(app: AppHandle) -> Result<(), String> {
    let path = credential_path(&app)?;
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(format!("could not delete credential: {error}")),
    }
}

/// Connection metadata only. Passwords and MFA codes are deliberately absent:
/// they are accepted only by `send_response`, and are never stored or passed
/// as process arguments. OpenConnect запускается внутри контейнера gp-relay,
/// поэтому из настроек остаётся только портал.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ConnectionConfig {
    pub portal: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SessionState {
    Idle,
    Starting,
    Running,
    Stopping,
    Exited,
    Failed,
    Cancelled,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SessionSnapshot {
    pub session_id: Option<u64>,
    pub state: SessionState,
    pub exit_code: Option<i32>,
    pub error: Option<String>,
    pub started_at: Option<u64>,
}

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SocksState {
    Stopped,
    Starting,
    Running,
    Stopping,
    Error,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SocksSnapshot {
    pub state: SocksState,
    pub pid: Option<u32>,
    pub port: u16,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct OutputEvent {
    session_id: u64,
    stream: OutputStream,
    text: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct LogPayload {
    level: String,
    message: String,
    timestamp: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct PromptPayload {
    request_id: String,
    kind: PromptKind,
    fields: Vec<PromptField>,
    message: String,
    /// Непустой список — UI показывает выпадающий список (например, выбор шлюза).
    choices: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct PromptField {
    kind: PromptKind,
    label: String,
    required: bool,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct VpnStatusPayload {
    state: String,
    message: Option<String>,
    portal: Option<String>,
    connected_at: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "snake_case")]
enum OutputStream {
    Stdout,
    Stderr,
}

struct Session {
    id: u64,
    child: Arc<Mutex<Child>>,
    stdin: Arc<Mutex<ChildStdin>>,
    snapshot: SessionSnapshot,
    portal: String,
    connected: bool,
    disconnect_state: DisconnectState,
    /// Values submitted through the interactive prompt are retained only in
    /// memory for PTY echo redaction. They are never persisted or used as
    /// process arguments.
    sensitive_inputs: Vec<String>,
}

#[derive(Default)]
struct InnerState {
    session: Option<Session>,
    next_id: u64,
    active_prompt: Option<PendingPrompt>,
    next_prompt_id: u64,
}

#[derive(Debug, Clone)]
struct PendingPrompt {
    request_id: String,
    kind: PromptKind,
    choices: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum PromptKind {
    Username,
    Password,
    Mfa,
    Gateway,
    Text,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DisconnectState {
    NotRequested,
    InterruptSent,
}

#[derive(Clone, Default)]
pub struct AppState {
    inner: Arc<Mutex<InnerState>>,
}

impl AppState {
    fn allocate_id(&self) -> u64 {
        let mut inner = self.inner.lock().expect("state mutex poisoned");
        inner.next_id = inner.next_id.saturating_add(1);
        if inner.next_id == 0 {
            inner.next_id = 1;
        }
        inner.next_id
    }
}

fn now_unix_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or_default()
}

fn idle_snapshot() -> SessionSnapshot {
    SessionSnapshot {
        session_id: None,
        state: SessionState::Idle,
        exit_code: None,
        error: None,
        started_at: None,
    }
}

fn emit_status(app: &AppHandle, snapshot: SessionSnapshot) {
    let _ = app.emit(STATUS_EVENT, snapshot);
}

fn emit_log(app: &AppHandle, level: &str, message: impl Into<String>) {
    let _ = app.emit(
        "vpn://log",
        LogPayload {
            level: level.to_string(),
            message: message.into(),
            timestamp: String::new(),
        },
    );
}

/// ASCII-поиск подстроки без учёта регистра (безопасен для UTF-8: возвращает
/// только валидные байтовые границы исходной строки).
fn find_ascii_ci(haystack: &str, needle: &str) -> Option<usize> {
    let h = haystack.as_bytes();
    let n = needle.as_bytes();
    if n.is_empty() || h.len() < n.len() {
        return None;
    }
    (0..=h.len() - n.len()).find(|&i| h[i..i + n.len()].eq_ignore_ascii_case(n))
}

/// Портал сам перечисляет шлюзы: "GATEWAY: [gp.domru.ru|gpm.domru.ru|gpo.domru.ru]:"
/// Возвращаем список для выпадающего списка в UI. Парсить ответ не нужно —
/// пользователь выбирает из того, что отдал портал.
fn parse_gateway_choices(text: &str) -> Option<Vec<String>> {
    let key_pos = find_ascii_ci(text, "gateway")?;
    let rest = &text[key_pos..];
    let open = rest.find('[')?;
    let close = rest[open + 1..].find(']')? + open + 1;
    let choices: Vec<String> = rest[open + 1..close]
        .split('|')
        .map(|item| item.trim().trim_matches(|c| c == '"' || c == '\'').to_string())
        .filter(|item| !item.is_empty() && item.len() <= 253)
        .collect();
    if choices.is_empty() {
        None
    } else {
        Some(choices)
    }
}

fn detect_prompt(text: &str) -> Option<PromptKind> {
    let lower = text.to_lowercase();
    if lower.contains("gateway:") || (lower.contains("select") && lower.contains("gateway")) {
        // "GATEWAY: [gp.domru.ru|gpm.domru.ru|gpo.domru.ru]:" — список шлюзов,
        // портал отдаёт его сам; выше в UI он превращается в выпадающий список.
        if parse_gateway_choices(text).is_some() {
            return Some(PromptKind::Gateway);
        }
    }
    if lower.contains("one-time")
        || lower.contains("one time")
        || lower.contains("otp")
        || lower.contains("verification code")
        || lower.contains("authentication code")
        || lower.contains("token code")
        || lower.contains("passcode")
        || lower.contains("mfa")
        || lower.contains("одноразов")
        || lower.contains("код подтверждения")
        || lower.contains("код:")
        || lower.contains("challenge:")
    {
        Some(PromptKind::Mfa)
    } else if lower.contains("password")
        || lower.contains("passphrase")
        || lower.contains("пароль")
    {
        Some(PromptKind::Password)
    } else if lower.contains("username")
        || lower.contains("user name")
        || lower.contains("логин")
    {
        Some(PromptKind::Username)
    } else if (lower.contains("authgroup") || lower.contains("auth group") || lower.contains("gateway"))
        && (lower.contains(':')
            || lower.contains("choose")
            || lower.contains("select")
            || lower.contains("enter")
            || lower.contains("please"))
    {
        // OpenConnect may ask for an authentication group or gateway. The
        // exact choices are portal-specific, so expose the prompt verbatim as
        // a generic text response.
        Some(PromptKind::Text)
    } else if lower.contains("(yes/no")
        || lower.contains("[yes/no")
        || lower.contains("do you want to continue(y/n)?")
        || lower.contains("reason for disconnect")
        || lower.contains("disconnect reason")
    {
        Some(PromptKind::Text)
    } else {
        None
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum OpenConnectStatus {
    Connected,
    Failed,
}

fn parse_openconnect_status(text: &str) -> Option<OpenConnectStatus> {
    let lower = text.to_lowercase();
    // Check failures first: "failed to establish ..." must not be mistaken
    // for the successful "established ..." substring.
    if lower.contains("authentication failed")
        || lower.contains("login failed")
        || (lower.contains("failed to connect")
            && !lower.contains("failed to connect esp tunnel; using https instead"))
        || lower.contains("could not connect")
        || lower.contains("unable to connect")
        || lower.contains("connection failed")
        || lower.contains("failed to establish")
    {
        return Some(OpenConnectStatus::Failed);
    }
    if lower.contains("esp session established")
        || lower.contains("established dtls connection")
        || lower.contains("vpn tunnel established")
        || lower.contains("vpn tunnel connected")
        || lower.contains("esp tunnel connected")
        || (lower.contains("configured as")
            && lower.contains("ssl connected")
            && lower.contains("esp established"))
        || lower.contains("connected as")
    {
        return Some(OpenConnectStatus::Connected);
    }
    None
}

fn disconnect_bytes() -> &'static [u8] {
    // socat runs openconnect in a PTY inside the container; ETX is therefore
    // the portable equivalent of pressing Ctrl-C in the foreground process.
    &[0x03]
}

fn redact_output(state: &AppState, session_id: u64, text: &str) -> String {
    let values = state
        .inner
        .lock()
        .ok()
        .and_then(|inner| {
            inner
                .session
                .as_ref()
                .filter(|session| session.id == session_id)
                .map(|session| session.sensitive_inputs.clone())
        })
        .unwrap_or_default();
    values.into_iter().filter(|value| !value.is_empty()).fold(
        text.to_string(),
        |redacted, value| redacted.replace(&value, "<redacted>"),
    )
}

fn remember_sensitive_input(state: &AppState, session_id: u64, value: &str) {
    if value.is_empty() {
        return;
    }
    if let Ok(mut inner) = state.inner.lock() {
        if let Some(session) = inner
            .session
            .as_mut()
            .filter(|session| session.id == session_id)
        {
            if !session.sensitive_inputs.iter().any(|known| known == value) {
                session.sensitive_inputs.push(value.to_string());
            }
        }
    }
}

fn prompt_label(kind: &PromptKind) -> &'static str {
    match kind {
        PromptKind::Username => "Имя пользователя GlobalProtect",
        PromptKind::Password => "Пароль GlobalProtect",
        PromptKind::Mfa => "Одноразовый код",
        PromptKind::Gateway => "Шлюз GlobalProtect",
        PromptKind::Text => "Ответ сервера",
    }
}

fn emit_frontend_status(
    app: &AppHandle,
    state: &str,
    session: Option<&Session>,
    message: Option<String>,
) {
    let payload = VpnStatusPayload {
        state: state.to_string(),
        message,
        portal: session.map(|s| s.portal.clone()),
        connected_at: None,
    };
    let _ = app.emit("vpn://status", payload);
}

fn notify_prompt(
    app: &AppHandle,
    state: &AppState,
    session_id: u64,
    kind: PromptKind,
    message: String,
    choices: Vec<String>,
) {
    let request_id = {
        let mut inner = match state.inner.lock() {
            Ok(inner) => inner,
            Err(_) => return,
        };
        let session_prefix = format!("{session_id}-");
        if inner
            .active_prompt
            .as_ref()
            .is_some_and(|prompt| prompt.request_id.starts_with(&session_prefix))
        {
            // PTY output may arrive in overlapping stdout/stderr fragments.
            // Keep the original request id stable until the user responds.
            return;
        }
        inner.next_prompt_id = inner.next_prompt_id.saturating_add(1);
        let id = format!("{session_id}-{}", inner.next_prompt_id);
        inner.active_prompt = Some(PendingPrompt {
            request_id: id.clone(),
            kind: kind.clone(),
            choices: choices.clone(),
        });
        id
    };
    let _ = app.emit(
        "vpn://prompt",
        PromptPayload {
            request_id,
            kind: kind.clone(),
            fields: vec![PromptField {
                kind: kind.clone(),
                label: prompt_label(&kind).to_string(),
                required: true,
            }],
            message,
            choices,
        },
    );
}

fn prompt_payload(pending: &PendingPrompt, message: String) -> PromptPayload {
    PromptPayload {
        request_id: pending.request_id.clone(),
        kind: pending.kind.clone(),
        fields: vec![PromptField {
            kind: pending.kind.clone(),
            label: prompt_label(&pending.kind).to_string(),
            required: true,
        }],
        message,
        choices: pending.choices.clone(),
    }
}

fn schedule_prompt_fallback(
    app: AppHandle,
    state: AppState,
    session_id: u64,
    kind: PromptKind,
    delay: Duration,
) {
    thread::spawn(move || {
        thread::sleep(delay);
        let should_prompt = state
            .inner
            .lock()
            .ok()
            .is_some_and(|inner| {
                inner.active_prompt.is_none()
                    && inner.session.as_ref().is_some_and(|session| {
                        session.id == session_id
                            && !session.connected
                            && session.disconnect_state == DisconnectState::NotRequested
                    })
            });
        if should_prompt {
            let message = format!("{} (резервный интерактивный запрос)", prompt_label(&kind));
            emit_log(&app, "info", message.clone());
            notify_prompt(&app, &state, session_id, kind, message, Vec::new());
        }
    });
}

#[tauri::command]
fn vpn_current_prompt(state: State<'_, AppState>) -> Result<Option<PromptPayload>, String> {
    let inner = state
        .inner
        .lock()
        .map_err(|_| "state mutex poisoned".to_string())?;
    Ok(inner.active_prompt.as_ref().map(|pending| {
        prompt_payload(pending, prompt_label(&pending.kind).to_string())
    }))
}

fn validate_token(value: &str, field: &str) -> Result<(), String> {
    if value.is_empty() {
        return Err(format!("{field} must not be empty"));
    }
    if value.len() > 255 {
        return Err(format!("{field} is too long"));
    }
    // The portal is sent to a remote shell as one command token. Keep it
    // strict so metadata cannot become shell syntax.
    if !value
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || b"._:/-[]".contains(&byte))
    {
        return Err(format!("{field} contains unsupported characters"));
    }
    Ok(())
}

fn write_line(stdin: &Arc<Mutex<ChildStdin>>, line: &str) -> Result<(), String> {
    // A response is exactly one line. This prevents the GUI from accidentally
    // submitting a second remote-shell command.
    if line
        .chars()
        .any(|character| matches!(character, '\r' | '\n' | '\0'))
    {
        return Err("response must be a single line".into());
    }
    if line.len() > 4096 {
        return Err("response is too long".into());
    }
    write_bytes(stdin, format!("{line}\n").as_bytes())
}

fn write_bytes(stdin: &Arc<Mutex<ChildStdin>>, bytes: &[u8]) -> Result<(), String> {
    let mut writer = stdin
        .lock()
        .map_err(|_| "stdin mutex poisoned".to_string())?;
    writer
        .write_all(bytes)
        .and_then(|_| writer.flush())
        .map_err(|error| format!("could not write to process stdin: {error}"))
}

fn decode_utf8_chunk(pending: &mut Vec<u8>, chunk: &[u8]) -> String {
    pending.extend_from_slice(chunk);
    let mut output = String::new();
    loop {
        match std::str::from_utf8(pending) {
            Ok(text) => {
                output.push_str(text);
                pending.clear();
                break;
            }
            Err(error) => {
                let valid = error.valid_up_to();
                if valid > 0 {
                    output.push_str(std::str::from_utf8(&pending[..valid]).unwrap_or_default());
                    pending.drain(..valid);
                }
                match error.error_len() {
                    Some(invalid) => {
                        output.push('\u{fffd}');
                        pending.drain(..invalid);
                    }
                    None => break,
                }
            }
        }
    }
    output
}

fn spawn_output_reader<R: Read + Send + 'static>(
    app: AppHandle,
    state: AppState,
    session_id: u64,
    mut reader: R,
    stream: OutputStream,
) {
    thread::spawn(move || {
        let mut buffer = [0_u8; 4096];
        // Pipe reads may split both UTF-8 text and prompt words at arbitrary
        // byte boundaries. Keep a small rolling window for detection instead
        // of assuming that e.g. `Логин:` arrives in one `read()` call.
        let mut analysis_text = String::new();
        let mut pending_utf8 = Vec::new();
        loop {
            match reader.read(&mut buffer) {
                Ok(0) => {
                    if !pending_utf8.is_empty() {
                        emit_log(
                            &app,
                            "info",
                            String::from_utf8_lossy(&pending_utf8).into_owned(),
                        );
                    }
                    break;
                }
                Ok(size) => {
                    let raw_text = decode_utf8_chunk(&mut pending_utf8, &buffer[..size]);
                    if raw_text.is_empty() {
                        continue;
                    }
                    let text = redact_output(&state, session_id, &raw_text);
                    let _ = app.emit(
                        OUTPUT_EVENT,
                        OutputEvent {
                            session_id,
                            stream: stream.clone(),
                            text: text.clone(),
                        },
                    );
                    emit_log(&app, "info", text.clone());

                    analysis_text.push_str(&raw_text);
                    if analysis_text.chars().count() > 8192 {
                        analysis_text = analysis_text
                            .chars()
                            .rev()
                            .take(4096)
                            .collect::<String>()
                            .chars()
                            .rev()
                            .collect();
                    }
                    let prompt = detect_prompt(&analysis_text);
                    let status = parse_openconnect_status(&analysis_text);
                    if let Some(kind) = prompt {
                        let choices = if kind == PromptKind::Gateway {
                            parse_gateway_choices(&analysis_text).unwrap_or_default()
                        } else {
                            Vec::new()
                        };
                        let message = if kind == PromptKind::Text {
                            text.clone()
                        } else if kind == PromptKind::Gateway {
                            format!(
                                "{}: выберите шлюз из списка, который предложил портал",
                                prompt_label(&kind)
                            )
                        } else {
                            prompt_label(&kind).to_string()
                        };
                        notify_prompt(&app, &state, session_id, kind, message, choices);
                        // Do not rediscover the previous prompt after its
                        // response clears `active_prompt`.
                        analysis_text.clear();
                    }
                    match status {
                        Some(OpenConnectStatus::Connected) => {
                            if let Ok(mut inner) = state.inner.lock() {
                                if let Some(session) = inner
                                    .session
                                    .as_mut()
                                    .filter(|session| session.id == session_id)
                                {
                                    session.connected = true;
                                }
                                emit_frontend_status(
                                    &app,
                                    "connected",
                                    inner.session.as_ref(),
                                    Some("OpenConnect подключён".into()),
                                );
                            }
                        }
                        Some(OpenConnectStatus::Failed) => {
                            if let Ok(mut inner) = state.inner.lock() {
                                if let Some(session) = inner
                                    .session
                                    .as_mut()
                                    .filter(|session| session.id == session_id)
                                {
                                    session.connected = false;
                                    session.snapshot.state = SessionState::Failed;
                                    session.snapshot.error =
                                        Some("OpenConnect сообщил об ошибке подключения".into());
                                }
                                emit_frontend_status(
                                    &app,
                                    "error",
                                    inner.session.as_ref(),
                                    Some("OpenConnect сообщил об ошибке подключения".into()),
                                );
                            }
                        }
                        None => {}
                    }
                }
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(error) => {
                    let _ = app.emit(
                        OUTPUT_EVENT,
                        OutputEvent {
                            session_id,
                            stream: stream.clone(),
                            text: format!("\n[stream read error: {error}]\n"),
                        },
                    );
                    break;
                }
            }
        }
    });
}

fn cleanup_runtime_children(state: &AppState) {
    let session_child = match state.inner.lock() {
        Ok(mut inner) => {
            inner.active_prompt = None;
            inner.session.take().map(|session| session.child)
        }
        Err(_) => return,
    };
    if let Some(child) = session_child {
        let _ = child
            .lock()
            .ok()
            .and_then(|mut process| process.kill().ok());
    }
}

fn spawn_waiter(app: AppHandle, state: AppState, session_id: u64, child: Arc<Mutex<Child>>) {
    thread::spawn(move || {
        let result = wait_for_child(&child);

        let disconnecting = state
            .inner
            .lock()
            .ok()
            .and_then(|inner| {
                inner
                    .session
                    .as_ref()
                    .filter(|session| session.id == session_id)
                    .map(|session| session.disconnect_state != DisconnectState::NotRequested)
            })
            .unwrap_or(false);

        let (snapshot, state_name, message) = match &result {
            Ok(status) => (SessionSnapshot {
                session_id: Some(session_id),
                state: SessionState::Exited,
                exit_code: status.code(),
                error: None,
                started_at: None,
            }, if disconnecting {
                "idle"
            } else if status.success() {
                "idle"
            } else {
                "error"
            }, if disconnecting {
                "VPN отключён"
            } else if status.success() {
                "OpenConnect завершён"
            } else {
                "OpenConnect завершился с ошибкой"
            }),
            Err(error) => (SessionSnapshot {
                session_id: Some(session_id),
                state: SessionState::Failed,
                exit_code: None,
                error: Some(error.clone()),
                started_at: None,
            }, "error", "Сессия OpenConnect завершилась с ошибкой"),
        };
        emit_status(&app, snapshot);
        emit_frontend_status(&app, state_name, None, Some(message.into()));

        if let Ok(mut inner) = state.inner.lock() {
            if inner
                .session
                .as_ref()
                .is_some_and(|session| session.id == session_id)
            {
                inner.session = None;
            }
        }
    });
}

fn spawn_disconnect_cleanup(app: AppHandle, child: Arc<Mutex<Child>>, session_id: u64) {
    thread::spawn(move || {
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            let exited = child
                .lock()
                .ok()
                .and_then(|mut process| process.try_wait().ok())
                .flatten()
                .is_some();
            if exited {
                return;
            }
            if Instant::now() >= deadline {
                if let Ok(mut process) = child.lock() {
                    if let Err(error) = process.kill() {
                        emit_log(
                            &app,
                            "error",
                            format!("Не удалось завершить docker exec после Ctrl-C: {error}"),
                        );
                    } else {
                        emit_log(
                            &app,
                            "warn",
                            format!("Сеанс {session_id} принудительно завершён после Ctrl-C"),
                        );
                    }
                }
                return;
            }
            thread::sleep(Duration::from_millis(100));
        }
    });
}

/// Polling keeps the child mutex available for `cancel`. Holding it
/// during `Child::wait` would make a kill request wait forever.
fn wait_for_child(child: &Arc<Mutex<Child>>) -> Result<ExitStatus, String> {
    loop {
        let status = child
            .lock()
            .map_err(|_| "child mutex poisoned".to_string())?
            .try_wait()
            .map_err(|error| error.to_string())?;
        if let Some(status) = status {
            return Ok(status);
        }
        thread::sleep(Duration::from_millis(100));
    }
}

#[tauri::command]
fn start_connection(
    app: AppHandle,
    state: State<'_, AppState>,
    config: ConnectionConfig,
) -> Result<SessionSnapshot, String> {
    validate_token(&config.portal, "portal")?;
    {
        let inner = state
            .inner
            .lock()
            .map_err(|_| "state mutex poisoned".to_string())?;
        if inner.session.is_some() {
            return Err("VPN сессия уже запущена".into());
        }
    }

    // Docker-путь: openconnect запускается прямо в контейнере, PTY внутри даёт
    // socat (наружу он торчит обычными пайпами — то, что нужно GUI). sshd и
    // ssh.exe в схеме больше не участвуют.
    let mut command = std::process::Command::new("docker");
    #[cfg(target_os = "windows")]
    command.creation_flags(CREATE_NO_WINDOW);
    command
        .arg("exec")
        .arg("-i")
        .arg(RELAY_CONTAINER)
        .arg("socat")
        .arg("-")
        .arg(format!(
            "EXEC:\"openconnect --protocol=gp {}\",pty,stderr,sane",
            config.portal
        ))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    let mut child = command
        .spawn()
        .map_err(|error| format!("could not start docker exec: {error}"))?;
    let stdin = child.stdin.take().ok_or("docker stdin is unavailable")?;
    let stdout = child.stdout.take().ok_or("docker stdout is unavailable")?;
    let stderr = child.stderr.take().ok_or("docker stderr is unavailable")?;
    let id = state.allocate_id();
    let child = Arc::new(Mutex::new(child));
    let stdin = Arc::new(Mutex::new(stdin));
    let snapshot = SessionSnapshot {
        session_id: Some(id),
        state: SessionState::Starting,
        exit_code: None,
        error: None,
        started_at: Some(now_unix_seconds()),
    };
    let app_state = state.inner.clone();
    {
        let mut inner = app_state
            .lock()
            .map_err(|_| "state mutex poisoned".to_string())?;
        if inner.session.is_some() {
            let _ = child
                .lock()
                .ok()
                .and_then(|mut process| process.kill().ok());
            return Err("VPN сессия уже запущена".into());
        }
        inner.session = Some(Session {
            id,
            child: Arc::clone(&child),
            stdin: Arc::clone(&stdin),
            snapshot: snapshot.clone(),
            portal: config.portal.clone(),
            connected: false,
            disconnect_state: DisconnectState::NotRequested,
            sensitive_inputs: Vec::new(),
        });
    }

    let reader_state = AppState {
        inner: state.inner.clone(),
    };
    spawn_output_reader(
        app.clone(),
        reader_state.clone(),
        id,
        stdout,
        OutputStream::Stdout,
    );
    spawn_output_reader(app.clone(), reader_state, id, stderr, OutputStream::Stderr);
    spawn_waiter(
        app.clone(),
        AppState {
            inner: state.inner.clone(),
        },
        id,
        child,
    );

    // Портал уже в argv docker exec — openconnect стартует сразу в PTY контейнера,
    // никакой команды в stdin отправлять не нужно. Всё, что печатает openconnect
    // (запросы логина/пароля/OTP), приходит на stdout и обрабатывается как раньше.
    let running = SessionSnapshot {
        state: SessionState::Running,
        ..snapshot
    };
    if let Ok(mut inner) = state.inner.lock() {
        if let Some(session) = inner.session.as_mut().filter(|session| session.id == id) {
            session.snapshot = running.clone();
        }
    }
    emit_status(&app, running.clone());
    if let Ok(inner) = state.inner.lock() {
        emit_frontend_status(
            &app,
            "connecting",
            inner.session.as_ref(),
            Some("Ожидаем ответ GlobalProtect".into()),
        );
    }
    schedule_prompt_fallback(
        app,
        AppState { inner: state.inner.clone() },
        id,
        PromptKind::Username,
        Duration::from_millis(1200),
    );
    Ok(running)
}

#[tauri::command]
fn send_response(state: State<'_, AppState>, response: String) -> Result<(), String> {
    let inner = state
        .inner
        .lock()
        .map_err(|_| "state mutex poisoned".to_string())?;
    let session = inner.session.as_ref().ok_or("нет активной VPN-сессии")?;
    let session_id = session.id;
    let stdin = Arc::clone(&session.stdin);
    drop(inner);
    remember_sensitive_input(&AppState { inner: state.inner.clone() }, session_id, &response);
    write_line(&stdin, &response)
}

#[tauri::command]
fn query_status(state: State<'_, AppState>) -> Result<SessionSnapshot, String> {
    let inner = state
        .inner
        .lock()
        .map_err(|_| "state mutex poisoned".to_string())?;
    Ok(inner
        .session
        .as_ref()
        .map(|session| session.snapshot.clone())
        .unwrap_or_else(idle_snapshot))
}

#[tauri::command]
fn request_status(state: State<'_, AppState>) -> Result<(), String> {
    let inner = state
        .inner
        .lock()
        .map_err(|_| "state mutex poisoned".to_string())?;
    inner.session.as_ref().ok_or("нет активной VPN-сессии")?;
    // OpenConnect occupies the foreground PTY, so a status command cannot be
    // injected into it. `vpn_status` is derived from its output instead.
    Ok(())
}

#[tauri::command]
fn query_details(state: State<'_, AppState>) -> Result<(), String> {
    let inner = state
        .inner
        .lock()
        .map_err(|_| "state mutex poisoned".to_string())?;
    inner.session.as_ref().ok_or("нет активной VPN-сессии")?;
    // Details are intentionally metadata-only in this mode; sending a shell
    // command would corrupt the foreground OpenConnect input stream.
    Ok(())
}

#[tauri::command]
fn disconnect(app: AppHandle, state: State<'_, AppState>) -> Result<(), String> {
    let (session_id, stdin, child, snapshot) = {
        let mut inner = state
            .inner
            .lock()
            .map_err(|_| "state mutex poisoned".to_string())?;
        let session = inner.session.as_mut().ok_or("нет активной VPN-сессии")?;
        if session.disconnect_state != DisconnectState::NotRequested {
            return Err("disconnect is already in progress".into());
        }
        // Mark this before writing so repeated clicks cannot send multiple
        // interrupts. The remote shell wrapper exits after openconnect exits.
        session.disconnect_state = DisconnectState::InterruptSent;
        let mut snapshot = session.snapshot.clone();
        snapshot.state = SessionState::Stopping;
        session.snapshot = snapshot.clone();
        (
            session.id,
            Arc::clone(&session.stdin),
            Arc::clone(&session.child),
            snapshot,
        )
    };

    if let Err(error) = write_bytes(&stdin, disconnect_bytes()) {
        if let Ok(mut inner) = state.inner.lock() {
            if let Some(session) = inner
                .session
                .as_mut()
                .filter(|session| session.id == session_id)
            {
                session.disconnect_state = DisconnectState::NotRequested;
            }
        }
        return Err(error);
    }
    emit_status(&app, snapshot);
    spawn_disconnect_cleanup(app, child, session_id);
    Ok(())
}

#[tauri::command]
fn cancel(app: AppHandle, state: State<'_, AppState>) -> Result<(), String> {
    let session = {
        let mut inner = state
            .inner
            .lock()
            .map_err(|_| "state mutex poisoned".to_string())?;
        inner.active_prompt = None;
        inner.session.take()
    };
    let session = session.ok_or("нет активной VPN-сессии")?;
    session
        .child
        .lock()
        .map_err(|_| "child mutex poisoned".to_string())?
        .kill()
        .map_err(|error| format!("could not cancel docker exec: {error}"))?;
    emit_status(
        &app,
        SessionSnapshot {
            session_id: Some(session.id),
            state: SessionState::Cancelled,
            exit_code: None,
            error: None,
            started_at: session.snapshot.started_at,
        },
    );
    Ok(())
}

/// SOCKS5 теперь даёт dante внутри контейнера gp-relay. Отдельного процесса на
/// стороне Windows нет: команда оставлена ради фронтенда и возвращает
/// снимок «порт 1080, управляется контейнером».
#[tauri::command]
fn socks_status(_state: State<'_, AppState>) -> Result<SocksSnapshot, String> {
    Ok(relay_socks_snapshot())
}

/// Остановить прокси можно только вместе с контейнером, поэтому команда лишь
/// повторяет текущий снимок состояния.
#[tauri::command]
fn socks_stop(_state: State<'_, AppState>) -> Result<SocksSnapshot, String> {
    Ok(relay_socks_snapshot())
}

fn relay_socks_snapshot() -> SocksSnapshot {
    let container_running = docker_exec(vec![
        "inspect".into(),
        "-f".into(),
        "{{.State.Running}}".into(),
        RELAY_CONTAINER.into(),
    ])
    .map(|output| output.trim() == "true")
    .unwrap_or(false);
    SocksSnapshot {
        state: if container_running {
            SocksState::Running
        } else {
            SocksState::Stopped
        },
        // PID процесса внутри контейнера GUI не знает и им не управляет.
        pid: None,
        // Наружу порт публикует контейнер: -p 1080:1080.
        port: RELAY_SOCKS_PORT,
        error: None,
    }
}

#[tauri::command]
fn vpn_connect(
    app: AppHandle,
    state: State<'_, AppState>,
    settings: ConnectionConfig,
) -> Result<SessionSnapshot, String> {
    start_connection(app, state, settings)
}

#[tauri::command]
fn vpn_status(state: State<'_, AppState>) -> Result<VpnStatusPayload, String> {
    let inner = state
        .inner
        .lock()
        .map_err(|_| "state mutex poisoned".to_string())?;
    let (state_name, message) = if inner.session.as_ref().is_some_and(|s| s.connected) {
        ("connected", Some("OpenConnect подключён".into()))
    } else {
        match inner.session.as_ref().map(|s| &s.snapshot.state) {
            None => ("idle", None),
            Some(SessionState::Starting) => ("connecting", Some("Запускаем сессию OpenConnect".into())),
            Some(SessionState::Running) => (
                "connecting",
                Some("Ожидаем аутентификацию OpenConnect".into()),
            ),
            Some(SessionState::Stopping) => {
                ("disconnecting", Some("Отключаем OpenConnect".into()))
            }
            Some(SessionState::Exited | SessionState::Cancelled) => ("idle", None),
            Some(SessionState::Failed) => {
                ("error", Some("Сессия OpenConnect завершилась с ошибкой".into()))
            }
            Some(SessionState::Idle) => ("idle", None),
        }
    };
    Ok(VpnStatusPayload {
        state: state_name.to_string(),
        message,
        portal: inner.session.as_ref().map(|s| s.portal.clone()),
        connected_at: None,
    })
}

#[tauri::command]
fn vpn_disconnect(app: AppHandle, state: State<'_, AppState>) -> Result<(), String> {
    disconnect(app, state)
}

#[tauri::command]
fn vpn_submit_prompt(
    state: State<'_, AppState>,
    request_id: String,
    values: serde_json::Value,
) -> Result<(), String> {
    let (stdin, kind) = {
        let mut inner = state
            .inner
            .lock()
            .map_err(|_| "state mutex poisoned".to_string())?;
        let pending = inner.active_prompt.take().ok_or("no active prompt")?;
        if pending.request_id != request_id {
            inner.active_prompt = Some(pending);
            return Err("prompt is stale".into());
        }
        let session = inner.session.as_ref().ok_or("нет активной VPN-сессии")?;
        (Arc::clone(&session.stdin), pending.kind)
    };
    let key = match kind {
        PromptKind::Username => "username",
        PromptKind::Password => "password",
        PromptKind::Mfa => "mfa",
        PromptKind::Gateway => "gateway",
        PromptKind::Text => "text",
    };
    let value = values
        .get(key)
        .and_then(serde_json::Value::as_str)
        .or_else(|| {
            values
                .as_object()
                .and_then(|object| object.values().next())
                .and_then(serde_json::Value::as_str)
        })
        .ok_or("prompt response must contain a text value")?;
    // `value` is never logged or inserted into a process argument.
    let session_id = {
        let inner = state
            .inner
            .lock()
            .map_err(|_| "state mutex poisoned".to_string())?;
        inner
            .session
            .as_ref()
            .ok_or("нет активной VPN-сессии")?
            .id
    };
    remember_sensitive_input(&AppState { inner: state.inner.clone() }, session_id, value);
    write_line(&stdin, value)
}

#[tauri::command]
fn vpn_cancel_prompt(
    app: AppHandle,
    state: State<'_, AppState>,
    request_id: String,
) -> Result<(), String> {
    {
        let inner = state
            .inner
            .lock()
            .map_err(|_| "state mutex poisoned".to_string())?;
        if inner
            .active_prompt
            .as_ref()
            .map_or(true, |prompt| prompt.request_id != request_id)
        {
            return Err("prompt is stale".into());
        }
    }
    cancel(app, state)
}

pub fn run() {
    let app = tauri::Builder::default()
        .manage(AppState::default())
        .invoke_handler(tauri::generate_handler![
            start_connection,
            send_response,
            query_status,
            request_status,
            query_details,
            disconnect,
            cancel,
            socks_status,
            socks_stop,
            docker_exec,
            socks_probe,
            docker_vpn_status,
            docker_image_present,
            docker_ensure_image,
            vpn_connect,
            vpn_status,
            vpn_disconnect,
            vpn_submit_prompt,
            vpn_cancel_prompt,
            vpn_current_prompt,
            credential_save,
            credential_load,
            credential_delete
        ])
        .build(tauri::generate_context!())
        .expect("error while building GlobalProtect Remote GUI");
    app.run(|app_handle, event| {
        if matches!(event, tauri::RunEvent::Exit | tauri::RunEvent::ExitRequested { .. }) {
            let state = app_handle.state::<AppState>();
            cleanup_runtime_children(&state);
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_openconnect_prompt_variants() {
        assert_eq!(detect_prompt("Username:"), Some(PromptKind::Username));
        assert_eq!(detect_prompt("Логин:"), Some(PromptKind::Username));
        assert_eq!(detect_prompt("Password:"), Some(PromptKind::Password));
        assert_eq!(detect_prompt("Пароль:"), Some(PromptKind::Password));
        assert_eq!(detect_prompt("Enter OTP:"), Some(PromptKind::Mfa));
        assert_eq!(detect_prompt("Введите одноразовый код:"), Some(PromptKind::Mfa));
        assert_eq!(detect_prompt("Challenge:"), Some(PromptKind::Mfa));
        assert_eq!(detect_prompt("AuthGroup:"), Some(PromptKind::Text));
        assert_eq!(detect_prompt("Choose gateway:"), Some(PromptKind::Text));
    }

    #[test]
    fn detects_cyrillic_prompt_split_at_every_utf8_byte() {
        let mut pending = Vec::new();
        let mut decoded = String::new();
        for byte in "Логин:".as_bytes() {
            decoded.push_str(&decode_utf8_chunk(&mut pending, &[*byte]));
        }
        assert!(pending.is_empty());
        assert_eq!(decoded, "Логин:");
        assert_eq!(detect_prompt(&decoded), Some(PromptKind::Username));
    }

    #[test]
    fn repeated_password_and_mfa_prompts_remain_classifiable() {
        assert_eq!(detect_prompt("Пароль:"), Some(PromptKind::Password));
        assert_eq!(detect_prompt("Пароль:"), Some(PromptKind::Password));
        assert_eq!(detect_prompt("Введите одноразовый код:"), Some(PromptKind::Mfa));
        assert_eq!(detect_prompt("Введите новый одноразовый код:"), Some(PromptKind::Mfa));
        assert_eq!(detect_prompt("Last login: Sat Sep 12 19:51:28 2026"), None);
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn dpapi_round_trip_is_bound_to_current_windows_user() {
        let plaintext = b"gp-relay-test-secret";
        let protected = dpapi_protect(plaintext).expect("DPAPI protect");
        assert_ne!(protected, plaintext);
        assert_eq!(dpapi_unprotect(&protected).expect("DPAPI unprotect"), plaintext);
    }

    #[test]
    fn parses_openconnect_status_from_realistic_output() {
        assert_eq!(
            parse_openconnect_status("Established DTLS connection. ESP session established"),
            Some(OpenConnectStatus::Connected)
        );
        assert_eq!(
            parse_openconnect_status("Authentication failed"),
            Some(OpenConnectStatus::Failed)
        );
        assert_eq!(
            parse_openconnect_status("Failed to establish DTLS connection"),
            Some(OpenConnectStatus::Failed)
        );
        assert_eq!(
            parse_openconnect_status("Failed to connect ESP tunnel; using HTTPS instead."),
            None
        );
        assert_eq!(
            parse_openconnect_status("ESP tunnel connected; exiting HTTPS mainloop."),
            Some(OpenConnectStatus::Connected)
        );
        assert_eq!(
            parse_openconnect_status("Configured as 10.0.0.1, with SSL connected and ESP established"),
            Some(OpenConnectStatus::Connected)
        );
        assert_eq!(parse_openconnect_status("POST https://portal/"), None);
    }

    #[test]
    fn disconnect_is_a_single_ctrl_c_byte() {
        assert_eq!(disconnect_bytes(), &[0x03]);
    }

    #[test]
    fn portal_token_rejects_shell_metacharacters() {
        assert_eq!(validate_token("gp.domru.ru", "portal"), Ok(()));
        assert!(validate_token("", "portal").is_err());
        assert!(validate_token("gp.domru.ru; rm -rf /", "portal").is_err());
    }

    #[test]
    fn parses_gateway_choice_list_from_portal_output() {
        let output = "Portal reports GlobalProtect version 6.3.3-828; we will report the same client version.\n\
            Portal set HIP report interval to 60 minutes).\n\
            3 gateway servers available: gp.domru.ru (gp.domru.ru) gpm.domru.ru (gpm.domru.ru) gpo.domru.ru (gpo.domru.ru)\n\
            Please select GlobalProtect gateway.\n\
            GATEWAY: [gp.domru.ru|gpm.domru.ru|gpo.domru.ru]:";
        assert_eq!(
            parse_gateway_choices(output),
            Some(vec![
                "gp.domru.ru".to_string(),
                "gpm.domru.ru".to_string(),
                "gpo.domru.ru".to_string()
            ])
        );
        assert_eq!(detect_prompt(output), Some(PromptKind::Gateway));
    }

    #[test]
    fn gateway_parser_ignores_plain_hostname_mentions() {
        assert_eq!(parse_gateway_choices("Connected to gp.domru.ru:443"), None);
        assert_eq!(parse_gateway_choices("GATEWAY: [single.host]:"), Some(vec!["single.host".to_string()]));
        // Юникод в выводе не должен ломать разбор списка.
        assert_eq!(
            parse_gateway_choices("Пожалуйста, выберите шлюз.\nGATEWAY: [a.example|b.example]:"),
            Some(vec!["a.example".to_string(), "b.example".to_string()])
        );
    }
}
