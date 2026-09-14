use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use serde::{Deserialize, Serialize};
use std::fs;
use std::io::{self, Read, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, ExitStatus, Stdio};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tauri::{AppHandle, Emitter, Manager, State};

#[cfg(target_os = "windows")]
use std::os::windows::process::CommandExt;
#[cfg(target_os = "windows")]
use std::os::windows::ffi::OsStringExt;
#[cfg(target_os = "windows")]
use windows_sys::Win32::Foundation::{CloseHandle, LocalFree};
#[cfg(target_os = "windows")]
use windows_sys::Win32::Security::Cryptography::{
    CryptProtectData, CryptUnprotectData, CRYPTPROTECT_UI_FORBIDDEN, CRYPT_INTEGER_BLOB,
};
#[cfg(target_os = "windows")]
use windows_sys::Win32::System::Threading::{
    OpenProcess, QueryFullProcessImageNameW, PROCESS_QUERY_LIMITED_INFORMATION,
};

#[cfg(target_os = "windows")]
const CREATE_NO_WINDOW: u32 = 0x0800_0000;
#[cfg(target_os = "windows")]
const CREATE_NEW_PROCESS_GROUP: u32 = 0x0000_0200;

const OUTPUT_EVENT: &str = "ssh-output";
const STATUS_EVENT: &str = "session-status";
const DEFAULT_VM_SSH_USER: &str = "vpn";
const DEFAULT_VM_IDENTITY_FILE: &str = r"vm\ssh\gp-relay_ed25519";
const DEFAULT_VM_KNOWN_HOSTS: &str = r"vm\ssh\known_hosts";
const GP_RELAY_VM_NAME: &str = "gp-relay";
const GP_RELAY_VM_UUID: &str = "693e96f2-5c89-4d8c-8f3e-e384dc948042";
const GP_RELAY_PID_FILE: &str = "gp-relay.pid";
const DEFAULT_SOCKS_PORT: u16 = 1081;
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
/// as process arguments.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ConnectionConfig {
    pub host: String,
    #[serde(default = "default_port")]
    pub port: u16,
    pub ssh_user: String,
    pub portal: String,
    #[serde(default)]
    pub identity_file: Option<String>,
    /// Optional per-connection known_hosts file. When omitted, ssh.exe keeps
    /// its normal user/system host-key lookup for remote relay servers.
    #[serde(default)]
    pub known_hosts_file: Option<String>,
    /// Local loopback SOCKS5 port exposed by the Windows-side ssh.exe
    /// dynamic forward after OpenConnect is connected.
    #[serde(default = "default_socks_port")]
    pub socks_port: u16,
    #[serde(default = "default_true")]
    pub socks_enabled: bool,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VmConfig {
    pub qemu_exe: String,
    #[serde(default)]
    pub boot_mode: VmBootMode,
    #[serde(default)]
    pub disk_image: Option<String>,
    #[serde(default)]
    pub iso_image: Option<String>,
    #[serde(default = "default_memory_mb")]
    pub memory_mb: u32,
    #[serde(default = "default_cpus")]
    pub cpus: u8,
    #[serde(default = "default_forward_port")]
    pub ssh_forward_port: u16,
    pub ssh_user: String,
    pub identity_file: Option<String>,
    pub known_hosts_file: String,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, Default, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum VmBootMode {
    #[default]
    Disk,
    Iso,
}

fn default_memory_mb() -> u32 {
    4096
}

fn default_cpus() -> u8 {
    2
}

fn default_forward_port() -> u16 {
    2222
}

fn default_port() -> u16 {
    22
}

fn default_socks_port() -> u16 {
    DEFAULT_SOCKS_PORT
}

fn default_true() -> bool {
    true
}

fn resolve_path_from(base: &Path, value: &str) -> PathBuf {
    let path = Path::new(value);
    if path.is_absolute() {
        path.to_path_buf()
    } else {
        base.join(path)
    }
}

/// Portable releases keep the executable, `tools`, and `vm` beside each
/// other. During development the executable lives below `src-tauri/target`,
/// so walk up to the project root when that layout is detected.
fn portable_base_dir() -> Result<PathBuf, String> {
    let executable = std::env::current_exe()
        .map_err(|error| format!("could not resolve current executable: {error}"))?;
    let executable_dir = executable
        .parent()
        .ok_or("current executable has no parent directory")?;
    if executable_dir.join("tools").join("qemu").is_dir()
        || executable_dir.join("vm").is_dir()
    {
        return Ok(executable_dir.to_path_buf());
    }
    for ancestor in executable_dir.ancestors() {
        if ancestor.join("src-tauri").is_dir() && ancestor.join("tools").join("qemu").is_dir() {
            return Ok(ancestor.to_path_buf());
        }
    }
    Ok(executable_dir.to_path_buf())
}

fn resolve_portable_path(value: &str) -> Result<String, String> {
    Ok(resolve_path_from(&portable_base_dir()?, value)
        .to_string_lossy()
        .into_owned())
}

fn resolve_connection_paths(mut config: ConnectionConfig) -> Result<ConnectionConfig, String> {
    config.identity_file = config
        .identity_file
        .as_deref()
        .map(resolve_portable_path)
        .transpose()?;
    config.known_hosts_file = config
        .known_hosts_file
        .as_deref()
        .map(resolve_portable_path)
        .transpose()?;
    Ok(config)
}

fn resolve_vm_paths(mut config: VmConfig) -> Result<VmConfig, String> {
    config.qemu_exe = resolve_portable_path(&config.qemu_exe)?;
    config.disk_image = config.disk_image.as_deref().map(resolve_portable_path).transpose()?;
    config.iso_image = config.iso_image.as_deref().map(resolve_portable_path).transpose()?;
    config.identity_file = config.identity_file.as_deref().map(resolve_portable_path).transpose()?;
    config.known_hosts_file = resolve_portable_path(&config.known_hosts_file)?;
    Ok(config)
}

fn gp_relay_pid_file() -> Result<PathBuf, String> {
    Ok(portable_base_dir()?.join("vm").join(GP_RELAY_PID_FILE))
}

#[cfg(target_os = "windows")]
fn process_image_path(pid: u32) -> Result<PathBuf, String> {
    let handle = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
    if handle.is_null() {
        return Err(format!("could not open process {pid}: {}", io::Error::last_os_error()));
    }
    let mut buffer = vec![0_u16; 32_768];
    let mut size = buffer.len() as u32;
    let ok = unsafe { QueryFullProcessImageNameW(handle, 0, buffer.as_mut_ptr(), &mut size) };
    unsafe { CloseHandle(handle) };
    if ok == 0 {
        return Err(format!(
            "could not read process {pid} image: {}",
            io::Error::last_os_error()
        ));
    }
    buffer.truncate(size as usize);
    Ok(PathBuf::from(std::ffi::OsString::from_wide(&buffer)))
}

#[cfg(not(target_os = "windows"))]
fn process_image_path(_pid: u32) -> Result<PathBuf, String> {
    Err("process image lookup is only supported on Windows".into())
}

fn same_path(left: &Path, right: &Path) -> bool {
    let left = fs::canonicalize(left).unwrap_or_else(|_| left.to_path_buf());
    let right = fs::canonicalize(right).unwrap_or_else(|_| right.to_path_buf());
    left.to_string_lossy().eq_ignore_ascii_case(&right.to_string_lossy())
}

fn discover_marked_vm_pid(expected_qemu: &Path) -> Result<u32, String> {
    let pid_file = gp_relay_pid_file()?;
    let pid: u32 = fs::read_to_string(&pid_file)
        .map_err(|error| format!("could not read {}: {error}", pid_file.display()))?
        .trim()
        .parse()
        .map_err(|_| format!("invalid PID in {}", pid_file.display()))?;
    let actual_qemu = process_image_path(pid)?;
    if !same_path(&actual_qemu, expected_qemu) {
        return Err(format!(
            "PID {pid} belongs to {}, not {}",
            actual_qemu.display(),
            expected_qemu.display()
        ));
    }
    Ok(pid)
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
    server_host: Option<String>,
    portal: Option<String>,
    connected_at: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
struct FrontendVmSettings {
    qemu_exe: String,
    #[serde(default)]
    boot_mode: Option<VmBootMode>,
    #[serde(default)]
    disk_image: Option<String>,
    #[serde(default)]
    iso_image: Option<String>,
    memory_mb: Option<u32>,
    cpus: Option<u8>,
    ssh_forward_port: Option<u16>,
    #[serde(default)]
    ssh_user: Option<String>,
    #[serde(default)]
    identity_file: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
struct FrontendConnectionSettings {
    server_host: String,
    ssh_port: Option<u16>,
    ssh_user: String,
    #[serde(default)]
    identity_file: Option<String>,
    #[serde(default)]
    known_hosts_file: Option<String>,
    portal: String,
    #[serde(default)]
    socks_port: Option<u16>,
    #[serde(default)]
    socks_enabled: Option<bool>,
    #[allow(dead_code)]
    vm: Option<FrontendVmSettings>,
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
    host: String,
    portal: String,
    connected: bool,
    disconnect_state: DisconnectState,
    /// Values submitted through the interactive prompt are retained only in
    /// memory for PTY echo redaction. They are never persisted or used as
    /// process arguments.
    sensitive_inputs: Vec<String>,
    socks_port: u16,
    socks_enabled: bool,
    ssh_port: u16,
    ssh_user: String,
    identity_file: Option<String>,
    known_hosts_file: Option<String>,
}

struct VmSession {
    /// Present only when this GUI instance launched QEMU itself. An already
    /// running, SSH-verified relay can be adopted without owning its process.
    child: Option<Arc<Mutex<Child>>>,
    snapshot: VmSnapshot,
}

struct SocksSession {
    session_id: u64,
    child: Arc<Mutex<Child>>,
    snapshot: SocksSnapshot,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum VmState {
    Stopped,
    Starting,
    Running,
    Stopping,
    Error,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VmSnapshot {
    pub state: VmState,
    pub pid: Option<u32>,
    pub ssh_forward_port: Option<u16>,
    pub error: Option<String>,
    pub message: Option<String>,
    pub detail: Option<String>,
}

#[derive(Default)]
struct InnerState {
    session: Option<Session>,
    vm: Option<VmSession>,
    socks: Option<SocksSession>,
    socks_last_snapshot: Option<SocksSnapshot>,
    /// Set while the dynamic-forward child is being spawned. This closes the
    /// small race where duplicate OpenConnect output chunks could otherwise
    /// create two SOCKS processes before the first one is stored.
    socks_starting_for: Option<u64>,
    next_id: u64,
    active_prompt: Option<PendingPrompt>,
    next_prompt_id: u64,
}

#[derive(Debug, Clone)]
struct PendingPrompt {
    request_id: String,
    kind: PromptKind,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum PromptKind {
    Username,
    Password,
    Mfa,
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

fn stopped_vm_snapshot() -> VmSnapshot {
    VmSnapshot {
        state: VmState::Stopped,
        pid: None,
        ssh_forward_port: None,
        error: None,
        message: Some("VM выключена".into()),
        detail: None,
    }
}

fn stopped_socks_snapshot(port: u16) -> SocksSnapshot {
    SocksSnapshot {
        state: SocksState::Stopped,
        pid: None,
        port,
        error: None,
    }
}

fn emit_status(app: &AppHandle, snapshot: SessionSnapshot) {
    let _ = app.emit(STATUS_EVENT, snapshot);
}

fn emit_vm_status(app: &AppHandle, snapshot: VmSnapshot) {
    let _ = app.emit("vm://status", snapshot);
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

fn detect_prompt(text: &str) -> Option<PromptKind> {
    let lower = text.to_lowercase();
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
    // ssh -tt gives the remote process a PTY; ETX is therefore the portable
    // equivalent of pressing Ctrl-C in the foreground openconnect process.
    &[0x03]
}

fn openconnect_command(portal: &str) -> String {
    // Keep openconnect in the foreground. The shell wrapper emits a marker
    // and exits only after openconnect returns, so Ctrl-C cannot be followed
    // by an early `exit` command that might be consumed by openconnect.
    format!(
        "sudo -n openconnect --protocol=gp -- '{portal}'; status=$?; printf '\\n[openconnect-exit:%s]\\n' \"$status\"; exit \"$status\""
    )
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
        server_host: session.map(|s| s.host.clone()),
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
            notify_prompt(&app, &state, session_id, kind, message);
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

fn validate_config(config: &ConnectionConfig) -> Result<(), String> {
    validate_token(&config.host, "host")?;
    validate_token(&config.ssh_user, "sshUser")?;
    validate_token(&config.portal, "portal")?;
    if config.port == 0 {
        return Err("port must be between 1 and 65535".into());
    }
    if config.socks_port == 0 {
        return Err("socksPort must be between 1 and 65535".into());
    }
    if let Some(path) = config.identity_file.as_deref() {
        if path.is_empty() || path.len() > 4096 || path.contains('\0') {
            return Err("identityFile is invalid".into());
        }
        if !Path::new(path).is_file() {
            return Err("identityFile does not point to an existing file".into());
        }
    }
    if let Some(path) = config.known_hosts_file.as_deref() {
        if path.is_empty() || path.len() > 4096 || path.contains('\0') {
            return Err("knownHostsFile is invalid".into());
        }
        if !Path::new(path).is_file() {
            return Err("knownHostsFile does not point to an existing file".into());
        }
    }
    Ok(())
}

fn socks_ssh_args(
    socks_port: u16,
    ssh_port: u16,
    ssh_user: &str,
    identity_file: &str,
    known_hosts_file: &str,
) -> Vec<String> {
    vec![
        "-F".into(),
        "none".into(),
        "-N".into(),
        "-T".into(),
        "-n".into(),
        "-D".into(),
        format!("127.0.0.1:{socks_port}"),
        "-o".into(),
        "BatchMode=yes".into(),
        "-o".into(),
        "PreferredAuthentications=publickey".into(),
        "-o".into(),
        "IdentitiesOnly=yes".into(),
        "-o".into(),
        "StrictHostKeyChecking=yes".into(),
        "-o".into(),
        format!("UserKnownHostsFile={known_hosts_file}"),
        "-o".into(),
        "ConnectTimeout=15".into(),
        "-o".into(),
        "ConnectionAttempts=1".into(),
        "-o".into(),
        "ExitOnForwardFailure=yes".into(),
        "-o".into(),
        "ServerAliveInterval=15".into(),
        "-o".into(),
        "ServerAliveCountMax=3".into(),
        "-p".into(),
        ssh_port.to_string(),
        "-i".into(),
        identity_file.into(),
        format!("{ssh_user}@127.0.0.1"),
    ]
}

fn validate_vm_config(config: &VmConfig) -> Result<(), String> {
    if config.qemu_exe.is_empty() || config.qemu_exe.len() > 4096 || config.qemu_exe.contains('\0')
    {
        return Err("qemuExe is invalid".into());
    }
    if !(256..=262_144).contains(&config.memory_mb) {
        return Err("memoryMb must be between 256 and 262144".into());
    }
    if !(1..=128).contains(&config.cpus) {
        return Err("cpus must be between 1 and 128".into());
    }
    if config.ssh_forward_port == 0 {
        return Err("sshForwardPort must be between 1 and 65535".into());
    }
    if !Path::new(&config.qemu_exe).is_file() {
        return Err("qemuExe does not point to an existing file".into());
    }
    if config.ssh_user.is_empty() || config.ssh_user.len() > 255 {
        return Err("sshUser is invalid".into());
    }
    if config.known_hosts_file.is_empty()
        || config.known_hosts_file.len() > 4096
        || config.known_hosts_file.contains('\0')
    {
        return Err("knownHostsFile is invalid".into());
    }
    match config.boot_mode {
        VmBootMode::Disk => {
            let path = config
                .disk_image
                .as_deref()
                .ok_or("diskImage is required in disk boot mode")?;
            if path.is_empty() || path.len() > 4096 || path.contains('\0') {
                return Err("diskImage is invalid".into());
            }
            if !Path::new(path).is_file() {
                return Err("diskImage does not point to an existing file".into());
            }
            if let Some(identity_file) = config.identity_file.as_deref() {
                if identity_file.is_empty()
                    || identity_file.len() > 4096
                    || identity_file.contains('\0')
                {
                    return Err("identityFile is invalid".into());
                }
                if !Path::new(identity_file).is_file() {
                    return Err("identityFile does not point to an existing file".into());
                }
            }
            if !Path::new(&config.known_hosts_file).is_file() {
                return Err("knownHostsFile does not point to an existing file".into());
            }
        }
        VmBootMode::Iso => {
            let path = config
                .iso_image
                .as_deref()
                .ok_or("isoImage is required in ISO boot mode")?;
            if path.is_empty() || path.len() > 4096 || path.contains('\0') {
                return Err("isoImage is invalid".into());
            }
            let iso = Path::new(path);
            if !iso.is_file() {
                return Err("isoImage does not point to an existing file".into());
            }
            if iso
                .extension()
                .and_then(|ext| ext.to_str())
                .map(|ext| ext.eq_ignore_ascii_case("iso"))
                != Some(true)
            {
                return Err("isoImage must have an .iso extension".into());
            }
        }
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
        .map_err(|error| format!("could not write to ssh stdin: {error}"))
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
                        let message = if kind == PromptKind::Text {
                            text.clone()
                        } else {
                            prompt_label(&kind).to_string()
                        };
                        notify_prompt(&app, &state, session_id, kind, message);
                        // Do not rediscover the previous prompt after its
                        // response clears `active_prompt`.
                        analysis_text.clear();
                    }
                    match status {
                        Some(OpenConnectStatus::Connected) => {
                            let should_start_socks = if let Ok(mut inner) = state.inner.lock() {
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
                                inner.session.as_ref().is_some_and(|session| {
                                    session.id == session_id && session.connected
                                })
                            } else {
                                false
                            };
                            if should_start_socks {
                                start_socks_for_session(app.clone(), state.clone(), session_id);
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
                            let _ = stop_socks_for_session(&app, &state, Some(session_id));
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
                            text: format!("\n[ssh stream read error: {error}]\n"),
                        },
                    );
                    break;
                }
            }
        }
    });
}

fn cleanup_runtime_children(state: &AppState) {
    let (session_child, socks_child) = match state.inner.lock() {
        Ok(mut inner) => {
            inner.active_prompt = None;
            inner.socks_starting_for = None;
            let session_child = inner.session.take().map(|session| session.child);
            let socks_child = inner.socks.take().map(|socks| socks.child);
            (session_child, socks_child)
        }
        Err(_) => return,
    };
    for child in [session_child, socks_child].into_iter().flatten() {
        let _ = child
            .lock()
            .ok()
            .and_then(|mut process| process.kill().ok());
    }
}

fn spawn_waiter(app: AppHandle, state: AppState, session_id: u64, child: Arc<Mutex<Child>>) {
    thread::spawn(move || {
        let result = wait_for_child(&child);

        // The SOCKS forward depends on this SSH/OpenConnect session. Stop it
        // before publishing the terminal VPN state, so no stale proxy remains
        // usable after the tunnel has gone away.
        let _ = stop_socks_for_session(&app, &state, Some(session_id));

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
            }, "error", "SSH-сессия завершилась с ошибкой"),
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
                            format!("Не удалось завершить SSH после Ctrl-C: {error}"),
                        );
                    } else {
                        emit_log(
                            &app,
                            "warn",
                            format!("SSH-сессия {session_id} принудительно завершена после Ctrl-C"),
                        );
                    }
                }
                return;
            }
            thread::sleep(Duration::from_millis(100));
        }
    });
}

fn emit_socks_status(app: &AppHandle, snapshot: SocksSnapshot) {
    let _ = app.emit("socks://status", snapshot);
}

fn mark_socks_error(app: &AppHandle, state: &AppState, session_id: u64, port: u16, error: String) {
    let snapshot = SocksSnapshot {
        state: SocksState::Error,
        pid: None,
        port,
        error: Some(error),
    };
    if let Ok(mut inner) = state.inner.lock() {
        if inner.socks_starting_for == Some(session_id) {
            inner.socks_starting_for = None;
        }
        inner.socks_last_snapshot = Some(snapshot.clone());
    }
    emit_socks_status(app, snapshot);
}

/// Start the Windows-side dynamic forward once OpenConnect has reported a
/// connected tunnel. The target is deliberately fixed to the local relay VM;
/// this prevents a GUI setting from turning this process into an arbitrary
/// SSH tunnel launcher.
fn start_socks_for_session(app: AppHandle, state: AppState, session_id: u64) {
    let (port, ssh_port, ssh_user, identity_file, known_hosts_file) = {
        let mut inner = match state.inner.lock() {
            Ok(inner) => inner,
            Err(_) => return,
        };
        let session = match inner
            .session
            .as_ref()
            .filter(|session| session.id == session_id && session.connected && session.socks_enabled)
        {
            Some(session) => session,
            None => return,
        };
        if session.disconnect_state != DisconnectState::NotRequested
            || inner.socks.is_some()
            || inner.socks_starting_for.is_some()
        {
            return;
        }
        let details = (
            session.socks_port,
            session.ssh_port,
            session.ssh_user.clone(),
            session
                .identity_file
                .clone()
                .unwrap_or_else(|| DEFAULT_VM_IDENTITY_FILE.to_string()),
            session
                .known_hosts_file
                .clone()
                .unwrap_or_else(|| DEFAULT_VM_KNOWN_HOSTS.to_string()),
        );
        inner.socks_starting_for = Some(session_id);
        details
    };

    if port == 0 {
        mark_socks_error(&app, &state, session_id, port, "socksPort must be between 1 and 65535".into());
        return;
    }
    if !Path::new(&identity_file).is_file() {
        mark_socks_error(
            &app,
            &state,
            session_id,
            port,
            "SOCKS identityFile does not point to an existing file".into(),
        );
        return;
    }
    if !Path::new(&known_hosts_file).is_file() {
        mark_socks_error(
            &app,
            &state,
            session_id,
            port,
            "SOCKS knownHostsFile does not point to an existing file".into(),
        );
        return;
    }
    let probe = match TcpListener::bind((Ipv4Addr::LOCALHOST, port)) {
        Ok(listener) => listener,
        Err(error) => {
            mark_socks_error(
                &app,
                &state,
                session_id,
                port,
                format!("SOCKS port {port} is unavailable: {error}"),
            );
            return;
        }
    };
    drop(probe);

    let mut command = std::process::Command::new("ssh.exe");
    #[cfg(target_os = "windows")]
    command.creation_flags(CREATE_NO_WINDOW);
    command
        .args(socks_ssh_args(
            port,
            ssh_port,
            &ssh_user,
            &identity_file,
            &known_hosts_file,
        ))
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let child = match command.spawn() {
        Ok(child) => child,
        Err(error) => {
            mark_socks_error(
                &app,
                &state,
                session_id,
                port,
                format!("could not start SOCKS ssh.exe: {error}"),
            );
            return;
        }
    };
    let pid = child.id();
    let child = Arc::new(Mutex::new(child));

    // ExitOnForwardFailure reports bind/authentication failures through the
    // process exit status. Check immediately before publishing Running, while
    // the child is still owned by this lifecycle.
    let early_exit = child
        .lock()
        .ok()
        .and_then(|mut process| process.try_wait().ok())
        .flatten();
    if let Some(status) = early_exit {
        mark_socks_error(
            &app,
            &state,
            session_id,
            port,
            format!("SOCKS ssh.exe exited during startup with code {:?}", status.code()),
        );
        return;
    }

    let snapshot = SocksSnapshot {
        state: SocksState::Starting,
        pid: Some(pid),
        port,
        error: None,
    };
    let accepted = if let Ok(mut inner) = state.inner.lock() {
        let accepted = inner.socks_starting_for == Some(session_id)
            && inner
                .session
                .as_ref()
                .is_some_and(|session| {
                    session.id == session_id
                        && session.connected
                        && session.disconnect_state == DisconnectState::NotRequested
                });
        if accepted {
            inner.socks_starting_for = None;
            inner.socks_last_snapshot = Some(snapshot.clone());
            inner.socks = Some(SocksSession {
                session_id,
                child: Arc::clone(&child),
                snapshot: snapshot.clone(),
            });
        } else if inner.socks_starting_for == Some(session_id) {
            inner.socks_starting_for = None;
        }
        accepted
    } else {
        false
    };
    if !accepted {
        let _ = child
            .lock()
            .ok()
            .and_then(|mut process| process.kill().ok());
        return;
    }
    emit_socks_status(&app, snapshot);
    spawn_socks_waiter(app.clone(), state.clone(), session_id, Arc::clone(&child));
    spawn_socks_readiness(app, state, session_id, child, port);
}

fn spawn_socks_readiness(
    app: AppHandle,
    state: AppState,
    session_id: u64,
    child: Arc<Mutex<Child>>,
    port: u16,
) {
    thread::spawn(move || {
        let address = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port);
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            let current = state
                .inner
                .lock()
                .ok()
                .and_then(|inner| {
                    inner.socks.as_ref().map(|socks| {
                        socks.session_id == session_id
                            && Arc::ptr_eq(&socks.child, &child)
                            && socks.snapshot.state == SocksState::Starting
                    })
                })
                .unwrap_or(false);
            if !current {
                return;
            }
            if child
                .lock()
                .ok()
                .and_then(|mut process| process.try_wait().ok())
                .flatten()
                .is_some()
            {
                return;
            }
            if TcpStream::connect_timeout(&address, Duration::from_millis(300)).is_ok() {
                let snapshot = if let Ok(mut inner) = state.inner.lock() {
                    let snapshot = if let Some(socks) = inner.socks.as_mut().filter(|socks| {
                        socks.session_id == session_id && Arc::ptr_eq(&socks.child, &child)
                    }) {
                        socks.snapshot.state = SocksState::Running;
                        socks.snapshot.error = None;
                        Some(socks.snapshot.clone())
                    } else {
                        None
                    };
                    if let Some(snapshot) = snapshot.as_ref() {
                        inner.socks_last_snapshot = Some(snapshot.clone());
                    }
                    snapshot
                } else {
                    None
                };
                if let Some(snapshot) = snapshot {
                    emit_socks_status(&app, snapshot);
                }
                return;
            }
            if Instant::now() >= deadline {
                let snapshot = if let Ok(mut inner) = state.inner.lock() {
                    let snapshot = if let Some(socks) = inner.socks.as_mut().filter(|socks| {
                        socks.session_id == session_id && Arc::ptr_eq(&socks.child, &child)
                    }) {
                        let snapshot = SocksSnapshot {
                            state: SocksState::Error,
                            pid: None,
                            port,
                            error: Some("SOCKS listener did not become ready within 10 seconds".into()),
                        };
                        socks.snapshot = snapshot.clone();
                        Some(snapshot)
                    } else {
                        None
                    };
                    if let Some(snapshot) = snapshot.as_ref() {
                        inner.socks_last_snapshot = Some(snapshot.clone());
                    }
                    snapshot
                } else {
                    None
                };
                if let Some(snapshot) = snapshot {
                    emit_socks_status(&app, snapshot);
                    let _ = child
                        .lock()
                        .ok()
                        .and_then(|mut process| process.kill().ok());
                }
                return;
            }
            thread::sleep(Duration::from_millis(100));
        }
    });
}

fn spawn_socks_waiter(app: AppHandle, state: AppState, session_id: u64, child: Arc<Mutex<Child>>) {
    thread::spawn(move || {
        let result = wait_for_child(&child);
        let (port, stopping) = state
            .inner
            .lock()
            .ok()
            .and_then(|inner| {
                inner.socks.as_ref().filter(|socks| {
                    socks.session_id == session_id && Arc::ptr_eq(&socks.child, &child)
                }).map(|socks| (
                    socks.snapshot.port,
                    socks.snapshot.state == SocksState::Stopping,
                ))
            })
            .unwrap_or((DEFAULT_SOCKS_PORT, false));
        let snapshot = match result {
            Ok(status) if stopping || status.success() => SocksSnapshot {
                state: SocksState::Stopped,
                pid: None,
                port,
                error: None,
            },
            Ok(status) => SocksSnapshot {
                state: SocksState::Error,
                pid: None,
                port,
                error: Some(format!("SOCKS ssh.exe exited with code {:?}", status.code())),
            },
            Err(error) => SocksSnapshot {
                state: SocksState::Error,
                pid: None,
                port,
                error: Some(error),
            },
        };
        emit_socks_status(&app, snapshot.clone());
        if let Ok(mut inner) = state.inner.lock() {
            inner.socks_last_snapshot = Some(snapshot.clone());
            if inner.socks.as_ref().is_some_and(|socks| {
                socks.session_id == session_id && Arc::ptr_eq(&socks.child, &child)
            }) {
                inner.socks = None;
            }
        }
    });
}

fn stop_socks_for_session(app: &AppHandle, state: &AppState, session_id: Option<u64>) -> Result<(), String> {
    let child_and_snapshot = {
        let mut inner = state
            .inner
            .lock()
            .map_err(|_| "state mutex poisoned".to_string())?;
        if let Some(expected_id) = session_id {
            if inner.socks.as_ref().is_some_and(|socks| socks.session_id != expected_id) {
                return Ok(());
            }
            if inner.socks_starting_for == Some(expected_id) {
                inner.socks_starting_for = None;
            }
        } else {
            inner.socks_starting_for = None;
        }
        let (child, snapshot) = {
            let socks = match inner.socks.as_mut() {
                Some(socks) => socks,
                None => return Ok(()),
            };
            let mut snapshot = socks.snapshot.clone();
            snapshot.state = SocksState::Stopping;
            socks.snapshot = snapshot.clone();
            (Arc::clone(&socks.child), snapshot)
        };
        inner.socks_last_snapshot = Some(snapshot.clone());
        (child, snapshot)
    };
    let (child, snapshot) = child_and_snapshot;
    emit_socks_status(app, snapshot);
    let result = child
        .lock()
        .map_err(|_| "SOCKS child mutex poisoned".to_string())?
        .kill()
        .map_err(|error| format!("could not stop SOCKS ssh.exe: {error}"));
    result
}

/// Polling keeps the child mutex available for `cancel`/`vm_stop`. Holding it
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
    let config = resolve_connection_paths(config)?;
    validate_config(&config)?;
    {
        let inner = state
            .inner
            .lock()
            .map_err(|_| "state mutex poisoned".to_string())?;
        if inner.session.is_some() {
            return Err("an SSH session is already running".into());
        }
    }

    let mut command = std::process::Command::new("ssh.exe");
    #[cfg(target_os = "windows")]
    command.creation_flags(CREATE_NO_WINDOW);
    command
        .arg("-tt")
        .arg("-o")
        .arg("BatchMode=yes")
        .arg("-o")
        .arg("ConnectTimeout=15")
        .arg("-p")
        .arg(config.port.to_string());
    if let Some(identity_file) = config.identity_file.as_deref() {
        command.arg("-i").arg(identity_file);
    }
    if let Some(known_hosts_file) = config.known_hosts_file.as_deref() {
        command
            .arg("-o")
            .arg("StrictHostKeyChecking=yes")
            .arg("-o")
            .arg(format!("UserKnownHostsFile={known_hosts_file}"));
    }
    command
        .arg(format!("{}@{}", config.ssh_user, config.host))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    let mut child = command
        .spawn()
        .map_err(|error| format!("could not start ssh.exe: {error}"))?;
    let stdin = child.stdin.take().ok_or("ssh stdin is unavailable")?;
    let stdout = child.stdout.take().ok_or("ssh stdout is unavailable")?;
    let stderr = child.stderr.take().ok_or("ssh stderr is unavailable")?;
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
            return Err("an SSH session is already running".into());
        }
        inner.session = Some(Session {
            id,
            child: Arc::clone(&child),
            stdin: Arc::clone(&stdin),
            snapshot: snapshot.clone(),
            host: config.host.clone(),
            portal: config.portal.clone(),
            connected: false,
            disconnect_state: DisconnectState::NotRequested,
            sensitive_inputs: Vec::new(),
            socks_port: config.socks_port,
            socks_enabled: config.socks_enabled,
            ssh_port: config.port,
            ssh_user: config.ssh_user.clone(),
            identity_file: config.identity_file.clone(),
            known_hosts_file: config.known_hosts_file.clone(),
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

    // Keep one SSH PTY alive with openconnect in the foreground. The portal
    // is sent over stdin, not the local ssh.exe argv. Once openconnect exits,
    // the wrapper exits the remote shell as well.
    if let Err(error) = write_line(&stdin, &openconnect_command(&config.portal)) {
        if let Ok(mut inner) = state.inner.lock() {
            if let Some(session) = inner.session.take() {
                let _ = session
                    .child
                    .lock()
                    .ok()
                    .and_then(|mut process| process.kill().ok());
            }
        }
        return Err(error);
    }
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
            Some("Ожидаем ответ SSH/GlobalProtect".into()),
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
    let session = inner.session.as_ref().ok_or("no active SSH session")?;
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
    inner.session.as_ref().ok_or("no active SSH session")?;
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
    inner.session.as_ref().ok_or("no active SSH session")?;
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
        let session = inner.session.as_mut().ok_or("no active SSH session")?;
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

    if let Err(error) = stop_socks_for_session(&app, &state, Some(session_id)) {
        emit_log(&app, "warn", format!("Не удалось остановить SOCKS: {error}"));
    }

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
    if let Err(error) = stop_socks_for_session(&app, &state, None) {
        emit_log(&app, "warn", format!("Не удалось остановить SOCKS: {error}"));
    }
    let session = {
        let mut inner = state
            .inner
            .lock()
            .map_err(|_| "state mutex poisoned".to_string())?;
        inner.active_prompt = None;
        inner.session.take()
    };
    let session = session.ok_or("no active SSH session")?;
    session
        .child
        .lock()
        .map_err(|_| "child mutex poisoned".to_string())?
        .kill()
        .map_err(|error| format!("could not cancel ssh.exe: {error}"))?;
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

fn spawn_vm_waiter(app: AppHandle, state: AppState, child: Arc<Mutex<Child>>, port: u16) {
    thread::spawn(move || {
        let result = wait_for_child(&child);
        let snapshot = match result {
            Ok(status) if status.success() => VmSnapshot {
                state: VmState::Stopped,
                pid: None,
                ssh_forward_port: Some(port),
                error: None,
                message: Some("VM выключена".into()),
                detail: Some(format!("SSH-forward 127.0.0.1:{port} закрыт")),
            },
            Ok(status) => VmSnapshot {
                state: VmState::Error,
                pid: None,
                ssh_forward_port: Some(port),
                error: Some(format!("QEMU exited with code {:?}", status.code())),
                message: Some("Процесс QEMU завершился с ошибкой".into()),
                detail: Some(format!("Код выхода {:?}", status.code())),
            },
            Err(error) => VmSnapshot {
                state: VmState::Error,
                pid: None,
                ssh_forward_port: Some(port),
                error: Some(error.clone()),
                message: Some("Не удалось получить статус QEMU".into()),
                detail: Some(error),
            },
        };
        let level = if snapshot.error.is_some() { "error" } else { "info" };
        emit_log(
            &app,
            level,
            snapshot
                .message
                .clone()
                .unwrap_or_else(|| "Статус QEMU изменился".into()),
        );
        emit_vm_status(&app, snapshot.clone());
        if let Ok(mut inner) = state.inner.lock() {
            if inner
                .vm
                .as_ref()
                .is_some_and(|vm| {
                    vm.child
                        .as_ref()
                        .is_some_and(|owned| Arc::ptr_eq(owned, &child))
                })
            {
                inner.vm = None;
            }
        }
    });
}

#[tauri::command]
fn vm_status(state: State<'_, AppState>) -> Result<VmSnapshot, String> {
    let inner = state
        .inner
        .lock()
        .map_err(|_| "state mutex poisoned".to_string())?;
    Ok(inner
        .vm
        .as_ref()
        .map(|vm| vm.snapshot.clone())
        .unwrap_or_else(stopped_vm_snapshot))
}

#[tauri::command]
fn socks_status(state: State<'_, AppState>) -> Result<SocksSnapshot, String> {
    let inner = state
        .inner
        .lock()
        .map_err(|_| "state mutex poisoned".to_string())?;
    Ok(inner
        .socks
        .as_ref()
        .map(|socks| socks.snapshot.clone())
        .or_else(|| inner.socks_last_snapshot.clone())
        .unwrap_or_else(|| stopped_socks_snapshot(DEFAULT_SOCKS_PORT)))
}

#[tauri::command]
fn socks_stop(app: AppHandle, state: State<'_, AppState>) -> Result<SocksSnapshot, String> {
    stop_socks_for_session(&app, &state, None)?;
    Ok(socks_status(state)?)
}

fn vm_start_impl(
    app: AppHandle,
    state: State<'_, AppState>,
    config: VmConfig,
) -> Result<VmSnapshot, String> {
    let config = resolve_vm_paths(config)?;
    validate_vm_config(&config)?;
    {
        let inner = state
            .inner
            .lock()
            .map_err(|_| "state mutex poisoned".to_string())?;
        if let Some(vm) = inner.vm.as_ref() {
            if vm.snapshot.ssh_forward_port == Some(config.ssh_forward_port) {
                return Ok(vm.snapshot.clone());
            }
            return Err(format!(
                "a QEMU VM is already running on SSH forward port {}",
                vm.snapshot
                    .ssh_forward_port
                    .map(|port| port.to_string())
                    .unwrap_or_else(|| "unknown".into())
            ));
        }
    }

    let hostfwd = format!("tcp:127.0.0.1:{}-:22", config.ssh_forward_port);
    let port_probe = match TcpListener::bind((Ipv4Addr::LOCALHOST, config.ssh_forward_port)) {
        Ok(listener) => listener,
        Err(bind_error) if config.boot_mode == VmBootMode::Disk => {
            match check_vm_ssh(
                &config.ssh_user,
                config.ssh_forward_port,
                config.identity_file.as_deref(),
                &config.known_hosts_file,
            ) {
                Ok(()) => {
                    let snapshot = VmSnapshot {
                        state: VmState::Running,
                        pid: None,
                        ssh_forward_port: Some(config.ssh_forward_port),
                        error: None,
                        message: Some("Подхвачена уже работающая Ubuntu VM".into()),
                        detail: Some(format!(
                            "{}@127.0.0.1:{} · внешний QEMU",
                            config.ssh_user, config.ssh_forward_port
                        )),
                    };
                    {
                        let mut inner = state
                            .inner
                            .lock()
                            .map_err(|_| "state mutex poisoned".to_string())?;
                        if let Some(vm) = inner.vm.as_ref() {
                            return Ok(vm.snapshot.clone());
                        }
                        inner.vm = Some(VmSession {
                            child: None,
                            snapshot: snapshot.clone(),
                        });
                    }
                    emit_log(
                        &app,
                        "success",
                        format!(
                            "QEMU: порт {} уже занят нашей SSH-доступной Ubuntu; использую существующую VM",
                            config.ssh_forward_port
                        ),
                    );
                    emit_vm_status(&app, snapshot.clone());
                    return Ok(snapshot);
                }
                Err(ssh_error) => {
                    return Err(format!(
                        "SSH forward port {} is unavailable: {bind_error}. Порт занят, но проверка Ubuntu SSH не прошла: {ssh_error}",
                        config.ssh_forward_port
                    ));
                }
            }
        }
        Err(error) => {
            return Err(format!(
                "SSH forward port {} is unavailable: {error}",
                config.ssh_forward_port
            ));
        }
    };
    drop(port_probe);
    let boot_source = match config.boot_mode {
        VmBootMode::Disk => config.disk_image.as_deref().unwrap_or_default(),
        VmBootMode::Iso => config.iso_image.as_deref().unwrap_or_default(),
    };
    emit_log(
        &app,
        "info",
        format!(
            "QEMU: запускаю {} · {} MB · {} vCPU · SSH 127.0.0.1:{} → VM:22",
            boot_source, config.memory_mb, config.cpus, config.ssh_forward_port
        ),
    );
    let pid_file = gp_relay_pid_file()?;
    if let Some(parent) = pid_file.parent() {
        fs::create_dir_all(parent)
            .map_err(|error| format!("could not create VM runtime directory: {error}"))?;
    }
    let mut command = std::process::Command::new(&config.qemu_exe);
    #[cfg(target_os = "windows")]
    command.creation_flags(CREATE_NO_WINDOW | CREATE_NEW_PROCESS_GROUP);
    command
        .arg("-machine")
        .arg("q35,accel=whpx")
        .arg("-name")
        .arg(GP_RELAY_VM_NAME)
        .arg("-uuid")
        .arg(GP_RELAY_VM_UUID)
        .arg("-pidfile")
        .arg(&pid_file)
        .arg("-display")
        .arg("none")
        .arg("-no-reboot")
        .arg("-m")
        .arg(config.memory_mb.to_string())
        .arg("-smp")
        .arg(config.cpus.to_string());
    match config.boot_mode {
        VmBootMode::Disk => {
            command.arg("-drive").arg(format!(
                "file={},if=virtio",
                config.disk_image.as_deref().unwrap_or_default()
            ));
        }
        VmBootMode::Iso => {
            command
                .arg("-cdrom")
                .arg(config.iso_image.as_deref().unwrap_or_default())
                .arg("-boot")
                .arg("order=d");
        }
    }
    command
        .arg("-netdev")
        .arg(format!("user,id=net0,hostfwd={hostfwd}"))
        .arg("-device")
        .arg("virtio-net-pci,netdev=net0")
        .arg("-serial")
        // Raw Ubuntu serial output can produce thousands of event messages
        // during boot and starve the WebView status/prompt handlers. Keep the
        // live journal focused on lifecycle. Detached stdio also lets QEMU
        // survive closing and reopening the GUI.
        .arg("null")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    let child = command
        .spawn()
        .map_err(|error| format!("could not start QEMU: {error}"))?;
    let pid = child.id();
    let child = Arc::new(Mutex::new(child));
    let snapshot = VmSnapshot {
        state: VmState::Starting,
        pid: Some(pid),
        ssh_forward_port: Some(config.ssh_forward_port),
        error: None,
        message: Some("QEMU запущен, ждём Ubuntu SSH".into()),
        detail: Some(format!("PID {pid} · 127.0.0.1:{} → VM:22", config.ssh_forward_port)),
    };
    let app_state = AppState {
        inner: state.inner.clone(),
    };
    {
        let mut inner = app_state
            .inner
            .lock()
            .map_err(|_| "state mutex poisoned".to_string())?;
        if let Some(vm) = inner.vm.as_ref() {
            let existing = vm.snapshot.clone();
            let _ = child
                .lock()
                .ok()
                .and_then(|mut process| process.kill().ok());
            return Ok(existing);
        }
        inner.vm = Some(VmSession {
            child: Some(Arc::clone(&child)),
            snapshot: snapshot.clone(),
        });
    }
    emit_log(&app, "success", format!("QEMU: процесс запущен, PID {pid}"));
    emit_log(
        &app,
        "info",
        format!("SSH: ожидаю Ubuntu на 127.0.0.1:{}", config.ssh_forward_port),
    );
    spawn_vm_waiter(app.clone(), app_state, child, config.ssh_forward_port);
    emit_vm_status(&app, snapshot.clone());
    if config.boot_mode == VmBootMode::Iso {
        let alive = state
            .inner
            .lock()
            .map_err(|_| "state mutex poisoned".to_string())?
            .vm
            .as_ref()
            .and_then(|vm| vm.child.as_ref())
            .map(|child| {
                child
                    .lock()
                    .ok()
                    .and_then(|mut child| child.try_wait().ok())
                    .is_some_and(|status| status.is_none())
            })
            .unwrap_or(false);
        if !alive {
            return Err("QEMU exited immediately in ISO boot mode".into());
        }
        let mut running = snapshot;
        running.state = VmState::Running;
        running.message = Some("QEMU работает в режиме ISO".into());
        running.detail = Some(format!("PID {pid} · SSH readiness отключена"));
        if let Ok(mut inner) = state.inner.lock() {
            if let Some(vm) = inner.vm.as_mut() {
                vm.snapshot = running.clone();
            }
        }
        emit_vm_status(&app, running.clone());
        Ok(running)
    } else {
        spawn_vm_readiness(
            app,
            AppState {
                inner: state.inner.clone(),
            },
            config.ssh_forward_port,
            config.ssh_user,
            config.identity_file,
            config.known_hosts_file,
        );
        Ok(snapshot)
    }
}

fn spawn_vm_readiness(
    app: AppHandle,
    state: AppState,
    port: u16,
    ssh_user: String,
    identity_file: Option<String>,
    known_hosts_file: String,
) {
    thread::spawn(move || {
        let address = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port);
        let mut tcp_reported = false;
        for _ in 0..120 {
            let vm_alive = state
                .inner
                .lock()
                .ok()
                .and_then(|inner| {
                    inner
                        .vm
                        .as_ref()
                        .and_then(|vm| vm.child.as_ref().map(Arc::clone))
                })
                .and_then(|child| {
                    child
                        .lock()
                        .ok()
                        .and_then(|mut child| child.try_wait().ok())
                })
                .is_some_and(|status| status.is_none());
            if !vm_alive {
                return;
            }

            if TcpStream::connect_timeout(&address, Duration::from_millis(300)).is_ok() {
                if !tcp_reported {
                    tcp_reported = true;
                    emit_log(&app, "info", format!("SSH: порт 127.0.0.1:{port} открыт, проверяю ключ"));
                    if let Ok(mut inner) = state.inner.lock() {
                        if let Some(vm) = inner.vm.as_mut() {
                            vm.snapshot.message = Some("SSH-порт открыт, проверяем ключ".into());
                            vm.snapshot.detail = Some(format!("127.0.0.1:{port} → VM:22"));
                            emit_vm_status(&app, vm.snapshot.clone());
                        }
                    }
                }
                match check_vm_ssh(&ssh_user, port, identity_file.as_deref(), &known_hosts_file) {
                    Ok(()) => {
                        if let Ok(mut inner) = state.inner.lock() {
                            if let Some(vm) = inner.vm.as_mut() {
                                vm.snapshot.state = VmState::Running;
                                vm.snapshot.error = None;
                                vm.snapshot.message = Some("Ubuntu доступна по SSH".into());
                                vm.snapshot.detail = Some(format!("{ssh_user}@127.0.0.1:{port}"));
                                emit_vm_status(&app, vm.snapshot.clone());
                            }
                        }
                        emit_log(
                            &app,
                            "success",
                            format!("SSH: Ubuntu готова — {ssh_user}@127.0.0.1:{port}"),
                        );
                        return;
                    }
                    Err(error) => {
                        // TCP is up while sshd is still starting, so keep retrying.
                        if let Ok(mut inner) = state.inner.lock() {
                            if let Some(vm) = inner.vm.as_mut() {
                                vm.snapshot.message = Some("SSH-порт открыт, ждём sshd".into());
                                vm.snapshot.detail = Some(error);
                            }
                        }
                    }
                }
            }
            thread::sleep(Duration::from_millis(500));
        }

        if let Ok(mut inner) = state.inner.lock() {
            if let Some(vm) = inner.vm.as_mut() {
                vm.snapshot.state = VmState::Error;
                vm.snapshot.error = Some(
                    "QEMU работает, но SSH BatchMode handshake не прошёл за 60 секунд".into(),
                );
                vm.snapshot.message = Some("Ubuntu SSH недоступен".into());
                vm.snapshot.detail = Some(format!("Таймаут 60 секунд · 127.0.0.1:{port}"));
                emit_vm_status(&app, vm.snapshot.clone());
            }
        }
        emit_log(
            &app,
            "error",
            format!("SSH: Ubuntu не ответила на 127.0.0.1:{port} за 60 секунд"),
        );
    });
}

fn check_vm_ssh(
    ssh_user: &str,
    port: u16,
    identity_file: Option<&str>,
    known_hosts_file: &str,
) -> Result<(), String> {
    let mut command = std::process::Command::new("ssh.exe");
    #[cfg(target_os = "windows")]
    command.creation_flags(CREATE_NO_WINDOW);
    command
        .arg("-o")
        .arg("BatchMode=yes")
        .arg("-o")
        .arg("StrictHostKeyChecking=yes")
        .arg("-o")
        .arg(format!("UserKnownHostsFile={known_hosts_file}"))
        .arg("-o")
        .arg("ConnectTimeout=3")
        .arg("-o")
        .arg("ConnectionAttempts=1")
        .arg("-p")
        .arg(port.to_string());
    if let Some(identity_file) = identity_file {
        command.arg("-i").arg(identity_file);
    }
    command
        .arg(format!("{ssh_user}@127.0.0.1"))
        .arg("true")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let output = command
        .output()
        .map_err(|error| format!("could not start ssh.exe: {error}"))?;
    if output.status.success() {
        Ok(())
    } else {
        let detail = String::from_utf8_lossy(&output.stderr).trim().to_string();
        Err(if detail.is_empty() {
            format!("ssh.exe exited with code {:?}", output.status.code())
        } else {
            detail
        })
    }
}

#[tauri::command]
fn vm_stop(app: AppHandle, state: State<'_, AppState>) -> Result<VmSnapshot, String> {
    // A SOCKS connection traverses the VM's SSH forward, so tear it down
    // before QEMU is killed. This is best-effort: VM shutdown must still be
    // possible if the proxy already exited.
    if let Err(error) = stop_socks_for_session(&app, &state, None) {
        emit_log(&app, "warn", format!("Не удалось остановить SOCKS перед VM: {error}"));
    }
    let (child, mut snapshot) = {
        let inner = state
            .inner
            .lock()
            .map_err(|_| "state mutex poisoned".to_string())?;
        let vm = inner.vm.as_ref().ok_or("no active QEMU VM")?;
        let child = vm.child.as_ref().ok_or(
            "VM была подхвачена через SSH и не принадлежит этому окну; выключите её командой sudo poweroff по SSH",
        )?;
        (Arc::clone(child), vm.snapshot.clone())
    };
    child
        .lock()
        .map_err(|_| "VM child mutex poisoned".to_string())?
        .kill()
        .map_err(|error| format!("could not stop QEMU: {error}"))?;
    snapshot.state = VmState::Stopping;
    snapshot.message = Some("Останавливаем QEMU".into());
    snapshot.detail = snapshot.pid.map(|pid| format!("PID {pid}"));
    if let Ok(mut inner) = state.inner.lock() {
        if let Some(vm) = inner
            .vm
            .as_mut()
            .filter(|vm| {
                vm.child
                    .as_ref()
                    .is_some_and(|owned| Arc::ptr_eq(owned, &child))
            })
        {
            vm.snapshot = snapshot.clone();
        }
    }
    emit_vm_status(&app, snapshot.clone());
    emit_log(&app, "info", "QEMU: отправлена команда остановки процесса");
    Ok(snapshot)
}

#[tauri::command]
fn vpn_connect(
    app: AppHandle,
    state: State<'_, AppState>,
    settings: FrontendConnectionSettings,
) -> Result<SessionSnapshot, String> {
    start_connection(
        app,
        state,
        ConnectionConfig {
            host: settings.server_host,
            port: settings.ssh_port.unwrap_or(22),
            ssh_user: settings.ssh_user,
            portal: settings.portal,
            identity_file: settings.identity_file,
            known_hosts_file: settings.known_hosts_file,
            socks_port: settings.socks_port.unwrap_or(DEFAULT_SOCKS_PORT),
            socks_enabled: settings.socks_enabled.unwrap_or(true),
        },
    )
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
            Some(SessionState::Starting) => ("connecting", Some("Запускаем SSH-сессию".into())),
            Some(SessionState::Running) => (
                "connecting",
                Some("Ожидаем аутентификацию OpenConnect".into()),
            ),
            Some(SessionState::Stopping) => {
                ("disconnecting", Some("Отключаем OpenConnect".into()))
            }
            Some(SessionState::Exited | SessionState::Cancelled) => ("idle", None),
            Some(SessionState::Failed) => {
                ("error", Some("SSH-сессия завершилась с ошибкой".into()))
            }
            Some(SessionState::Idle) => ("idle", None),
        }
    };
    Ok(VpnStatusPayload {
        state: state_name.to_string(),
        message,
        server_host: inner.session.as_ref().map(|s| s.host.clone()),
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
        let session = inner.session.as_ref().ok_or("no active SSH session")?;
        (Arc::clone(&session.stdin), pending.kind)
    };
    let key = match kind {
        PromptKind::Username => "username",
        PromptKind::Password => "password",
        PromptKind::Mfa => "mfa",
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
            .ok_or("no active SSH session")?
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

#[tauri::command]
fn vm_start(
    app: AppHandle,
    state: State<'_, AppState>,
    settings: FrontendVmSettings,
) -> Result<VmSnapshot, String> {
    vm_start_impl(app, state, frontend_vm_config(settings))
}

fn frontend_vm_config(settings: FrontendVmSettings) -> VmConfig {
    VmConfig {
        qemu_exe: settings.qemu_exe,
        boot_mode: settings.boot_mode.unwrap_or_default(),
        disk_image: settings.disk_image,
        iso_image: settings.iso_image,
        memory_mb: settings.memory_mb.unwrap_or(4096),
        cpus: settings.cpus.unwrap_or(2),
        ssh_forward_port: settings.ssh_forward_port.unwrap_or(2222),
        ssh_user: settings
            .ssh_user
            .unwrap_or_else(|| DEFAULT_VM_SSH_USER.to_string()),
        identity_file: settings
            .identity_file
            .or_else(|| Some(DEFAULT_VM_IDENTITY_FILE.to_string())),
        known_hosts_file: DEFAULT_VM_KNOWN_HOSTS.to_string(),
    }
}

#[tauri::command]
fn vm_discover(
    app: AppHandle,
    state: State<'_, AppState>,
    settings: FrontendVmSettings,
) -> Result<VmSnapshot, String> {
    {
        let inner = state
            .inner
            .lock()
            .map_err(|_| "state mutex poisoned".to_string())?;
        if let Some(vm) = inner.vm.as_ref() {
            return Ok(vm.snapshot.clone());
        }
    }
    let config = resolve_vm_paths(frontend_vm_config(settings))?;
    if let Ok(pid) = discover_marked_vm_pid(Path::new(&config.qemu_exe)) {
        let ssh_ready = check_vm_ssh(
            &config.ssh_user,
            config.ssh_forward_port,
            config.identity_file.as_deref(),
            &config.known_hosts_file,
        )
        .is_ok();
        let snapshot = VmSnapshot {
            state: if ssh_ready { VmState::Running } else { VmState::Starting },
            pid: Some(pid),
            ssh_forward_port: Some(config.ssh_forward_port),
            error: None,
            message: Some(if ssh_ready {
                "Подхвачена уже работающая GP Relay VM".into()
            } else {
                "GP Relay VM найдена по PID, ждём Ubuntu SSH".into()
            }),
            detail: Some(format!(
                "PID {pid} · {} · UUID {}",
                GP_RELAY_VM_NAME, GP_RELAY_VM_UUID
            )),
        };
        {
            let mut inner = state
                .inner
                .lock()
                .map_err(|_| "state mutex poisoned".to_string())?;
            if let Some(vm) = inner.vm.as_ref() {
                return Ok(vm.snapshot.clone());
            }
            inner.vm = Some(VmSession {
                child: None,
                snapshot: snapshot.clone(),
            });
        }
        emit_log(
            &app,
            "success",
            format!("QEMU: найдена наша VM по PID {pid}, имени {GP_RELAY_VM_NAME} и SSH-ключу"),
        );
        emit_vm_status(&app, snapshot.clone());
        if !ssh_ready {
            spawn_vm_readiness(
                app,
                AppState { inner: state.inner.clone() },
                config.ssh_forward_port,
                config.ssh_user,
                config.identity_file,
                config.known_hosts_file,
            );
        }
        return Ok(snapshot);
    }
    if config.boot_mode != VmBootMode::Disk
        || check_vm_ssh(
            &config.ssh_user,
            config.ssh_forward_port,
            config.identity_file.as_deref(),
            &config.known_hosts_file,
        )
        .is_err()
    {
        return Ok(stopped_vm_snapshot());
    }
    let snapshot = VmSnapshot {
        state: VmState::Running,
        pid: None,
        ssh_forward_port: Some(config.ssh_forward_port),
        error: None,
        message: Some("Подхвачена уже работающая Ubuntu VM".into()),
        detail: Some(format!(
            "{}@127.0.0.1:{} · внешний QEMU",
            config.ssh_user, config.ssh_forward_port
        )),
    };
    {
        let mut inner = state
            .inner
            .lock()
            .map_err(|_| "state mutex poisoned".to_string())?;
        if let Some(vm) = inner.vm.as_ref() {
            return Ok(vm.snapshot.clone());
        }
        inner.vm = Some(VmSession {
            child: None,
            snapshot: snapshot.clone(),
        });
    }
    emit_log(
        &app,
        "success",
        format!(
            "QEMU: обнаружена работающая Ubuntu на SSH-forward 127.0.0.1:{}",
            config.ssh_forward_port
        ),
    );
    emit_vm_status(&app, snapshot.clone());
    Ok(snapshot)
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
            vm_status,
            socks_status,
            socks_stop,
            vm_discover,
            vm_start,
            vm_stop,
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
    fn portable_paths_are_relative_to_the_executable_directory() {
        let base = Path::new(r"D:\Apps\GP Relay");
        assert_eq!(
            resolve_path_from(base, r"vm\ubuntu-gp.qcow2"),
            base.join(r"vm\ubuntu-gp.qcow2")
        );
        assert_eq!(
            resolve_path_from(base, r"E:\VMs\custom.qcow2"),
            PathBuf::from(r"E:\VMs\custom.qcow2")
        );
    }

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
    fn openconnect_command_keeps_only_portal_in_remote_command() {
        let command = openconnect_command("gp.domru.ru");
        assert!(command.starts_with("sudo -n openconnect --protocol=gp -- 'gp.domru.ru';"));
        assert!(command.contains("exit \"$status\""));
        assert!(!command.contains("password"));
        assert!(!command.contains("otp"));
    }

    #[test]
    fn socks_args_use_loopback_dynamic_forward_and_strict_host_key_options() {
        let args = socks_ssh_args(1080, 2222, "vpn", r"C:\key", r"C:\known_hosts");
        assert_eq!(args[0..8], [
            "-F",
            "none",
            "-N",
            "-T",
            "-n",
            "-D",
            "127.0.0.1:1080",
            "-o",
        ]);
        assert!(args.contains(&"BatchMode=yes".into()));
        assert!(args.contains(&"StrictHostKeyChecking=yes".into()));
        assert!(args.contains(&"ExitOnForwardFailure=yes".into()));
        assert!(args.contains(&"ServerAliveInterval=15".into()));
        assert!(args.contains(&"ServerAliveCountMax=3".into()));
        assert!(args.contains(&"-p".into()));
        assert!(args.contains(&"2222".into()));
        assert!(args.contains(&"vpn@127.0.0.1".into()));
        assert!(!args.iter().any(|arg| arg == "0.0.0.0:1080"));
    }

    #[test]
    fn config_rejects_invalid_socks_port() {
        let config = ConnectionConfig {
            host: "127.0.0.1".into(),
            port: 2222,
            ssh_user: "vpn".into(),
            portal: "gp.domru.ru".into(),
            identity_file: None,
            known_hosts_file: None,
            socks_port: 0,
            socks_enabled: true,
        };
        assert_eq!(validate_config(&config), Err("socksPort must be between 1 and 65535".into()));
    }
}
