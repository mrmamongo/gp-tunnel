use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use serde::{Deserialize, Serialize};
use std::{fs, io};
use tauri::{AppHandle, Manager};
#[cfg(target_os = "windows")]
use windows_sys::Win32::Foundation::LocalFree;
#[cfg(target_os = "windows")]
use windows_sys::Win32::Security::Cryptography::{
    CryptProtectData, CryptUnprotectData, CRYPTPROTECT_UI_FORBIDDEN, CRYPT_INTEGER_BLOB,
};

const CREDENTIAL_FILE: &str = "credentials.json";

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct StoredCredential {
    #[serde(default)]
    portal: Option<String>,
    username: String,
    protected_password: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct CredentialPayload {
    portal: Option<String>,
    username: String,
    password: String,
}

#[cfg(target_os = "windows")]
fn dpapi_protect(plaintext: &[u8]) -> Result<Vec<u8>, String> {
    let input = CRYPT_INTEGER_BLOB {
        cbData: plaintext
            .len()
            .try_into()
            .map_err(|_| "credential is too large")?,
        pbData: plaintext.as_ptr() as *mut u8,
    };
    let mut output = CRYPT_INTEGER_BLOB {
        cbData: 0,
        pbData: std::ptr::null_mut(),
    };
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
        return Err(format!(
            "DPAPI encryption failed: {}",
            std::io::Error::last_os_error()
        ));
    }
    let bytes =
        unsafe { std::slice::from_raw_parts(output.pbData, output.cbData as usize).to_vec() };
    unsafe { LocalFree(output.pbData as *mut std::ffi::c_void) };
    Ok(bytes)
}

#[cfg(target_os = "windows")]
fn dpapi_unprotect(ciphertext: &[u8]) -> Result<Vec<u8>, String> {
    let input = CRYPT_INTEGER_BLOB {
        cbData: ciphertext
            .len()
            .try_into()
            .map_err(|_| "credential is too large")?,
        pbData: ciphertext.as_ptr() as *mut u8,
    };
    let mut output = CRYPT_INTEGER_BLOB {
        cbData: 0,
        pbData: std::ptr::null_mut(),
    };
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
        return Err(format!(
            "DPAPI decryption failed: {}",
            std::io::Error::last_os_error()
        ));
    }
    let bytes =
        unsafe { std::slice::from_raw_parts(output.pbData, output.cbData as usize).to_vec() };
    unsafe { LocalFree(output.pbData as *mut std::ffi::c_void) };
    Ok(bytes)
}

fn credential_path(app: &AppHandle) -> Result<std::path::PathBuf, String> {
    app.path()
        .app_data_dir()
        .map(|directory| directory.join(CREDENTIAL_FILE))
        .map_err(|error| format!("could not resolve app data directory: {error}"))
}

#[cfg(not(target_os = "windows"))]
fn dpapi_protect(_: &[u8]) -> Result<Vec<u8>, String> {
    Err("DPAPI доступен только в Windows".into())
}
#[cfg(not(target_os = "windows"))]
fn dpapi_unprotect(_: &[u8]) -> Result<Vec<u8>, String> {
    Err("DPAPI доступен только в Windows".into())
}

#[cfg(all(test, target_os = "windows"))]
mod tests {
    use super::*;
    #[test]
    fn dpapi_round_trip() {
        let password = b"gp-relay-test-secret";
        let encrypted = dpapi_protect(password).unwrap();
        assert_ne!(encrypted, password);
        assert_eq!(dpapi_unprotect(&encrypted).unwrap(), password);
    }
    #[test]
    fn legacy_record_has_no_portal() {
        let record: StoredCredential =
            serde_json::from_str(r#"{"username":"user","protectedPassword":"AA=="}"#).unwrap();
        assert!(record.portal.is_none());
    }
}

pub(crate) fn save(
    app: &AppHandle,
    portal: String,
    username: String,
    password: String,
) -> Result<(), String> {
    if username.trim().is_empty() || username.len() > 255 {
        return Err("username is invalid".into());
    }
    if password.is_empty() || password.len() > 4096 {
        return Err("password is invalid".into());
    }
    let path = credential_path(&app)?;
    let parent = path.parent().ok_or("credential directory is invalid")?;
    fs::create_dir_all(parent)
        .map_err(|error| format!("could not create credential directory: {error}"))?;
    let protected_password = BASE64.encode(dpapi_protect(password.as_bytes())?);
    let record = StoredCredential {
        portal: Some(portal),
        username,
        protected_password,
    };
    let encoded = serde_json::to_vec(&record)
        .map_err(|error| format!("could not encode credential: {error}"))?;
    fs::write(path, encoded).map_err(|error| format!("could not save credential: {error}"))
}

#[tauri::command]
pub(crate) fn credential_load(app: AppHandle) -> Result<Option<CredentialPayload>, String> {
    let path = credential_path(&app)?;
    let encoded = match fs::read(path) {
        Ok(encoded) => encoded,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(format!("could not read credential: {error}")),
    };
    let record: StoredCredential = serde_json::from_slice(&encoded)
        .map_err(|error| format!("could not decode credential: {error}"))?;
    let ciphertext = BASE64
        .decode(record.protected_password)
        .map_err(|error| format!("credential base64 is invalid: {error}"))?;
    let password = String::from_utf8(dpapi_unprotect(&ciphertext)?)
        .map_err(|_| "decrypted credential is not UTF-8".to_string())?;
    Ok(Some(CredentialPayload {
        portal: record.portal,
        username: record.username,
        password,
    }))
}

#[tauri::command]
pub(crate) fn credential_delete(app: AppHandle) -> Result<(), String> {
    let path = credential_path(&app)?;
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(format!("could not delete credential: {error}")),
    }
}
