use crate::PromptKind;
pub(crate) fn find_ascii_ci(haystack: &str, needle: &str) -> Option<usize> {
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
pub(crate) fn parse_gateway_choices(text: &str) -> Option<Vec<String>> {
    let key_pos = find_ascii_ci(text, "gateway")?;
    let rest = &text[key_pos..];
    let open = rest.find('[')?;
    let close = rest[open + 1..].find(']')? + open + 1;
    let choices: Vec<String> = rest[open + 1..close]
        .split('|')
        .map(|item| {
            item.trim()
                .trim_matches(|c| c == '"' || c == '\'')
                .to_string()
        })
        .filter(|item| !item.is_empty() && item.len() <= 253)
        .collect();
    if choices.is_empty() {
        None
    } else {
        Some(choices)
    }
}

pub(crate) fn detect_prompt(text: &str) -> Option<PromptKind> {
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
    {
        Some(PromptKind::Mfa)
    } else if lower.contains("password") || lower.contains("passphrase") || lower.contains("пароль")
    {
        Some(PromptKind::Password)
    } else if lower.contains("username") || lower.contains("user name") || lower.contains("логин")
    {
        Some(PromptKind::Username)
    } else if (lower.contains("authgroup")
        || lower.contains("auth group")
        || lower.contains("gateway"))
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
    } else if lower.contains("challenge:") {
        Some(PromptKind::Challenge)
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

/// OpenConnect prints a server message followed by the generic "Challenge:".
/// The label alone says nothing about whether the server wants a password or OTP.
pub(crate) fn detect_interactive_prompt(text: &str) -> Option<PromptKind> {
    let mut lines = text.lines().rev().map(str::trim).filter(|l| !l.is_empty());
    let kind = detect_prompt(lines.next()?)?;
    if kind != PromptKind::Challenge {
        return Some(kind);
    }
    match lines.next().and_then(detect_prompt) {
        Some(PromptKind::Password) => Some(PromptKind::Password),
        Some(PromptKind::Mfa) => Some(PromptKind::Mfa),
        _ => Some(PromptKind::Challenge),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum OpenConnectStatus {
    Connected,
    Failed,
}

pub(crate) fn parse_openconnect_status(text: &str) -> Option<OpenConnectStatus> {
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
        || (lower.contains("configured as") && lower.contains("ssl connected"))
        || lower.contains("connected as")
    {
        return Some(OpenConnectStatus::Connected);
    }
    None
}

pub(crate) fn disconnect_bytes() -> &'static [u8] {
    // socat runs openconnect in a PTY inside the container; ETX is therefore
    // the portable equivalent of pressing Ctrl-C in the foreground process.
    &[0x03]
}

pub(crate) fn decode_utf8_chunk(pending: &mut Vec<u8>, chunk: &[u8]) -> String {
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

pub(crate) fn validate_token(value: &str, field: &str) -> Result<(), String> {
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
        assert_eq!(
            detect_prompt("Введите одноразовый код:"),
            Some(PromptKind::Mfa)
        );
        assert_eq!(detect_prompt("Challenge:"), Some(PromptKind::Challenge));
        assert_eq!(detect_prompt("AuthGroup:"), Some(PromptKind::Text));
        assert_eq!(detect_prompt("Choose gateway:"), Some(PromptKind::Text));
    }

    #[test]
    fn challenge_uses_server_message_instead_of_assuming_otp() {
        assert_eq!(
            detect_interactive_prompt("Enter your password\nChallenge: "),
            Some(PromptKind::Password)
        );
        assert_eq!(
            detect_interactive_prompt("Введите пароль:\r\nChallenge: "),
            Some(PromptKind::Password)
        );
        assert_eq!(
            detect_interactive_prompt("Enter your one-time password\nChallenge: "),
            Some(PromptKind::Mfa)
        );
        assert_eq!(
            detect_interactive_prompt("Enter verification code\nChallenge: "),
            Some(PromptKind::Mfa)
        );
        assert_eq!(
            detect_interactive_prompt("Challenge: "),
            Some(PromptKind::Challenge)
        );
        assert_eq!(
            detect_interactive_prompt("Approve the sign-in\nChallenge: "),
            Some(PromptKind::Challenge)
        );
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
        assert_eq!(
            detect_prompt("Введите одноразовый код:"),
            Some(PromptKind::Mfa)
        );
        assert_eq!(
            detect_prompt("Введите новый одноразовый код:"),
            Some(PromptKind::Mfa)
        );
        assert_eq!(detect_prompt("Last login: Sat Sep 12 19:51:28 2026"), None);
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
            parse_openconnect_status(
                "Configured as 10.0.0.1, with SSL connected and ESP established"
            ),
            Some(OpenConnectStatus::Connected)
        );
        assert_eq!(parse_openconnect_status("POST https://portal/"), None);
        assert_eq!(
            parse_openconnect_status("Configured as 10.0.0.1, with SSL connected and ESP disabled"),
            Some(OpenConnectStatus::Connected)
        );
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
        assert_eq!(
            parse_gateway_choices("GATEWAY: [single.host]:"),
            Some(vec!["single.host".to_string()])
        );
        // Юникод в выводе не должен ломать разбор списка.
        assert_eq!(
            parse_gateway_choices("Пожалуйста, выберите шлюз.\nGATEWAY: [a.example|b.example]:"),
            Some(vec!["a.example".to_string(), "b.example".to_string()])
        );
    }
}
