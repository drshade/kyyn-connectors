#[cfg(any(test, all(target_arch = "wasm32", target_os = "unknown")))]
use std::collections::BTreeSet;

#[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
const DEFAULT_TENANT: &str = "organizations";
#[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
const DEFAULT_CLIENT_ID: &str = "53ddb21b-849f-45a3-8168-8a0e555f386f";

#[cfg(any(test, all(target_arch = "wasm32", target_os = "unknown")))]
fn normalized_capabilities(capabilities: &[String]) -> Result<Vec<String>, String> {
    const KNOWN: &[&str] = &[
        "calendar-read",
        "chats-read",
        "files-read",
        "files-write",
        "mail-read",
        "meetings-read",
    ];
    if capabilities.is_empty() {
        return Err("at least one Microsoft capability is required".into());
    }
    let values: BTreeSet<_> = capabilities.iter().cloned().collect();
    if values.len() != capabilities.len()
        || values
            .iter()
            .any(|capability| !KNOWN.contains(&capability.as_str()))
    {
        return Err("Microsoft capabilities must be unique advertised values".into());
    }
    Ok(values.into_iter().collect())
}

#[cfg(any(test, all(target_arch = "wasm32", target_os = "unknown")))]
fn scopes(capabilities: &[String]) -> Result<String, String> {
    let capabilities = normalized_capabilities(capabilities)?;
    let mut scopes = BTreeSet::from(["offline_access", "User.Read"]);
    for capability in capabilities {
        match capability.as_str() {
            "mail-read" => {
                scopes.insert("Mail.Read");
            }
            "calendar-read" => {
                scopes.insert("Calendars.Read");
            }
            "chats-read" => {
                scopes.insert("Chat.Read");
            }
            "meetings-read" => {
                scopes.insert("Calendars.Read");
                scopes.insert("OnlineMeetings.Read");
                scopes.insert("OnlineMeetingTranscript.Read.All");
                scopes.insert("OnlineMeetingArtifact.Read.All");
            }
            "files-read" => {
                scopes.insert("Files.Read.All");
                scopes.insert("Sites.Read.All");
            }
            "files-write" => {
                scopes.insert("Files.ReadWrite");
                scopes.insert("Sites.ReadWrite.All");
            }
            _ => unreachable!("normalized above"),
        }
    }
    Ok(scopes.into_iter().collect::<Vec<_>>().join(" "))
}

#[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
mod guest {
    mod bindings {
        wit_bindgen::generate!({
            path: "../../../wit/connection.wit",
            world: "connection",
        });
    }

    use super::{DEFAULT_CLIENT_ID, DEFAULT_TENANT, normalized_capabilities, scopes};
    use bindings::exports::kyyn::connection::api::{
        AuthChallenge, AuthPollResult, ConnectionStatus, Guest,
    };
    use bindings::kyyn::connection::http::{self, Method, Request, Response};
    use bindings::kyyn::connection::secrets;
    use serde::Deserialize;

    const ACCESS_TOKEN: &str = "ms-access-token";
    const REFRESH_TOKEN: &str = "ms-refresh-token";
    const CAPABILITIES: &str = "ms-capabilities";

    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Config {
        #[serde(default = "default_tenant")]
        tenant: String,
        #[serde(default = "default_client_id")]
        client_id: String,
    }

    fn default_tenant() -> String {
        DEFAULT_TENANT.into()
    }

    fn default_client_id() -> String {
        DEFAULT_CLIENT_ID.into()
    }

    fn parse(text: &str) -> Result<Config, String> {
        let value: ron::Value =
            ron::from_str(text).map_err(|error| format!("Microsoft connection config: {error}"))?;
        value.into_rust().map_err(|error| {
            format!("Microsoft connection config shape (tenant, client_id): {error}")
        })
    }

    fn validate(config: &Config) -> Result<(), String> {
        if config.tenant.is_empty()
            || !config
                .tenant
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
        {
            return Err("tenant must be organizations, a tenant GUID, or a tenant domain".into());
        }
        if config.client_id.is_empty()
            || !config
                .client_id
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        {
            return Err("client_id must be a public Entra application id".into());
        }
        Ok(())
    }

    fn encode(value: &str) -> String {
        let mut out = String::new();
        for byte in value.bytes() {
            match byte {
                b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                    out.push(byte as char)
                }
                _ => out.push_str(&format!("%{byte:02X}")),
            }
        }
        out
    }

    fn form(fields: &[(&str, &str)]) -> Vec<u8> {
        fields
            .iter()
            .map(|(name, value)| format!("{}={}", encode(name), encode(value)))
            .collect::<Vec<_>>()
            .join("&")
            .into_bytes()
    }

    fn request(config: &Config, endpoint: &str, fields: &[(&str, &str)]) -> Request {
        Request {
            method: Method::Post,
            url: format!(
                "https://login.microsoftonline.com/{}/oauth2/v2.0/{endpoint}",
                config.tenant
            ),
            headers: vec![
                ("accept".into(), "application/json".into()),
                (
                    "content-type".into(),
                    "application/x-www-form-urlencoded".into(),
                ),
            ],
            body: Some(form(fields)),
            max_response_bytes: 1024 * 1024,
            timeout_ms: 120_000,
        }
    }

    fn fetch(request: &Request) -> Result<Response, String> {
        http::fetch(request).map_err(|error| error.message)
    }

    fn json(response: &Response) -> Result<serde_json::Value, String> {
        serde_json::from_slice(&response.body)
            .map_err(|_| format!("Microsoft returned invalid JSON (HTTP {})", response.status))
    }

    fn stored_capabilities() -> Option<Vec<String>> {
        let bytes = secrets::get(CAPABILITIES)?;
        let text = std::str::from_utf8(&bytes).ok()?;
        Some(text.lines().map(str::to_string).collect())
    }

    fn store_capabilities(capabilities: &[String]) -> Result<Vec<String>, String> {
        let capabilities = normalized_capabilities(capabilities)?;
        secrets::put(CAPABILITIES, capabilities.join("\n").as_bytes())?;
        Ok(capabilities)
    }

    fn refresh(config: &Config, capabilities: &[String]) -> Result<(), String> {
        let refresh = secrets::get(REFRESH_TOKEN).ok_or("no refresh credential")?;
        let refresh =
            std::str::from_utf8(&refresh).map_err(|_| "invalid local refresh credential")?;
        let scope = scopes(capabilities)?;
        let response = fetch(&request(
            config,
            "token",
            &[
                ("grant_type", "refresh_token"),
                ("client_id", &config.client_id),
                ("refresh_token", refresh),
                ("scope", &scope),
            ],
        ))?;
        let body = json(&response)?;
        let Some(access) = body["access_token"].as_str() else {
            if matches!(
                body["error"].as_str(),
                Some("invalid_grant" | "invalid_client")
            ) {
                secrets::delete(ACCESS_TOKEN);
                secrets::delete(REFRESH_TOKEN);
                secrets::delete(CAPABILITIES);
            }
            return Err("Microsoft rejected the refresh credential".into());
        };
        secrets::put(ACCESS_TOKEN, access.as_bytes())?;
        if let Some(rotated) = body["refresh_token"].as_str() {
            secrets::put(REFRESH_TOKEN, rotated.as_bytes())?;
        }
        Ok(())
    }

    struct Microsoft;

    impl Guest for Microsoft {
        fn validate_config(config: String) -> Result<(), String> {
            validate(&parse(&config)?)
        }

        fn status(config: String, capabilities: Vec<String>) -> Result<ConnectionStatus, String> {
            let config = parse(&config)?;
            validate(&config)?;
            let capabilities = normalized_capabilities(&capabilities)?;
            if stored_capabilities().as_ref() != Some(&capabilities) {
                return Ok(ConnectionStatus::NotEnrolled(
                    "the accepted capability set needs owner sign-in".into(),
                ));
            }
            if secrets::get(REFRESH_TOKEN).is_none() {
                return Ok(ConnectionStatus::NotEnrolled("no local credential".into()));
            }
            Ok(match refresh(&config, &capabilities) {
                Ok(()) => ConnectionStatus::Enrolled("Microsoft account".into()),
                Err(reason) => ConnectionStatus::Expired(reason),
            })
        }

        fn auth_begin(config: String, capabilities: Vec<String>) -> Result<AuthChallenge, String> {
            let config = parse(&config)?;
            validate(&config)?;
            let scope = scopes(&capabilities)?;
            let response = fetch(&request(
                &config,
                "devicecode",
                &[("client_id", &config.client_id), ("scope", &scope)],
            ))?;
            let body = json(&response)?;
            Ok(AuthChallenge {
                verification_url: body["verification_uri"]
                    .as_str()
                    .ok_or("Microsoft did not start device sign-in")?
                    .into(),
                user_code: body["user_code"].as_str().ok_or("no user code")?.into(),
                expires_in_secs: body["expires_in"].as_u64().unwrap_or(900),
                handle: body["device_code"].as_str().ok_or("no device code")?.into(),
            })
        }

        fn auth_poll(
            config: String,
            capabilities: Vec<String>,
            handle: String,
        ) -> Result<AuthPollResult, String> {
            let config = parse(&config)?;
            validate(&config)?;
            let capabilities = normalized_capabilities(&capabilities)?;
            let response = fetch(&request(
                &config,
                "token",
                &[
                    ("grant_type", "urn:ietf:params:oauth:grant-type:device_code"),
                    ("client_id", &config.client_id),
                    ("device_code", &handle),
                ],
            ))?;
            let body = json(&response)?;
            if let Some(access) = body["access_token"].as_str() {
                let refresh = body["refresh_token"]
                    .as_str()
                    .ok_or("Microsoft returned no refresh credential")?;
                secrets::put(ACCESS_TOKEN, access.as_bytes())?;
                secrets::put(REFRESH_TOKEN, refresh.as_bytes())?;
                store_capabilities(&capabilities)?;
                return Ok(AuthPollResult::Done("Microsoft account".into()));
            }
            Ok(match body["error"].as_str() {
                Some("authorization_pending" | "slow_down") => AuthPollResult::Pending,
                Some(error) => {
                    AuthPollResult::Failed(format!("Microsoft sign-in failed ({error})"))
                }
                None => AuthPollResult::Failed("unexpected Microsoft sign-in response".into()),
            })
        }

        fn disconnect() -> Result<(), String> {
            secrets::delete(ACCESS_TOKEN);
            secrets::delete(REFRESH_TOKEN);
            secrets::delete(CAPABILITIES);
            Ok(())
        }
    }

    bindings::export!(Microsoft with_types_in bindings);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn file_read_never_implies_write() {
        let value = scopes(&["files-read".into()]).expect("known capability");
        assert!(value.contains("Files.Read.All"));
        assert!(value.contains("Sites.Read.All"));
        assert!(!value.contains("Files.ReadWrite"));
    }

    #[test]
    fn capability_union_is_exact_sorted_and_rejects_duplicates() {
        let value = scopes(&["files-write".into(), "mail-read".into()]).expect("known union");
        assert_eq!(
            value,
            "Files.ReadWrite Mail.Read Sites.ReadWrite.All User.Read offline_access"
        );
        assert!(normalized_capabilities(&["mail-read".into(), "mail-read".into()]).is_err());
        assert!(normalized_capabilities(&["directory-admin".into()]).is_err());
    }
}
