#[cfg(any(test, all(target_arch = "wasm32", target_os = "unknown")))]
fn validate_capabilities(capabilities: &[String]) -> Result<(), String> {
    if capabilities.len() != 1 || capabilities[0] != "api" {
        return Err("Salesforce enrollment requires exactly the api capability".into());
    }
    Ok(())
}

#[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
const CLIENT_SECRET_RECIPE: &str = "client-secret";

#[cfg(any(test, all(target_arch = "wasm32", target_os = "unknown")))]
fn validate_client_secret(value: &[u8]) -> Result<&str, String> {
    let value = std::str::from_utf8(value)
        .map_err(|_| "Salesforce workload client secret must be UTF-8")?;
    if value.is_empty() {
        return Err("Salesforce workload client secret must not be empty".into());
    }
    Ok(value)
}

#[cfg(any(test, all(target_arch = "wasm32", target_os = "unknown")))]
fn ensure_workload_response(status: u16) -> Result<(), String> {
    if !(200..300).contains(&status) {
        return Err(format!(
            "Salesforce rejected the workload credential (HTTP {status})"
        ));
    }
    Ok(())
}

#[cfg(any(test, all(target_arch = "wasm32", target_os = "unknown")))]
#[derive(Debug, PartialEq, Eq)]
enum LocalCredentialStatus {
    NotEnrolled,
    Incomplete,
    Enrolled,
}

#[cfg(any(test, all(target_arch = "wasm32", target_os = "unknown")))]
fn local_credential_status(has_access: bool, has_refresh: bool) -> LocalCredentialStatus {
    match (has_access, has_refresh) {
        (false, false) => LocalCredentialStatus::NotEnrolled,
        (true, true) => LocalCredentialStatus::Enrolled,
        _ => LocalCredentialStatus::Incomplete,
    }
}

#[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
mod guest {
    mod bindings {
        wit_bindgen::generate!({
            path: "../../../wit/connection.wit",
            world: "connection",
        });
    }

    use super::{
        CLIENT_SECRET_RECIPE, LocalCredentialStatus, ensure_workload_response,
        local_credential_status, validate_capabilities, validate_client_secret,
    };
    use bindings::exports::kyyn::connection::api::{
        AuthChallenge, AuthPollResult, ConnectionStatus, Guest, RequestAuthorization,
    };
    use bindings::kyyn::connection::http::{self, Method, Request, Response};
    use bindings::kyyn::connection::invocation_inputs;
    use bindings::kyyn::connection::secrets;
    use serde::Deserialize;

    const ACCESS_TOKEN: &str = "sf-access-token";
    const REFRESH_TOKEN: &str = "sf-refresh-token";
    const CAPABILITIES: &str = "sf-capabilities";

    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Config {
        instance_url: String,
        client_id: String,
    }

    fn parse(text: &str) -> Result<Config, String> {
        let value: ron::Value = ron::from_str(text)
            .map_err(|error| format!("Salesforce connection config: {error}"))?;
        value.into_rust().map_err(|error| {
            format!("Salesforce connection config shape (instance_url, client_id): {error}")
        })
    }

    fn validate(config: &Config) -> Result<(), String> {
        if !config.instance_url.starts_with("https://") || config.instance_url.ends_with('/') {
            return Err("instance_url must be the exact HTTPS My Domain origin".into());
        }
        if config.client_id.trim().is_empty() {
            return Err("client_id (Connected App consumer key) is required".into());
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

    fn request(config: &Config, fields: &[(&str, &str)]) -> Request {
        Request {
            method: Method::Post,
            url: format!("{}/services/oauth2/token", config.instance_url),
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

    fn json(response: &Response) -> Result<serde_json::Value, String> {
        serde_json::from_slice(&response.body).map_err(|_| {
            format!(
                "Salesforce returned invalid JSON (HTTP {})",
                response.status
            )
        })
    }

    fn fetch(request: &Request) -> Result<Response, String> {
        http::fetch(request).map_err(|error| error.message)
    }

    fn capabilities_match(requested: &[String]) -> bool {
        let mut requested = requested.to_vec();
        requested.sort();
        secrets::get(CAPABILITIES).is_some_and(|stored| stored == requested.join("\n").as_bytes())
    }

    fn store_capabilities(capabilities: &[String]) -> Result<(), String> {
        let mut capabilities = capabilities.to_vec();
        capabilities.sort();
        secrets::put(CAPABILITIES, capabilities.join("\n").as_bytes())
    }

    fn refresh(config: &Config) -> Result<(), String> {
        let refresh = secrets::get(REFRESH_TOKEN).ok_or("no refresh credential")?;
        let refresh =
            std::str::from_utf8(&refresh).map_err(|_| "invalid local refresh credential")?;
        let response = fetch(&request(
            config,
            &[
                ("grant_type", "refresh_token"),
                ("client_id", &config.client_id),
                ("refresh_token", refresh),
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
            return Err("Salesforce rejected the refresh credential".into());
        };
        secrets::put(ACCESS_TOKEN, access.as_bytes())?;
        if let Some(rotated) = body["refresh_token"].as_str() {
            secrets::put(REFRESH_TOKEN, rotated.as_bytes())?;
        }
        Ok(())
    }

    fn workload_recipe_selected() -> Result<bool, String> {
        match invocation_inputs::recipe() {
            None => Ok(false),
            Some(recipe) if recipe == CLIENT_SECRET_RECIPE => Ok(true),
            Some(_) => Err("unsupported Salesforce workload recipe".into()),
        }
    }

    fn workload_secret() -> Result<Vec<u8>, String> {
        let value = invocation_inputs::get(CLIENT_SECRET_RECIPE)
            .map_err(|_| "Salesforce workload client secret is unavailable")?;
        validate_client_secret(&value)?;
        Ok(value)
    }

    fn workload_authorization(config: &Config) -> Result<RequestAuthorization, String> {
        let secret = workload_secret()?;
        let secret = validate_client_secret(&secret)?;
        let response = fetch(&request(
            config,
            &[
                ("grant_type", "client_credentials"),
                ("client_id", &config.client_id),
                ("client_secret", secret),
            ],
        ))?;
        ensure_workload_response(response.status)?;
        let body = json(&response)?;
        let access = body["access_token"]
            .as_str()
            .filter(|value| !value.is_empty())
            .ok_or("Salesforce returned no workload access token")?;
        Ok(RequestAuthorization::Bearer(access.into()))
    }

    struct Salesforce;

    impl Guest for Salesforce {
        fn validate_config(config: String) -> Result<(), String> {
            validate(&parse(&config)?)
        }

        fn status(config: String, capabilities: Vec<String>) -> Result<ConnectionStatus, String> {
            let config = parse(&config)?;
            validate(&config)?;
            validate_capabilities(&capabilities)?;
            if workload_recipe_selected()? {
                workload_authorization(&config)?;
                return Ok(ConnectionStatus::Enrolled(
                    "Salesforce workload application (credential verified)".into(),
                ));
            }
            if !capabilities_match(&capabilities) {
                return Ok(ConnectionStatus::NotEnrolled(
                    "the accepted capability set needs owner sign-in".into(),
                ));
            }
            Ok(
                match local_credential_status(
                    secrets::get(ACCESS_TOKEN).is_some(),
                    secrets::get(REFRESH_TOKEN).is_some(),
                ) {
                    LocalCredentialStatus::NotEnrolled => {
                        ConnectionStatus::NotEnrolled("no local credential".into())
                    }
                    LocalCredentialStatus::Incomplete => {
                        ConnectionStatus::Expired("local credential is incomplete".into())
                    }
                    LocalCredentialStatus::Enrolled => {
                        ConnectionStatus::Enrolled("Salesforce account".into())
                    }
                },
            )
        }

        fn authorization(
            config: String,
            capabilities: Vec<String>,
        ) -> Result<RequestAuthorization, String> {
            let config = parse(&config)?;
            validate(&config)?;
            validate_capabilities(&capabilities)?;
            if workload_recipe_selected()? {
                return workload_authorization(&config);
            }
            if !capabilities_match(&capabilities) {
                return Err("the accepted capability set needs owner sign-in".into());
            }
            refresh(&config)?;
            let token = secrets::get(ACCESS_TOKEN).ok_or("no local credential")?;
            let token = String::from_utf8(token).map_err(|_| "invalid local credential")?;
            Ok(RequestAuthorization::Bearer(token))
        }

        fn auth_begin(config: String, capabilities: Vec<String>) -> Result<AuthChallenge, String> {
            let config = parse(&config)?;
            validate(&config)?;
            validate_capabilities(&capabilities)?;
            let response = fetch(&request(
                &config,
                &[
                    ("response_type", "device_code"),
                    ("client_id", &config.client_id),
                    ("scope", "api refresh_token"),
                ],
            ))?;
            let body = json(&response)?;
            Ok(AuthChallenge {
                verification_url: body["verification_uri"]
                    .as_str()
                    .ok_or("Salesforce did not start device sign-in")?
                    .into(),
                user_code: body["user_code"].as_str().ok_or("no user code")?.into(),
                expires_in_secs: body["expires_in"].as_u64().unwrap_or(600),
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
            validate_capabilities(&capabilities)?;
            let response = fetch(&request(
                &config,
                &[
                    ("grant_type", "device"),
                    ("client_id", &config.client_id),
                    ("code", &handle),
                ],
            ))?;
            let body = json(&response)?;
            if let Some(access) = body["access_token"].as_str() {
                let refresh = body["refresh_token"]
                    .as_str()
                    .ok_or("Salesforce returned no refresh credential")?;
                secrets::put(ACCESS_TOKEN, access.as_bytes())?;
                secrets::put(REFRESH_TOKEN, refresh.as_bytes())?;
                store_capabilities(&capabilities)?;
                return Ok(AuthPollResult::Done("Salesforce account".into()));
            }
            Ok(match body["error"].as_str() {
                Some("authorization_pending" | "slow_down") => AuthPollResult::Pending,
                Some(error) => {
                    AuthPollResult::Failed(format!("Salesforce sign-in failed ({error})"))
                }
                None => AuthPollResult::Failed("unexpected Salesforce sign-in response".into()),
            })
        }

        fn disconnect() -> Result<(), String> {
            secrets::delete(ACCESS_TOKEN);
            secrets::delete(REFRESH_TOKEN);
            secrets::delete(CAPABILITIES);
            Ok(())
        }
    }

    bindings::export!(Salesforce with_types_in bindings);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_api_is_advertised() {
        assert!(validate_capabilities(&["api".into()]).is_ok());
        assert!(validate_capabilities(&[]).is_err());
        assert!(validate_capabilities(&["api".into(), "admin".into()]).is_err());
    }

    #[test]
    fn status_is_derived_from_local_credential_presence() {
        assert_eq!(
            local_credential_status(false, false),
            LocalCredentialStatus::NotEnrolled
        );
        assert_eq!(
            local_credential_status(true, false),
            LocalCredentialStatus::Incomplete
        );
        assert_eq!(
            local_credential_status(false, true),
            LocalCredentialStatus::Incomplete
        );
        assert_eq!(
            local_credential_status(true, true),
            LocalCredentialStatus::Enrolled
        );
    }

    #[test]
    fn workload_secret_is_nonempty_utf8_without_entering_diagnostics() {
        assert_eq!(
            validate_client_secret(b"runner-secret").unwrap(),
            "runner-secret"
        );
        assert_eq!(
            validate_client_secret(b"").unwrap_err(),
            "Salesforce workload client secret must not be empty"
        );
        assert_eq!(
            validate_client_secret(&[0xff]).unwrap_err(),
            "Salesforce workload client secret must be UTF-8"
        );
    }

    #[test]
    fn workload_http_failure_precedes_response_parsing() {
        assert_eq!(
            ensure_workload_response(502).unwrap_err(),
            "Salesforce rejected the workload credential (HTTP 502)"
        );
        assert!(ensure_workload_response(200).is_ok());
    }
}
