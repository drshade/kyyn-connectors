#[cfg(any(test, all(target_arch = "wasm32", target_os = "unknown")))]
fn validate_capabilities(capabilities: &[String]) -> Result<(), String> {
    if capabilities.len() != 1 || capabilities[0] != "api" {
        return Err("Salesforce enrollment requires exactly the api capability".into());
    }
    Ok(())
}

#[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
mod guest {
    mod bindings {
        wit_bindgen::generate!({
            path: "../../../wit/connection.wit",
            world: "connection",
        });
    }

    use super::validate_capabilities;
    use bindings::exports::kyyn::connection::api::{
        AuthChallenge, AuthPollResult, ConnectionStatus, Guest,
    };
    use bindings::kyyn::connection::http::{self, Method, Request, Response};
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

    struct Salesforce;

    impl Guest for Salesforce {
        fn validate_config(config: String) -> Result<(), String> {
            validate(&parse(&config)?)
        }

        fn status(config: String, capabilities: Vec<String>) -> Result<ConnectionStatus, String> {
            let config = parse(&config)?;
            validate(&config)?;
            validate_capabilities(&capabilities)?;
            if !capabilities_match(&capabilities) {
                return Ok(ConnectionStatus::NotEnrolled(
                    "the accepted capability set needs owner sign-in".into(),
                ));
            }
            if secrets::get(REFRESH_TOKEN).is_none() {
                return Ok(ConnectionStatus::NotEnrolled("no local credential".into()));
            }
            Ok(match refresh(&config) {
                Ok(()) => ConnectionStatus::Enrolled("Salesforce account".into()),
                Err(reason) => ConnectionStatus::Expired(reason),
            })
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
}
