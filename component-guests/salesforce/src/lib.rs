#[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
mod guest {
    mod bindings {
        wit_bindgen::generate!({
            path: "../../wit",
            world: "tap",
        });
    }

    use bindings::exports::kyyn::tap::api::{
        AuthChallenge, AuthPollResult, AuthStatus, FetchRequest, FetchResult, FetchStyle, Guest,
        Item, PluginDescribe, RunSpec,
    };
    use bindings::kyyn::tap::http::{self, Method, Request, Response};
    use bindings::kyyn::tap::{control, evidence, secrets};
    use serde::Deserialize;
    use sha2::Digest as _;

    const ACCESS_TOKEN: &str = "sf-access-token";
    const REFRESH_TOKEN: &str = "sf-refresh-token";
    const RESPONSE_CAP: u64 = 64 * 1024 * 1024;

    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Config {
        instance_url: String,
        client_id: String,
        query: String,
        #[serde(default = "default_kind")]
        kind: String,
        #[serde(default = "default_api_version")]
        api_version: String,
        #[serde(default = "default_id_field")]
        id_field: String,
    }

    fn default_kind() -> String {
        "sf-record".into()
    }

    fn default_api_version() -> String {
        "v62.0".into()
    }

    fn default_id_field() -> String {
        "Id".into()
    }

    fn parse_config(text: &str) -> Result<Config, String> {
        let value: ron::Value =
            ron::from_str(text).map_err(|error| format!("salesforce config: {error}"))?;
        value.into_rust().map_err(|error| {
            format!(
                "salesforce config shape (instance_url, client_id, query; optional kind, \
                 api_version, id_field): {error}"
            )
        })
    }

    fn host_of(url: &str) -> String {
        url.trim_start_matches("https://")
            .split('/')
            .next()
            .unwrap_or("salesforce")
            .into()
    }

    fn validate(config: &Config) -> Result<(), String> {
        if !config.instance_url.starts_with("https://") {
            return Err("instance_url must be an https:// URL (the org's My Domain)".into());
        }
        if config.client_id.trim().is_empty() {
            return Err("client_id (the Connected App's consumer key) is required".into());
        }
        if !config
            .query
            .trim()
            .to_ascii_lowercase()
            .starts_with("select")
        {
            return Err("query must be a SOQL SELECT".into());
        }
        if config.kind.is_empty()
            || !config
                .kind
                .chars()
                .all(|ch| ch.is_ascii_alphanumeric() || ch == '-')
        {
            return Err(format!("kind '{}' must be a bare token", config.kind));
        }
        Ok(())
    }

    fn percent_encode(value: &str) -> String {
        let mut encoded = String::with_capacity(value.len() * 3);
        for byte in value.bytes() {
            match byte {
                b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                    encoded.push(byte as char)
                }
                _ => encoded.push_str(&format!("%{byte:02X}")),
            }
        }
        encoded
    }

    fn form(fields: &[(&str, &str)]) -> Vec<u8> {
        fields
            .iter()
            .map(|(name, value)| format!("{}={}", percent_encode(name), percent_encode(value)))
            .collect::<Vec<_>>()
            .join("&")
            .into_bytes()
    }

    fn request(
        method: Method,
        url: String,
        body: Option<Vec<u8>>,
        authorization: Option<&str>,
    ) -> Request {
        Request {
            method,
            url,
            headers: vec![
                ("accept".into(), "application/json".into()),
                (
                    "content-type".into(),
                    "application/x-www-form-urlencoded".into(),
                ),
            ],
            body,
            secret_authorization: authorization.map(str::to_string),
            max_response_bytes: RESPONSE_CAP,
            timeout_ms: 120_000,
        }
    }

    fn json(response: &Response) -> Result<serde_json::Value, String> {
        serde_json::from_slice(&response.body).map_err(|error| {
            format!(
                "invalid Salesforce JSON (HTTP {}): {error}",
                response.status
            )
        })
    }

    fn token_url(config: &Config) -> String {
        format!("{}/services/oauth2/token", config.instance_url)
    }

    struct Salesforce;

    impl Guest for Salesforce {
        fn describe() -> PluginDescribe {
            PluginDescribe {
                name: "salesforce".into(),
                link_namespace: "sf".into(),
                fetch_style: FetchStyle::Snapshot,
                auth_realm: Some("salesforce".into()),
            }
        }

        fn validate_config(config: String) -> Result<(), String> {
            validate(&parse_config(&config)?)
        }

        fn config_auth_realm(config: String) -> Result<Option<String>, String> {
            let config = parse_config(&config)?;
            Ok(Some(format!(
                "salesforce:{}:{}",
                host_of(&config.instance_url),
                config.client_id
            )))
        }

        fn status(_config: String) -> Result<AuthStatus, String> {
            if secrets::get(ACCESS_TOKEN).is_some() {
                Ok(AuthStatus::Authenticated(
                    "token cached (verified on fetch)".into(),
                ))
            } else {
                Ok(AuthStatus::NotAuthenticated(
                    "no token — sign the realm in first".into(),
                ))
            }
        }

        fn auth_begin(config: String) -> Result<AuthChallenge, String> {
            let config = parse_config(&config)?;
            validate(&config)?;
            let response = http::fetch(&request(
                Method::Post,
                token_url(&config),
                Some(form(&[
                    ("response_type", "device_code"),
                    ("client_id", &config.client_id),
                    ("scope", "api refresh_token"),
                ])),
                None,
            ))
            .map_err(|error| error.message)?;
            let body = json(&response)?;
            let field = |name: &str| body[name].as_str().map(str::to_string);
            Ok(AuthChallenge {
                verification_url: field("verification_uri")
                    .ok_or_else(|| format!("device flow refused: {body}"))?,
                user_code: field("user_code").ok_or("no user_code")?,
                expires_in_secs: body["expires_in"].as_u64().unwrap_or(600),
                handle: field("device_code").ok_or("no device_code")?,
            })
        }

        fn auth_poll(config: String, handle: String) -> Result<AuthPollResult, String> {
            let config = parse_config(&config)?;
            let response = http::fetch(&request(
                Method::Post,
                token_url(&config),
                Some(form(&[
                    ("grant_type", "device"),
                    ("client_id", &config.client_id),
                    ("code", &handle),
                ])),
                None,
            ))
            .map_err(|error| error.message)?;
            let body = json(&response)?;
            if let Some(token) = body["access_token"].as_str() {
                secrets::put(ACCESS_TOKEN, token.as_bytes())?;
                if let Some(refresh) = body["refresh_token"].as_str() {
                    secrets::put(REFRESH_TOKEN, refresh.as_bytes())?;
                }
                return Ok(AuthPollResult::Done("signed in".into()));
            }
            match body["error"].as_str() {
                Some("authorization_pending") | Some("slow_down") => Ok(AuthPollResult::Pending),
                Some(error) => Ok(AuthPollResult::Failed(format!(
                    "{error}: {}",
                    body["error_description"].as_str().unwrap_or("")
                ))),
                None => Ok(AuthPollResult::Failed(format!(
                    "unexpected reply (HTTP {}): {body}",
                    response.status
                ))),
            }
        }

        fn fetch(request: FetchRequest) -> Result<FetchResult, String> {
            if !matches!(request.spec, RunSpec::Snapshot) {
                return Err("salesforce is a snapshot source".into());
            }
            let config = parse_config(&request.config)?;
            validate(&config)?;
            run_query(&config)
        }
    }

    fn refresh(config: &Config) -> Result<(), String> {
        let refresh = secrets::get(REFRESH_TOKEN)
            .ok_or("token expired and no refresh token — sign in again")?;
        let refresh =
            std::str::from_utf8(&refresh).map_err(|_| "stored refresh token is not UTF-8")?;
        let response = http::fetch(&request(
            Method::Post,
            token_url(config),
            Some(form(&[
                ("grant_type", "refresh_token"),
                ("client_id", &config.client_id),
                ("refresh_token", refresh),
            ])),
            None,
        ))
        .map_err(|error| error.message)?;
        let body = json(&response)?;
        let token = body["access_token"]
            .as_str()
            .ok_or_else(|| format!("token refresh failed — sign in again ({body})"))?;
        secrets::put(ACCESS_TOKEN, token.as_bytes())
    }

    fn run_query(config: &Config) -> Result<FetchResult, String> {
        if secrets::get(ACCESS_TOKEN).is_none() {
            return Err("no token — sign the realm in first".into());
        }
        let first_url = format!(
            "{}/services/data/{}/query?q={}",
            config.instance_url,
            config.api_version,
            percent_encode(&config.query)
        );
        let mut records = Vec::new();
        let mut next = Some(first_url);
        let mut refreshed = false;
        let mut pages = 0u32;
        while let Some(url) = next.take() {
            let response =
                http::fetch(&request(Method::Get, url.clone(), None, Some(ACCESS_TOKEN)))
                    .map_err(|error| error.message)?;
            if response.status == 401 && !refreshed {
                refresh(config)?;
                refreshed = true;
                next = Some(url);
                continue;
            }
            if !(200..300).contains(&response.status) {
                return Err(format!(
                    "SOQL query failed (HTTP {}): {}",
                    response.status,
                    String::from_utf8_lossy(&response.body)
                ));
            }
            let page = json(&response)?;
            if let Some(batch) = page["records"].as_array() {
                records.extend(batch.iter().cloned());
            }
            next = page["nextRecordsUrl"]
                .as_str()
                .map(|path| format!("{}{}", config.instance_url, path));
            pages += 1;
            if next.is_some() {
                control::progress(&format!("{} records ({pages} pages)…", records.len()));
            }
            if pages >= 500 {
                return Err("paging exceeded 500 pages — narrow the query".into());
            }
        }

        let bundle = serde_json::to_vec_pretty(&records).map_err(|error| error.to_string())?;
        let file = evidence::open("records.json")?;
        file.write(&bundle)?;
        let _stored = file.finish()?;
        let mut items = Vec::new();
        for (index, record) in records.iter().enumerate() {
            let id = record[&config.id_field]
                .as_str()
                .map(str::to_string)
                .unwrap_or_else(|| format!("row-{index}"));
            let canonical = serde_json::to_vec(record).map_err(|error| error.to_string())?;
            let name = record["Name"].as_str().unwrap_or_default();
            let sobject = record["attributes"]["type"].as_str().unwrap_or("record");
            items.push(Item {
                id: id.clone(),
                kind: config.kind.clone(),
                version: None,
                content_hash: format!("{:x}", sha2::Sha256::digest(&canonical)),
                files: vec!["records.json".into()],
                file_hashes: Vec::new(),
                locator: Some(id),
                meta: format!("{sobject} · {name}"),
            });
        }
        control::progress(&format!("{} records returned", items.len()));
        Ok(FetchResult {
            notes: format!("{} record(s) from SOQL", items.len()),
            items,
            next_checkpoint: None,
        })
    }

    bindings::export!(Salesforce with_types_in bindings);
}
