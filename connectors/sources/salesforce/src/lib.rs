#[cfg(any(test, all(target_arch = "wasm32", target_os = "unknown")))]
use serde::Deserialize;

#[cfg(any(test, all(target_arch = "wasm32", target_os = "unknown")))]
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ConnectionConfig {
    instance_url: String,
    #[serde(rename = "client_id")]
    _client_id: String,
}

#[cfg(any(test, all(target_arch = "wasm32", target_os = "unknown")))]
fn parse_connection_config(text: &str) -> Result<ConnectionConfig, String> {
    let value: ron::Value =
        ron::from_str(text).map_err(|error| format!("salesforce connection config: {error}"))?;
    value.into_rust().map_err(|error| {
        format!("salesforce connection config shape (instance_url, client_id): {error}")
    })
}

#[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
mod guest {
    mod bindings {
        wit_bindgen::generate!({
            path: "../../../wit/source.wit",
            world: "source",
        });
    }

    use super::parse_connection_config;
    use bindings::exports::kyyn::source::api::{
        AuthChallenge, AuthPollResult, AuthStatus, ConnectorDescribe, FetchCompletion,
        FetchRequest, FetchResult, FetchStyle, Guest, Item, RunSpec,
    };
    use bindings::kyyn::source::http::{self, Method, Purpose, Request, Response};
    use bindings::kyyn::source::{control, evidence};
    use serde::Deserialize;

    const RESPONSE_CAP: u64 = 64 * 1024 * 1024;

    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Config {
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
                "salesforce config shape (query; optional kind, \
                 api_version, id_field): {error}"
            )
        })
    }

    fn validate(config: &Config) -> Result<(), String> {
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

    fn request(
        purpose: Purpose,
        method: Method,
        url: String,
        body: Option<Vec<u8>>,
        authorization: Option<&str>,
    ) -> Request {
        Request {
            purpose,
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

    struct Salesforce;

    impl Guest for Salesforce {
        fn describe() -> ConnectorDescribe {
            ConnectorDescribe {
                name: "salesforce".into(),
                link_namespace: "sf".into(),
                fetch_style: FetchStyle::Snapshot,
                auth_realm: None,
            }
        }

        fn validate_config(config: String) -> Result<(), String> {
            validate(&parse_config(&config)?)
        }

        fn config_auth_realm(_config: String) -> Result<Option<String>, String> {
            Ok(None)
        }

        fn status(_config: String) -> Result<AuthStatus, String> {
            Ok(AuthStatus::NotRequired)
        }

        fn auth_begin(_config: String) -> Result<AuthChallenge, String> {
            Err("authentication belongs to the selected named connection".into())
        }

        fn auth_poll(_config: String, _handle: String) -> Result<AuthPollResult, String> {
            Err("authentication belongs to the selected named connection".into())
        }

        fn fetch(request: FetchRequest) -> Result<FetchResult, String> {
            if !matches!(request.spec, RunSpec::Snapshot) {
                return Err("salesforce is a snapshot source".into());
            }
            let config = parse_config(&request.config)?;
            validate(&config)?;
            let connection = parse_connection_config(
                request
                    .connection_config
                    .as_deref()
                    .ok_or("salesforce requires a named connection")?,
            )?;
            if !connection.instance_url.starts_with("https://") {
                return Err("connection instance_url must be an https:// origin".into());
            }
            run_query(&config, &connection.instance_url)
        }
    }

    fn run_query(config: &Config, instance_url: &str) -> Result<FetchResult, String> {
        let first_url = format!(
            "{}/services/data/{}/query?q={}",
            instance_url,
            config.api_version,
            percent_encode(&config.query)
        );
        let mut records = Vec::new();
        let mut next = Some(first_url);
        let mut pages = 0u32;
        while let Some(url) = next.take() {
            let response = http::fetch(&request(
                Purpose::Observe,
                Method::Get,
                url.clone(),
                None,
                None,
            ))
            .map_err(|error| error.message)?;
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
                .map(|path| format!("{instance_url}{path}"));
            pages += 1;
            if next.is_some() {
                control::progress(&format!("{} records ({pages} pages)…", records.len()));
            }
            if pages >= 500 {
                return Err("paging exceeded 500 pages — narrow the query".into());
            }
        }

        for (index, record) in records.iter_mut().enumerate() {
            kyyn_source_bundle::ensure_locator_id(
                record,
                &config.id_field,
                format!("row-{index}"),
            )?;
        }
        let bundle = serde_json::to_vec_pretty(&records).map_err(|error| error.to_string())?;
        let file = evidence::open("records.json")?;
        file.write(&bundle)?;
        let _stored = file.finish()?;
        let mut items = Vec::new();
        for record in &records {
            let id = record["id"]
                .as_str()
                .expect("ensure_locator_id inserted a string")
                .to_string();
            let name = record["Name"].as_str().unwrap_or_default();
            let sobject = record["attributes"]["type"].as_str().unwrap_or("record");
            items.push(Item {
                id: id.clone(),
                kind: config.kind.clone(),
                version: None,
                content_hash: kyyn_source_bundle::canonical_record_sha256(record)
                    .map_err(|error| error.to_string())?,
                files: vec!["records.json".into()],
                file_hashes: Vec::new(),
                locator: Some(id),
                meta: format!("{sobject} · {name}"),
            });
        }
        control::progress(&format!("{} records returned", items.len()));
        Ok(FetchResult {
            completion: FetchCompletion::Complete,
            notes: format!("{} record(s) from SOQL", items.len()),
            items,
            next_checkpoint: None,
        })
    }

    bindings::export!(Salesforce with_types_in bindings);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn connection_config_accepts_engine_canonical_value_encoding() {
        let accepted: ron::Value = ron::from_str(
            r#"(
                instance_url: "https://example.my.salesforce.com",
                client_id: "consumer-key",
            )"#,
        )
        .unwrap();
        let wire = ron::ser::to_string_pretty(
            &accepted,
            ron::ser::PrettyConfig::default()
                .struct_names(false)
                .escape_strings(false),
        )
        .unwrap();

        let parsed = parse_connection_config(&wire).unwrap();
        assert_eq!(parsed.instance_url, "https://example.my.salesforce.com");
        assert_eq!(parsed._client_id, "consumer-key");
    }
}
