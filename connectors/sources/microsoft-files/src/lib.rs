#[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
mod guest {
    mod bindings {
        wit_bindgen::generate!({
            path: "../../../wit/source.wit",
            world: "source",
        });
    }

    use bindings::exports::kyyn::source::api::{
        AuthChallenge, AuthPollResult, AuthStatus, ConnectorDescribe, FetchRequest, FetchResult,
        FetchStyle, Guest, Item, RunSpec,
    };
    use bindings::kyyn::source::http::{self, Method, Purpose, Request, Response};
    use bindings::kyyn::source::{control, secrets};
    use serde::{Deserialize, Serialize};
    use std::collections::{BTreeMap, BTreeSet};

    const ACCESS_TOKEN: &str = "ms-access-token";
    const REFRESH_TOKEN: &str = "ms-refresh-token";
    const DEFAULT_CLIENT_ID: &str = "53ddb21b-849f-45a3-8168-8a0e555f386f";
    const READ_SCOPES: &str = "Files.Read.All Sites.Read.All offline_access openid profile";
    const GRAPH_ORIGIN: &str = "https://graph.microsoft.com";
    const RESPONSE_CAP: u64 = 64 * 1024 * 1024;
    const MAX_PAGES: u32 = 500;

    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Config {
        drive_id: String,
        item_id: String,
        item_kind: String,
        display_name: String,
        resolution: String,
        #[serde(default = "default_patterns")]
        patterns: Vec<String>,
        #[serde(default = "default_kind")]
        kind: String,
        #[serde(default = "default_max_file_bytes")]
        max_file_bytes: u64,
        #[serde(default = "default_client_id")]
        client_id: String,
        #[serde(default = "default_tenant")]
        tenant: String,
    }

    #[derive(Clone, Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct DriveItem {
        id: String,
        name: String,
        #[serde(rename = "eTag")]
        etag: Option<String>,
        last_modified_date_time: Option<String>,
        size: Option<u64>,
        folder: Option<serde_json::Value>,
        file: Option<serde_json::Value>,
        package: Option<serde_json::Value>,
        remote_item: Option<serde_json::Value>,
    }

    #[derive(Clone, Default, Deserialize, Serialize)]
    #[serde(deny_unknown_fields)]
    struct CheckpointEntry {
        path: String,
        version: String,
    }

    #[derive(Default, Deserialize, Serialize)]
    #[serde(deny_unknown_fields)]
    struct Checkpoint {
        #[serde(default)]
        items: BTreeMap<String, CheckpointEntry>,
    }

    struct Accumulator {
        items: Vec<Item>,
        checkpoint: BTreeMap<String, CheckpointEntry>,
        notes: Vec<String>,
    }

    type Candidate = (DriveItem, String);

    fn default_client_id() -> String {
        DEFAULT_CLIENT_ID.into()
    }

    fn default_tenant() -> String {
        "organizations".into()
    }

    fn default_patterns() -> Vec<String> {
        vec!["**/*".into()]
    }

    fn default_kind() -> String {
        "file".into()
    }

    fn default_max_file_bytes() -> u64 {
        RESPONSE_CAP
    }

    fn parse_config(text: &str) -> Result<Config, String> {
        let value: ron::Value =
            ron::from_str(text).map_err(|error| format!("Microsoft files config: {error}"))?;
        value.into_rust().map_err(|error| {
            format!(
                "Microsoft files config shape (drive_id, item_id, item_kind, display_name, resolution; optional patterns, kind, max_file_bytes, client_id, tenant): {error}"
            )
        })
    }

    fn path_segments(path: &str) -> Result<Vec<String>, String> {
        if path.starts_with('/') || path.ends_with('/') || path.contains('\\') {
            return Err("path must be a normalized library-relative path".into());
        }
        let segments: Vec<_> = path.split('/').map(str::to_string).collect();
        if segments.is_empty()
            || segments.iter().any(|segment| {
                segment.is_empty()
                    || matches!(segment.as_str(), "." | "..")
                    || segment.chars().any(char::is_control)
            })
        {
            return Err("path contains an empty, dot, or control-character segment".into());
        }
        Ok(segments)
    }

    fn validate(config: &Config) -> Result<(), String> {
        for (label, value) in [("drive_id", &config.drive_id), ("item_id", &config.item_id)] {
            if value.is_empty()
                || value.len() > 512
                || value
                    .chars()
                    .any(|ch| ch.is_control() || matches!(ch, '/' | '?' | '#'))
            {
                return Err(format!(
                    "{label} is not a valid canonical Microsoft identifier"
                ));
            }
        }
        if config.display_name.is_empty()
            || config.display_name.len() > 512
            || config.display_name.chars().any(char::is_control)
        {
            return Err("display_name is invalid".into());
        }
        if !matches!(config.item_kind.as_str(), "file" | "folder") {
            return Err("item_kind must be 'file' or 'folder'".into());
        }
        if !matches!(
            config.resolution.as_str(),
            "read-only" | "metadata-read-write"
        ) {
            return Err("resolution must be 'read-only' or 'metadata-read-write'".into());
        }
        if config.client_id.trim().is_empty() {
            return Err("client_id must not be empty".into());
        }
        if config.tenant.trim().is_empty()
            || !config
                .tenant
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.'))
        {
            return Err("tenant must be a tenant id or organizations".into());
        }
        if config.max_file_bytes == 0 || config.max_file_bytes > RESPONSE_CAP {
            return Err("max_file_bytes must be between 1 and 67108864".into());
        }
        if config.kind.is_empty()
            || !config
                .kind
                .chars()
                .all(|ch| ch.is_ascii_alphanumeric() || ch == '-')
        {
            return Err(format!("kind '{}' must be a bare token", config.kind));
        }
        for pattern in &config.patterns {
            glob::Pattern::new(pattern).map_err(|error| format!("pattern '{pattern}': {error}"))?;
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

    fn identity_url(config: &Config, endpoint: &str) -> String {
        format!(
            "https://login.microsoftonline.com/{}/oauth2/v2.0/{endpoint}",
            config.tenant
        )
    }

    fn scopes(config: &Config) -> &'static str {
        match config.resolution.as_str() {
            "metadata-read-write" => "Files.ReadWrite offline_access",
            _ => READ_SCOPES,
        }
    }

    fn realm_prefix(config: &Config) -> &'static str {
        match config.resolution.as_str() {
            "metadata-read-write" => "ms-files-resolve",
            _ => "ms-files-read",
        }
    }

    fn request(
        purpose: Purpose,
        method: Method,
        url: String,
        body: Option<Vec<u8>>,
        authorization: Option<&str>,
        max_response_bytes: u64,
    ) -> Request {
        Request {
            purpose,
            method,
            url,
            headers: if body.is_some() {
                vec![
                    ("accept".into(), "application/json".into()),
                    (
                        "content-type".into(),
                        "application/x-www-form-urlencoded".into(),
                    ),
                ]
            } else {
                vec![("accept".into(), "application/json".into())]
            },
            body,
            secret_authorization: authorization.map(str::to_string),
            max_response_bytes,
            timeout_ms: 120_000,
        }
    }

    fn json(response: &Response) -> Result<serde_json::Value, String> {
        serde_json::from_slice(&response.body)
            .map_err(|error| format!("invalid Graph JSON (HTTP {}): {error}", response.status))
    }

    fn token_error(body: &serde_json::Value) -> String {
        let code = body["error"].as_str().unwrap_or("token_error");
        let description = body["error_description"].as_str().unwrap_or("");
        format!("{code}: {description}")
    }

    fn refresh(config: &Config) -> Result<(), String> {
        let refresh = secrets::get(REFRESH_TOKEN)
            .ok_or("token expired and no refresh token — sign in again")?;
        let refresh =
            std::str::from_utf8(&refresh).map_err(|_| "stored refresh token is not UTF-8")?;
        let response = http::fetch(&request(
            Purpose::Authenticate,
            Method::Post,
            identity_url(config, "token"),
            Some(form(&[
                ("grant_type", "refresh_token"),
                ("client_id", &config.client_id),
                ("refresh_token", refresh),
                ("scope", scopes(config)),
            ])),
            None,
            RESPONSE_CAP,
        ))
        .map_err(|error| error.message)?;
        let body = json(&response)?;
        let Some(token) = body["access_token"].as_str() else {
            secrets::delete(ACCESS_TOKEN);
            secrets::delete(REFRESH_TOKEN);
            return Err(format!(
                "token refresh rejected — sign in again ({})",
                token_error(&body)
            ));
        };
        secrets::put(ACCESS_TOKEN, token.as_bytes())?;
        if let Some(rotated) = body["refresh_token"].as_str() {
            secrets::put(REFRESH_TOKEN, rotated.as_bytes())?;
        }
        Ok(())
    }

    fn graph_response(
        config: &Config,
        url: &str,
        refreshed: &mut bool,
    ) -> Result<Response, String> {
        for attempt in 1..=5u64 {
            let response = http::fetch(&request(
                Purpose::Observe,
                Method::Get,
                url.into(),
                None,
                Some(ACCESS_TOKEN),
                RESPONSE_CAP,
            ))
            .map_err(|error| error.message)?;
            if response.status == 401 && !*refreshed {
                refresh(config)?;
                *refreshed = true;
                continue;
            }
            if response.status == 401 {
                secrets::delete(ACCESS_TOKEN);
                return Err("Microsoft files token was rejected — sign in again".into());
            }
            if response.status == 429 && attempt < 5 {
                let retry_after = response
                    .headers
                    .iter()
                    .find(|(name, _)| name.eq_ignore_ascii_case("retry-after"))
                    .and_then(|(_, value)| value.parse::<u64>().ok())
                    .unwrap_or(5)
                    .min(60);
                control::progress(&format!(
                    "Graph rate limit; retrying after {retry_after}s ({attempt}/5)"
                ));
                control::sleep_ms(retry_after * 1_000);
                continue;
            }
            if response.status >= 500 && attempt < 5 {
                let delay = (1u64 << attempt).min(30);
                control::progress(&format!(
                    "Graph HTTP {}; retrying after {delay}s ({attempt}/5)",
                    response.status
                ));
                control::sleep_ms(delay * 1_000);
                continue;
            }
            return Ok(response);
        }
        Err("Graph GET exhausted retries".into())
    }

    fn graph_get(config: &Config, url: &str, refreshed: &mut bool) -> Result<Response, String> {
        let response = graph_response(config, url, refreshed)?;
        if !(200..300).contains(&response.status) {
            return Err(format!("Graph GET failed (HTTP {})", response.status));
        }
        Ok(response)
    }

    fn graph_pages(
        config: &Config,
        first_url: String,
        refreshed: &mut bool,
    ) -> Result<Vec<serde_json::Value>, String> {
        let mut records = Vec::new();
        let mut next = Some(first_url);
        let mut pages = 0u32;
        while let Some(url) = next.take() {
            let body = json(&graph_get(config, &url, refreshed)?)?;
            let values = body["value"]
                .as_array()
                .ok_or_else(|| "Graph collection has no value array".to_string())?;
            records.extend(values.iter().cloned());
            next = body["@odata.nextLink"].as_str().map(str::to_string);
            pages += 1;
            if pages >= MAX_PAGES && next.is_some() {
                return Err("Graph paging exceeded 500 pages — aborting".into());
            }
        }
        Ok(records)
    }

    fn children(
        config: &Config,
        drive_id: &str,
        parent_id: &str,
        refreshed: &mut bool,
    ) -> Result<Vec<DriveItem>, String> {
        let url = format!(
            "{GRAPH_ORIGIN}/v1.0/drives/{}/items/{}/children",
            percent_encode(drive_id),
            percent_encode(parent_id)
        );
        let mut children = graph_pages(config, url, refreshed)?
            .into_iter()
            .map(serde_json::from_value::<DriveItem>)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|error| format!("drive child shape: {error}"))?;
        children.sort_by(|left, right| left.name.cmp(&right.name));
        Ok(children)
    }

    fn target_item(config: &Config, refreshed: &mut bool) -> Result<DriveItem, String> {
        let url = format!(
            "{GRAPH_ORIGIN}/v1.0/drives/{}/items/{}",
            percent_encode(&config.drive_id),
            percent_encode(&config.item_id)
        );
        let body = json(&graph_get(config, &url, refreshed)?)?;
        serde_json::from_value(body).map_err(|error| format!("Microsoft drive item shape: {error}"))
    }

    fn safe_relative(path: &str) -> Result<(), String> {
        let _ = path_segments(path)?;
        Ok(())
    }

    fn folder_files(
        config: &Config,
        drive_id: &str,
        root: &DriveItem,
        root_path: &str,
        refreshed: &mut bool,
    ) -> Result<(Vec<Candidate>, Vec<String>), String> {
        let patterns = config
            .patterns
            .iter()
            .map(|pattern| {
                glob::Pattern::new(pattern).map_err(|error| format!("pattern '{pattern}': {error}"))
            })
            .collect::<Result<Vec<_>, _>>()?;
        let options = glob::MatchOptions {
            require_literal_separator: true,
            require_literal_leading_dot: true,
            ..Default::default()
        };
        let mut stack = vec![(root.id.clone(), String::new())];
        let mut files = Vec::new();
        let mut notes = Vec::new();
        while let Some((parent_id, folder_relative)) = stack.pop() {
            for item in children(config, drive_id, &parent_id, refreshed)? {
                let relative = if folder_relative.is_empty() {
                    item.name.clone()
                } else {
                    format!("{folder_relative}/{}", item.name)
                };
                safe_relative(&relative)
                    .map_err(|error| format!("unsafe SharePoint path '{relative}': {error}"))?;
                if item.folder.is_some() {
                    if item.package.is_some() || item.remote_item.is_some() {
                        notes.push(format!("skipped unsupported folder object '{relative}'"));
                    } else {
                        stack.push((item.id.clone(), relative));
                    }
                } else if item.file.is_none()
                    || item.package.is_some()
                    || item.remote_item.is_some()
                {
                    notes.push(format!("skipped unsupported object '{relative}'"));
                } else if patterns
                    .iter()
                    .any(|pattern| pattern.matches_with(&relative, options))
                {
                    files.push((item, format!("{root_path}/{relative}")));
                }
            }
        }
        files.sort_by(|left, right| left.1.cmp(&right.1));
        Ok((files, notes))
    }

    fn download(
        config: &Config,
        drive_id: &str,
        item: &DriveItem,
        evidence_path: &str,
    ) -> Result<http::StoredFile, String> {
        let url = format!(
            "{GRAPH_ORIGIN}/v1.0/drives/{}/items/{}/content",
            percent_encode(drive_id),
            percent_encode(&item.id)
        );
        let request = request(
            Purpose::Observe,
            Method::Get,
            url,
            None,
            Some(ACCESS_TOKEN),
            config.max_file_bytes,
        );
        let (status, stored) =
            http::fetch_to_evidence(&request, evidence_path).map_err(|error| error.message)?;
        if status == 401 {
            secrets::delete(ACCESS_TOKEN);
            return Err("Microsoft file content authorization expired — sign in again".into());
        }
        if !(200..300).contains(&status) {
            return Err(format!(
                "Microsoft file content download failed (HTTP {status}) for '{evidence_path}'"
            ));
        }
        Ok(stored)
    }

    fn version_of(item: &DriveItem, content_hash: Option<&str>) -> Option<String> {
        item.etag
            .clone()
            .or_else(|| item.last_modified_date_time.clone())
            .or_else(|| content_hash.map(str::to_string))
    }

    fn process_file(
        config: &Config,
        drive_id: &str,
        item: DriveItem,
        library_path: String,
        previous: Option<&CheckpointEntry>,
        accumulator: &mut Accumulator,
    ) -> Result<(), String> {
        if item.size.is_some_and(|size| size > config.max_file_bytes) {
            accumulator.notes.push(format!(
                "skipped '{library_path}' ({} bytes > {} cap)",
                item.size.unwrap_or_default(),
                config.max_file_bytes
            ));
            return Ok(());
        }
        let key = format!("{drive_id}:{}", item.id);
        let provider_version = version_of(&item, None);
        if let (Some(previous), Some(version)) = (previous, provider_version.as_deref())
            && previous.version == version
        {
            if previous.path != library_path {
                accumulator.notes.push(format!(
                    "observed rename '{}' → '{}' with unchanged provider version",
                    previous.path, library_path
                ));
            }
            accumulator.checkpoint.insert(
                key,
                CheckpointEntry {
                    path: library_path,
                    version: version.into(),
                },
            );
            return Ok(());
        }

        control::progress(&format!("downloading {library_path}…"));
        let stored = download(config, drive_id, &item, &library_path)?;
        let version = version_of(&item, Some(&stored.sha256)).expect("content hash supplied");
        if previous
            .is_some_and(|previous| previous.version == version && previous.path == library_path)
        {
            accumulator.checkpoint.insert(
                key,
                CheckpointEntry {
                    path: library_path,
                    version,
                },
            );
            return Ok(());
        }
        accumulator.checkpoint.insert(
            key.clone(),
            CheckpointEntry {
                path: library_path.clone(),
                version: version.clone(),
            },
        );
        accumulator.items.push(Item {
            id: key,
            kind: config.kind.clone(),
            version: item.etag.clone().or(item.last_modified_date_time.clone()),
            content_hash: stored.sha256,
            files: vec![library_path.clone()],
            file_hashes: Vec::new(),
            locator: Some(format!(
                "microsoft-file:{}/{}",
                percent_encode(&config.drive_id),
                percent_encode(&item.id)
            )),
            meta: format!(
                "{library_path} · {} bytes · modified {}",
                stored.bytes,
                item.last_modified_date_time.as_deref().unwrap_or("?")
            ),
        });
        Ok(())
    }

    fn fetch_microsoft_files(
        config: &Config,
        checkpoint: Option<String>,
    ) -> Result<FetchResult, String> {
        if secrets::get(ACCESS_TOKEN).is_none() {
            return Err("no Microsoft files token — sign this source in first".into());
        }
        let previous: Checkpoint = match checkpoint.as_deref() {
            Some(checkpoint) => ron::from_str(checkpoint)
                .map_err(|error| format!("parsing Microsoft files checkpoint: {error}"))?,
            None => Checkpoint::default(),
        };
        let mut refreshed = false;
        let target = target_item(config, &mut refreshed)?;
        if target.id != config.item_id {
            return Err("Microsoft returned a different item identity".into());
        }
        let actual_kind = if target.folder.is_some() {
            "folder"
        } else if target.file.is_some() && target.package.is_none() && target.remote_item.is_none()
        {
            "file"
        } else {
            return Err("configured identity is not a supported regular file or folder".into());
        };
        if actual_kind != config.item_kind {
            return Err(format!(
                "Microsoft item kind changed: accepted {}, observed {actual_kind}",
                config.item_kind
            ));
        }

        let mut notes = Vec::new();
        let files = if target.folder.is_some() {
            let (files, folder_notes) = folder_files(
                config,
                &config.drive_id,
                &target,
                &target.name,
                &mut refreshed,
            )?;
            notes.extend(folder_notes);
            files
        } else if target.file.is_some() && target.package.is_none() && target.remote_item.is_none()
        {
            let name = target.name.clone();
            vec![(target, name)]
        } else {
            return Err("configured identity is not a supported regular file or folder".into());
        };

        let mut accumulator = Accumulator {
            items: Vec::new(),
            checkpoint: BTreeMap::new(),
            notes,
        };
        let mut seen = BTreeSet::new();
        for (item, library_path) in files {
            let key = format!("{}:{}", config.drive_id, item.id);
            seen.insert(key.clone());
            process_file(
                config,
                &config.drive_id,
                item,
                library_path,
                previous.items.get(&key),
                &mut accumulator,
            )?;
        }
        let missing = previous
            .items
            .keys()
            .filter(|key| !seen.contains(*key))
            .count();
        if missing > 0 {
            accumulator.notes.push(format!(
                "observed {missing} previously tracked file(s) no longer selected or present"
            ));
        }
        accumulator.notes.insert(
            0,
            format!(
                "{} new/changed, {} unchanged",
                accumulator.items.len(),
                accumulator
                    .checkpoint
                    .len()
                    .saturating_sub(accumulator.items.len())
            ),
        );
        control::progress(&accumulator.notes[0]);
        Ok(FetchResult {
            items: accumulator.items,
            notes: accumulator.notes.join("; "),
            next_checkpoint: Some(
                ron::to_string(&Checkpoint {
                    items: accumulator.checkpoint,
                })
                .map_err(|error| format!("encoding checkpoint: {error}"))?,
            ),
        })
    }

    struct MicrosoftFiles;

    impl Guest for MicrosoftFiles {
        fn describe() -> ConnectorDescribe {
            ConnectorDescribe {
                name: "microsoft-files".into(),
                link_namespace: "microsoft-file".into(),
                fetch_style: FetchStyle::Snapshot,
                auth_realm: Some("ms-files-read".into()),
            }
        }

        fn validate_config(config: String) -> Result<(), String> {
            validate(&parse_config(&config)?)
        }

        fn config_auth_realm(config: String) -> Result<Option<String>, String> {
            let config = parse_config(&config)?;
            validate(&config)?;
            Ok(Some(format!(
                "{}:{}:{}",
                realm_prefix(&config),
                config.tenant,
                config.client_id
            )))
        }

        fn status(_config: String) -> Result<AuthStatus, String> {
            if secrets::get(ACCESS_TOKEN).is_some() {
                Ok(AuthStatus::Authenticated(
                    "Microsoft files token cached (verified on fetch)".into(),
                ))
            } else {
                Ok(AuthStatus::NotAuthenticated(
                    "no Microsoft files token — sign in first".into(),
                ))
            }
        }

        fn auth_begin(config: String) -> Result<AuthChallenge, String> {
            let config = parse_config(&config)?;
            validate(&config)?;
            let response = http::fetch(&request(
                Purpose::Authenticate,
                Method::Post,
                identity_url(&config, "devicecode"),
                Some(form(&[
                    ("client_id", &config.client_id),
                    ("scope", scopes(&config)),
                ])),
                None,
                RESPONSE_CAP,
            ))
            .map_err(|error| error.message)?;
            let body = json(&response)?;
            Ok(AuthChallenge {
                verification_url: body["verification_uri"]
                    .as_str()
                    .ok_or_else(|| format!("device flow refused: {}", token_error(&body)))?
                    .into(),
                user_code: body["user_code"].as_str().ok_or("no user_code")?.into(),
                expires_in_secs: body["expires_in"].as_u64().unwrap_or(900),
                handle: body["device_code"].as_str().ok_or("no device_code")?.into(),
            })
        }

        fn auth_poll(config: String, handle: String) -> Result<AuthPollResult, String> {
            let config = parse_config(&config)?;
            validate(&config)?;
            let response = http::fetch(&request(
                Purpose::Authenticate,
                Method::Post,
                identity_url(&config, "token"),
                Some(form(&[
                    ("grant_type", "urn:ietf:params:oauth:grant-type:device_code"),
                    ("client_id", &config.client_id),
                    ("device_code", &handle),
                ])),
                None,
                RESPONSE_CAP,
            ))
            .map_err(|error| error.message)?;
            let body = json(&response)?;
            if let Some(token) = body["access_token"].as_str() {
                secrets::put(ACCESS_TOKEN, token.as_bytes())?;
                let refresh = body["refresh_token"]
                    .as_str()
                    .ok_or("no refresh_token returned — offline_access is required")?;
                secrets::put(REFRESH_TOKEN, refresh.as_bytes())?;
                return Ok(AuthPollResult::Done(
                    "signed in with Microsoft files access".into(),
                ));
            }
            match body["error"].as_str() {
                Some("authorization_pending") | Some("slow_down") => Ok(AuthPollResult::Pending),
                Some(_) => Ok(AuthPollResult::Failed(token_error(&body))),
                None => Ok(AuthPollResult::Failed(format!(
                    "unexpected token reply (HTTP {})",
                    response.status
                ))),
            }
        }

        fn fetch(request: FetchRequest) -> Result<FetchResult, String> {
            let config = parse_config(&request.config)?;
            validate(&config)?;
            if !matches!(request.spec, RunSpec::Snapshot) {
                return Err("microsoft-files is a snapshot source".into());
            }
            fetch_microsoft_files(&config, request.checkpoint)
        }
    }

    bindings::export!(MicrosoftFiles with_types_in bindings);
}
