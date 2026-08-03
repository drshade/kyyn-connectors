#[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
mod guest {
    mod bindings {
        wit_bindgen::generate!({
            path: "../../../wit",
            world: "source",
        });
    }

    use bindings::exports::kyyn::source::api::{
        AuthChallenge, AuthPollResult, AuthStatus, ConnectorDescribe, FetchRequest, FetchResult,
        FetchStyle, Guest, Item, RunSpec,
    };
    use bindings::kyyn::source::{control, repo};
    use serde::Deserialize;

    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Config {
        url: String,
        #[serde(default = "default_ref")]
        git_ref: String,
        #[serde(default = "default_patterns")]
        patterns: Vec<String>,
        #[serde(default = "default_kind")]
        kind: String,
        #[serde(default = "default_max_bytes")]
        max_file_bytes: u64,
    }

    fn default_ref() -> String {
        "HEAD".into()
    }

    fn default_patterns() -> Vec<String> {
        vec!["**/*".into()]
    }

    fn default_kind() -> String {
        "file".into()
    }

    fn default_max_bytes() -> u64 {
        64 * 1024 * 1024
    }

    fn parse_config(text: &str) -> Result<Config, String> {
        let value: ron::Value =
            ron::from_str(text).map_err(|error| format!("git-repo config: {error}"))?;
        value.into_rust().map_err(|error| {
            format!(
                "git-repo config shape (url; optional git_ref, patterns, kind, max_file_bytes): \
                 {error}"
            )
        })
    }

    fn safe_token(value: &str) -> bool {
        !value.is_empty() && !value.starts_with('-') && !value.chars().any(char::is_whitespace)
    }

    fn validate(config: &Config) -> Result<(), String> {
        if !safe_token(&config.url) {
            return Err("url must be a single non-empty token".into());
        }
        if !safe_token(&config.git_ref) {
            return Err("git_ref must be a bare branch/tag name (or HEAD)".into());
        }
        for pattern in &config.patterns {
            glob::Pattern::new(pattern).map_err(|error| format!("pattern '{pattern}': {error}"))?;
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

    struct GitRepo;

    impl Guest for GitRepo {
        fn describe() -> ConnectorDescribe {
            ConnectorDescribe {
                name: "git-repo".into(),
                link_namespace: "repo".into(),
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
            Err("git-repo needs no sign-in".into())
        }

        fn auth_poll(_config: String, _handle: String) -> Result<AuthPollResult, String> {
            Err("git-repo needs no sign-in".into())
        }

        fn fetch(request: FetchRequest) -> Result<FetchResult, String> {
            if !matches!(request.spec, RunSpec::Snapshot) {
                return Err("git-repo is a snapshot source".into());
            }
            let config = parse_config(&request.config)?;
            validate(&config)?;
            let head = repo::resolve(&config.url, &config.git_ref)?;
            let short = &head[..12.min(head.len())];
            if request.checkpoint.as_deref() == Some(head.as_str()) {
                return Ok(FetchResult {
                    items: Vec::new(),
                    notes: format!("unchanged at {short}"),
                    next_checkpoint: Some(head),
                });
            }

            let patterns: Vec<glob::Pattern> = config
                .patterns
                .iter()
                .map(|pattern| {
                    glob::Pattern::new(pattern)
                        .map_err(|error| format!("pattern '{pattern}': {error}"))
                })
                .collect::<Result<_, _>>()?;
            let options = glob::MatchOptions {
                require_literal_separator: true,
                require_literal_leading_dot: true,
                ..Default::default()
            };
            let tree = repo::open(&config.url, &head)?;
            let mut items = Vec::new();
            let mut notes = vec![format!("tree at {short}")];
            for entry in tree.entries() {
                if !patterns
                    .iter()
                    .any(|pattern| pattern.matches_with(&entry.path, options))
                {
                    continue;
                }
                if entry.bytes > config.max_file_bytes {
                    notes.push(format!(
                        "skipped {} ({} bytes > {} cap)",
                        entry.path, entry.bytes, config.max_file_bytes
                    ));
                    continue;
                }
                let stored =
                    tree.copy_to_evidence(&entry.path, &entry.path, config.max_file_bytes)?;
                items.push(Item {
                    id: entry.path.clone(),
                    kind: config.kind.clone(),
                    version: None,
                    content_hash: stored.sha256,
                    files: vec![entry.path.clone()],
                    file_hashes: Vec::new(),
                    locator: None,
                    meta: format!("{} · {short}", entry.path),
                });
            }
            control::progress(&format!("{} file(s) matched at {short}", items.len()));
            Ok(FetchResult {
                items,
                notes: notes.join("; "),
                next_checkpoint: Some(head),
            })
        }
    }

    bindings::export!(GitRepo with_types_in bindings);
}
