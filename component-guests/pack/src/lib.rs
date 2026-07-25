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
    use bindings::kyyn::tap::{control, repo};
    use serde::Deserialize;

    const DEFAULT_REPO: &str = "https://github.com/drshade/kyyn-templates";
    const MAX_TEMPLATE_FILE_BYTES: u64 = 64 * 1024 * 1024;

    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Config {
        template: String,
        rev: String,
        #[serde(default = "default_repo")]
        repo: String,
    }

    #[derive(Deserialize, Default)]
    #[serde(default)]
    struct TemplateManifest {
        substitutions: Vec<ron::Value>,
    }

    fn default_repo() -> String {
        DEFAULT_REPO.into()
    }

    fn parse_config(text: &str) -> Result<Config, String> {
        let value: ron::Value =
            ron::from_str(text).map_err(|error| format!("pack config: {error}"))?;
        value
            .into_rust()
            .map_err(|error| format!("pack config shape (template, rev; optional repo): {error}"))
    }

    fn validate(config: &Config) -> Result<(), String> {
        if config.template.is_empty()
            || !config
                .template
                .chars()
                .all(|ch| ch.is_ascii_alphanumeric() || ch == '-' || ch == '_')
        {
            return Err(format!(
                "template '{}' must be a bare token",
                config.template
            ));
        }
        if config.rev.len() != 40 || !config.rev.chars().all(|ch| ch.is_ascii_hexdigit()) {
            return Err(format!(
                "rev '{}' is not a full 40-hex commit OID — movable ref names are not pins",
                config.rev
            ));
        }
        if config.repo.is_empty()
            || config.repo.starts_with('-')
            || config.repo.chars().any(char::is_whitespace)
        {
            return Err("repo must be a single non-empty token".into());
        }
        Ok(())
    }

    struct Pack;

    impl Guest for Pack {
        fn describe() -> PluginDescribe {
            PluginDescribe {
                name: "pack".into(),
                link_namespace: "pack".into(),
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
            Err("pack needs no sign-in".into())
        }

        fn auth_poll(_config: String, _handle: String) -> Result<AuthPollResult, String> {
            Err("pack needs no sign-in".into())
        }

        fn fetch(request: FetchRequest) -> Result<FetchResult, String> {
            if !matches!(request.spec, RunSpec::Snapshot) {
                return Err("pack is a snapshot source".into());
            }
            let config = parse_config(&request.config)?;
            validate(&config)?;
            let short = &config.rev[..12];
            if request.checkpoint.as_deref() == Some(config.rev.as_str()) {
                return Ok(FetchResult {
                    items: Vec::new(),
                    notes: format!("pack '{}' unchanged at {short}", config.template),
                    next_checkpoint: Some(config.rev),
                });
            }

            let tree = repo::open(&config.repo, &config.rev)?;
            let prefix = format!("{}/", config.template);
            let manifest_path = format!("{prefix}kyyn-template.ron");
            let manifest_bytes = tree.read(&manifest_path, 1024 * 1024).map_err(|error| {
                format!(
                    "repo at {short} offers no template '{}' (no {manifest_path}): {error}",
                    config.template
                )
            })?;
            let manifest_text = std::str::from_utf8(&manifest_bytes)
                .map_err(|error| format!("kyyn-template.ron is not UTF-8: {error}"))?;
            let manifest: TemplateManifest = ron::from_str(manifest_text)
                .map_err(|error| format!("kyyn-template.ron: {error}"))?;
            if !manifest.substitutions.is_empty() {
                return Err(format!(
                    "template '{}' declares identity substitutions — it is an init-time \
                     starter, not an importable pack",
                    config.template
                ));
            }

            let mut items = Vec::new();
            for entry in tree.entries() {
                let Some(rel) = entry.path.strip_prefix(&prefix) else {
                    continue;
                };
                if rel.is_empty() || rel == "kyyn-template.ron" {
                    continue;
                }
                if entry.bytes > MAX_TEMPLATE_FILE_BYTES {
                    return Err(format!(
                        "{rel}: {} bytes exceeds the 64 MiB evidence ceiling",
                        entry.bytes
                    ));
                }
                let stored = tree.copy_to_evidence(&entry.path, rel, MAX_TEMPLATE_FILE_BYTES)?;
                items.push(Item {
                    id: rel.into(),
                    kind: "file".into(),
                    version: None,
                    content_hash: stored.sha256,
                    files: vec![rel.into()],
                    file_hashes: Vec::new(),
                    locator: None,
                    meta: format!("{} · {rel} · {short}", config.template),
                });
            }
            control::progress(&format!(
                "pack '{}': {} file(s) at {short}",
                config.template,
                items.len()
            ));
            Ok(FetchResult {
                items,
                notes: format!("pack '{}' at {short}", config.template),
                next_checkpoint: Some(config.rev),
            })
        }
    }

    bindings::export!(Pack with_types_in bindings);
}
