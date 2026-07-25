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

    const MAX_FILE_BYTES: u64 = 64 * 1024 * 1024;

    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Config {
        url: String,
        #[serde(default = "default_ref")]
        git_ref: String,
        #[serde(default = "default_include")]
        include: Vec<String>,
    }

    #[derive(Deserialize, Default)]
    #[serde(default)]
    struct Registry {
        kinds: Vec<Kind>,
        roles: Vec<Role>,
    }

    #[derive(Deserialize, Default)]
    #[serde(default)]
    struct Kind {
        name: String,
        storage: String,
        fields: Vec<Field>,
    }

    #[derive(Deserialize, Default)]
    #[serde(default)]
    struct Field {
        name: String,
        role: Option<String>,
    }

    #[derive(Deserialize, Default)]
    #[serde(default)]
    struct Role {
        name: String,
        binds: Affordance,
    }

    #[derive(Deserialize, Default)]
    enum Affordance {
        Title,
        #[default]
        #[serde(other)]
        Other,
    }

    fn default_ref() -> String {
        "main".into()
    }

    fn default_include() -> Vec<String> {
        vec!["facts/**".into(), "receipts/**".into()]
    }

    fn parse_config(text: &str) -> Result<Config, String> {
        let value: ron::Value =
            ron::from_str(text).map_err(|error| format!("kb config: {error}"))?;
        value
            .into_rust()
            .map_err(|error| format!("kb config shape (url, git_ref, include): {error}"))
    }

    fn safe_token(value: &str) -> bool {
        !value.is_empty() && !value.starts_with('-') && !value.chars().any(char::is_whitespace)
    }

    fn validate(config: &Config) -> Result<(), String> {
        if !safe_token(&config.url) {
            return Err("url must be a single non-empty token".into());
        }
        if !safe_token(&config.git_ref) {
            return Err("git_ref must be a bare branch/tag name".into());
        }
        for pattern in &config.include {
            glob::Pattern::new(pattern).map_err(|error| format!("include '{pattern}': {error}"))?;
        }
        Ok(())
    }

    struct Route {
        kind: String,
        path: regex_lite::Regex,
        title_field: Option<String>,
    }

    fn routes(registry: &Registry) -> Vec<Route> {
        let title_roles: Vec<&str> = registry
            .roles
            .iter()
            .filter(|role| matches!(role.binds, Affordance::Title))
            .map(|role| role.name.as_str())
            .collect();
        registry
            .kinds
            .iter()
            .filter(|kind| kind.storage.contains('{'))
            .map(|kind| Route {
                kind: kind.name.clone(),
                path: storage_regex(&kind.storage),
                title_field: kind
                    .fields
                    .iter()
                    .find(|field| {
                        field
                            .role
                            .as_deref()
                            .is_some_and(|role| title_roles.contains(&role))
                    })
                    .map(|field| field.name.clone()),
            })
            .collect()
    }

    struct Kb;

    impl Guest for Kb {
        fn describe() -> PluginDescribe {
            PluginDescribe {
                name: "kb".into(),
                link_namespace: "kb".into(),
                fetch_style: FetchStyle::Sweep,
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
            Err("kb needs no sign-in".into())
        }

        fn auth_poll(_config: String, _handle: String) -> Result<AuthPollResult, String> {
            Err("kb needs no sign-in".into())
        }

        fn fetch(request: FetchRequest) -> Result<FetchResult, String> {
            if !matches!(request.spec, RunSpec::Sweep) {
                return Err("kb only sweeps".into());
            }
            let config = parse_config(&request.config)?;
            validate(&config)?;
            let head = repo::resolve(&config.url, &config.git_ref)?;
            let tree = repo::open(&config.url, &head)?;
            let mut items = Vec::new();
            let mut notes = vec![format!("remote HEAD {head}")];

            let registry_bytes = tree.read("registry.ron", 8 * 1024 * 1024).ok();
            let registry = registry_bytes
                .as_deref()
                .and_then(|bytes| std::str::from_utf8(bytes).ok())
                .and_then(|text| ron::from_str::<Registry>(text).ok());
            let routes = registry.as_ref().map(routes).unwrap_or_default();
            if registry_bytes.is_some() {
                let stored =
                    tree.copy_to_evidence("registry.ron", "registry.ron", 8 * 1024 * 1024)?;
                items.push(item(
                    "registry",
                    "registry",
                    "registry.ron",
                    stored.sha256,
                    format!("the remote KB's vocabulary · HEAD {head}"),
                ));
            } else {
                notes.push(
                    "remote has no readable registry.ron — records swept as plain files".into(),
                );
            }

            let patterns: Vec<glob::Pattern> = config
                .include
                .iter()
                .map(|pattern| {
                    glob::Pattern::new(pattern)
                        .map_err(|error| format!("include '{pattern}': {error}"))
                })
                .collect::<Result<_, _>>()?;
            for entry in tree.entries() {
                if !patterns.iter().any(|pattern| pattern.matches(&entry.path)) {
                    continue;
                }
                let bytes = tree.read(&entry.path, MAX_FILE_BYTES)?;
                let (kind, id, meta) = if entry.path.starts_with("receipts/") {
                    let id = entry
                        .path
                        .strip_prefix("receipts/")
                        .and_then(|path| path.strip_suffix(".ron"))
                        .unwrap_or(&entry.path)
                        .into();
                    (
                        "receipt".into(),
                        id,
                        receipt_meta(&bytes).unwrap_or_default(),
                    )
                } else if let Some((route, captures)) = routes.iter().find_map(|route| {
                    route
                        .path
                        .captures(&entry.path)
                        .map(|captures| (route, captures))
                }) {
                    let id = (1..captures.len())
                        .filter_map(|index| captures.get(index).map(|part| part.as_str()))
                        .collect::<Vec<_>>()
                        .join("/");
                    let meta = route
                        .title_field
                        .as_deref()
                        .and_then(|field| record_title(&bytes, field))
                        .unwrap_or_default();
                    (route.kind.clone(), id, meta)
                } else {
                    ("file".into(), entry.path.clone(), String::new())
                };
                let stored = tree.copy_to_evidence(&entry.path, &entry.path, MAX_FILE_BYTES)?;
                items.push(item(&kind, &id, &entry.path, stored.sha256, meta));
            }
            control::progress(&format!("federated {} item(s)", items.len()));
            Ok(FetchResult {
                items,
                notes: notes.join(" · "),
                next_checkpoint: None,
            })
        }
    }

    fn item(kind: &str, id: &str, path: &str, sha256: String, meta: String) -> Item {
        Item {
            id: id.into(),
            kind: kind.into(),
            version: None,
            content_hash: sha256,
            files: vec![path.into()],
            file_hashes: Vec::new(),
            locator: None,
            meta,
        }
    }

    fn storage_regex(storage: &str) -> regex_lite::Regex {
        let mut pattern = String::from("^");
        let mut rest = storage;
        while let Some(open) = rest.find('{') {
            pattern.push_str(&regex_lite::escape(&rest[..open]));
            let close = rest[open..]
                .find('}')
                .map(|index| open + index)
                .unwrap_or(rest.len());
            pattern.push_str("([^/]+)");
            rest = rest.get(close + 1..).unwrap_or("");
        }
        pattern.push_str(&regex_lite::escape(rest));
        pattern.push('$');
        regex_lite::Regex::new(&pattern).expect("storage pattern regex")
    }

    fn record_title(bytes: &[u8], field: &str) -> Option<String> {
        let value: ron::Value = ron::from_str(std::str::from_utf8(bytes).ok()?).ok()?;
        let ron::Value::Map(map) = value else {
            return None;
        };
        map.iter().find_map(|(key, value)| match (key, value) {
            (ron::Value::String(key), ron::Value::String(value)) if key == field => {
                Some(value.clone())
            }
            _ => None,
        })
    }

    fn receipt_meta(bytes: &[u8]) -> Option<String> {
        let value: ron::Value = ron::from_str(std::str::from_utf8(bytes).ok()?).ok()?;
        let ron::Value::Map(map) = value else {
            return None;
        };
        let get = |name: &str| {
            map.iter().find_map(|(key, value)| match (key, value) {
                (ron::Value::String(key), ron::Value::String(value)) if key == name => {
                    Some(value.clone())
                }
                _ => None,
            })
        };
        Some(format!(
            "accepted '{}' at {}",
            get("proposal_slug").unwrap_or_default(),
            get("accepted_at").unwrap_or_default()
        ))
    }

    bindings::export!(Kb with_types_in bindings);
}
