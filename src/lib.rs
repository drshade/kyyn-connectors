//! Repository-level contract gates for first-party connector components.

#[cfg(test)]
mod contract {
    use serde::Deserialize;
    use sha2::Digest as _;
    use std::collections::{BTreeSet, HashSet};

    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Manifest {
        connector_manifest: u32,
        sources: Vec<Source>,
        #[serde(default)]
        sinks: Vec<Sink>,
    }

    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Source {
        name: String,
        summary: String,
        world: String,
        namespace: String,
        #[serde(default)]
        capabilities: Capabilities,
        component: String,
        component_sha256: String,
        #[serde(default)]
        config: Vec<ConfigField>,
    }

    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Sink {
        name: String,
        summary: String,
        world: String,
        component: String,
        component_sha256: String,
        delivery: SinkDelivery,
        #[serde(default)]
        config: Vec<ConfigField>,
    }

    #[derive(Deserialize)]
    enum SinkDelivery {
        Convergent,
        CasConvergent,
    }

    #[derive(Default, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Capabilities {
        #[serde(default)]
        requests: Vec<RequestGrant>,
        #[serde(default)]
        auth: Option<String>,
        #[serde(default)]
        repo: bool,
    }

    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct RequestGrant {
        purpose: Purpose,
        authority: String,
        method: Method,
        path: String,
    }

    #[derive(Deserialize)]
    enum Purpose {
        Observe,
        Authenticate,
    }

    #[derive(Deserialize)]
    enum Method {
        Get,
        Post,
    }

    #[derive(Debug, Default, Deserialize, PartialEq, Eq)]
    enum ConfigType {
        #[default]
        Str,
        HttpsOrigin,
        Int,
        Bool,
        StrList,
        Ron,
        Path,
    }

    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct ConfigField {
        name: String,
        doc: String,
        #[serde(default)]
        ty: ConfigType,
        #[serde(default)]
        required: bool,
        #[serde(default)]
        example: Option<String>,
        #[serde(default)]
        default: Option<String>,
    }

    fn manifest() -> Manifest {
        let text =
            std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/kyyn-connectors.ron"))
                .expect("kyyn-connectors.ron");
        ron::Options::default()
            .with_default_extension(ron::extensions::Extensions::IMPLICIT_SOME)
            .from_str(&text)
            .expect("repository manifest parses")
    }

    #[test]
    fn manifest_is_direction_explicit_closed_and_reviewable() {
        let manifest = manifest();
        assert_eq!(manifest.connector_manifest, 1);
        assert_eq!(manifest.sinks.len(), 1, "one frozen local-file sink");
        assert_eq!(
            manifest.sources.len(),
            8,
            "the explicit SharePoint deferral is documented"
        );
        let mut names = HashSet::new();
        for source in &manifest.sources {
            assert!(
                names.insert(&source.name),
                "duplicate source {}",
                source.name
            );
            assert_eq!(source.world, "kyyn:source@1", "{} world", source.name);
            assert!(!source.summary.trim().is_empty(), "{} summary", source.name);
            assert!(
                !source.namespace.trim().is_empty(),
                "{} namespace",
                source.name
            );
            assert!(
                source.component.starts_with("components/sources/"),
                "{} component direction must be visible in its path",
                source.name
            );
            assert_eq!(source.component_sha256.len(), 64, "{} digest", source.name);

            let mut fields = HashSet::new();
            for field in &source.config {
                assert!(
                    fields.insert(&field.name),
                    "{} duplicate config {}",
                    source.name,
                    field.name
                );
                assert!(
                    !field.doc.trim().is_empty(),
                    "{}#{} needs a doc",
                    source.name,
                    field.name
                );
                assert!(
                    !field.required || field.example.is_some(),
                    "{}#{} is required but has no example",
                    source.name,
                    field.name
                );
                let _ = &field.default;
            }
            for grant in &source.capabilities.requests {
                assert!(grant.path.starts_with('/'), "{} request path", source.name);
                match grant.purpose {
                    Purpose::Observe => assert!(matches!(grant.method, Method::Get)),
                    Purpose::Authenticate => assert!(matches!(grant.method, Method::Post)),
                }
                if let Some(field) = grant.authority.strip_prefix("config:") {
                    assert!(
                        source.config.iter().any(|candidate| {
                            candidate.name == field && candidate.ty == ConfigType::HttpsOrigin
                        }),
                        "{} request authority field {} is not HttpsOrigin",
                        source.name,
                        field
                    );
                } else {
                    assert!(grant.authority.starts_with("https://"));
                    assert!(!grant.authority.ends_with('/'));
                }
            }
        }

        let sink = &manifest.sinks[0];
        assert!(names.insert(&sink.name), "connector names are global");
        assert_eq!(sink.name, "file-replace");
        assert_eq!(sink.world, "kyyn:sink@1");
        assert!(matches!(sink.delivery, SinkDelivery::Convergent));
        assert!(!sink.summary.trim().is_empty());
        assert_eq!(sink.component, "components/sinks/file-replace.wasm");
        assert_eq!(sink.component_sha256.len(), 64);
        assert_eq!(sink.config.len(), 1);
        assert_eq!(sink.config[0].name, "path");
        assert_eq!(sink.config[0].ty, ConfigType::Path);
        assert!(sink.config[0].required);
        assert!(sink.config[0].example.is_some());
        assert!(!sink.config[0].doc.trim().is_empty());
    }

    #[test]
    fn committed_component_digests_match_the_manifest() {
        let manifest = manifest();
        for source in manifest.sources {
            let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(&source.component);
            let bytes = std::fs::read(&path)
                .unwrap_or_else(|error| panic!("reading {}: {error}", path.display()));
            assert_eq!(
                format!("{:x}", sha2::Sha256::digest(bytes)),
                source.component_sha256,
                "{} has a stale component_sha256 pin",
                source.name
            );
        }
        for sink in manifest.sinks {
            let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(&sink.component);
            let bytes = std::fs::read(&path)
                .unwrap_or_else(|error| panic!("reading {}: {error}", path.display()));
            assert_eq!(
                format!("{:x}", sha2::Sha256::digest(bytes)),
                sink.component_sha256,
                "{} has a stale component_sha256 pin",
                sink.name
            );
        }
    }

    #[test]
    fn vendored_wit_matches_the_frozen_engine_contract() {
        const FROZEN_SOURCE_WIT_SHA256: &str =
            "39b217ca312114ce734f880da68ab4d79c6ad1498639f7534bd5db7e4faf18e7";
        assert_eq!(
            format!(
                "{:x}",
                sha2::Sha256::digest(include_bytes!("../wit/source.wit"))
            ),
            FROZEN_SOURCE_WIT_SHA256,
            "wit/source.wit drifted from kyyn's frozen kyyn:source@1 contract"
        );
        const FROZEN_SINK_WIT_SHA256: &str =
            "5b94c2b6c244c4f50262f6d32ff6846fcb86e4ebe9359c8fea662aee0e74435c";
        assert_eq!(
            format!(
                "{:x}",
                sha2::Sha256::digest(include_bytes!("../wit/sink.wit"))
            ),
            FROZEN_SINK_WIT_SHA256,
            "wit/sink.wit drifted from kyyn's frozen kyyn:sink@1 contract"
        );
    }

    #[test]
    fn component_imports_are_a_subset_of_declared_capabilities() {
        let manifest = manifest();
        for source in manifest.sources {
            let mut allowed = BTreeSet::from(["control", "evidence"]);
            if !source.capabilities.requests.is_empty() {
                allowed.insert("http");
            }
            if source.capabilities.auth.is_some() {
                allowed.insert("secrets");
            }
            if source.capabilities.repo {
                allowed.insert("repo");
            }
            if source
                .config
                .iter()
                .any(|field| field.ty == ConfigType::Path)
            {
                allowed.insert("local");
            }

            let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(&source.component);
            let bytes = std::fs::read(&path)
                .unwrap_or_else(|error| panic!("reading {}: {error}", path.display()));
            let mut level = 0usize;
            let mut imports = BTreeSet::new();
            for payload in wasmparser::Parser::new(0).parse_all(&bytes) {
                match payload
                    .unwrap_or_else(|error| panic!("parsing {} component: {error}", source.name))
                {
                    wasmparser::Payload::Version { .. } => level += 1,
                    wasmparser::Payload::End(_) => level -= 1,
                    wasmparser::Payload::ComponentImportSection(section) if level == 1 => {
                        for import in section {
                            let name = import.expect("component import").name.name;
                            let interface = name
                                .strip_prefix("kyyn:source/")
                                .and_then(|name| name.split('@').next())
                                .unwrap_or(name);
                            imports.insert(interface.to_string());
                        }
                    }
                    _ => {}
                }
            }
            let excess = imports
                .iter()
                .filter(|import| !allowed.contains(import.as_str()))
                .collect::<Vec<_>>();
            assert!(
                excess.is_empty(),
                "{} imports undeclared capabilities {excess:?}; imports={imports:?}, allowed={allowed:?}",
                source.name
            );
        }

        for sink in manifest.sinks {
            let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(&sink.component);
            let bytes = std::fs::read(&path)
                .unwrap_or_else(|error| panic!("reading {}: {error}", path.display()));
            let mut level = 0usize;
            let mut imports = BTreeSet::new();
            for payload in wasmparser::Parser::new(0).parse_all(&bytes) {
                match payload
                    .unwrap_or_else(|error| panic!("parsing {} component: {error}", sink.name))
                {
                    wasmparser::Payload::Version { .. } => level += 1,
                    wasmparser::Payload::End(_) => level -= 1,
                    wasmparser::Payload::ComponentImportSection(section) if level == 1 => {
                        for import in section {
                            let name = import.expect("component import").name.name;
                            let interface = name
                                .strip_prefix("kyyn:sink/")
                                .and_then(|name| name.split('@').next())
                                .unwrap_or(name);
                            imports.insert(interface.to_string());
                        }
                    }
                    _ => {}
                }
            }
            assert_eq!(
                imports,
                BTreeSet::from(["file-replace".to_string()]),
                "{} must import exactly its one host effect operation",
                sink.name
            );
        }
    }
}
