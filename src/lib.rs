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
        #[serde(default)]
        connections: Vec<Connection>,
        sources: Vec<Source>,
        #[serde(default)]
        sinks: Vec<Sink>,
    }

    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Connection {
        name: String,
        summary: String,
        world: String,
        component: String,
        component_sha256: String,
        #[serde(default)]
        capabilities: Vec<String>,
        #[serde(default)]
        requests: Vec<RequestGrant>,
        #[serde(default)]
        verification_origins: Vec<String>,
        #[serde(default)]
        config: Vec<ConfigField>,
    }

    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Source {
        name: String,
        summary: String,
        world: String,
        namespace: String,
        #[serde(default)]
        connection: Option<ConnectionRequirement>,
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
        connection: Option<ConnectionRequirement>,
        #[serde(default)]
        config: Vec<ConfigField>,
    }

    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct ConnectionRequirement {
        provider: String,
        capabilities: Vec<String>,
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
        #[serde(default)]
        continuation: Continuation,
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
    enum Continuation {
        #[default]
        None,
        ProviderDownload,
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
        assert_eq!(manifest.connections.len(), 2, "two account providers");
        assert_eq!(manifest.sinks.len(), 3, "three first-party sinks");
        assert_eq!(manifest.sources.len(), 9, "nine first-party sources");
        let mut provider_names = HashSet::new();
        for connection in &manifest.connections {
            assert!(
                provider_names.insert(&connection.name),
                "duplicate connection provider {}",
                connection.name
            );
            assert_eq!(
                connection.world, "kyyn:connection@1",
                "{} world",
                connection.name
            );
            assert!(
                !connection.summary.trim().is_empty(),
                "{} summary",
                connection.name
            );
            assert!(
                connection.component.starts_with("components/connections/"),
                "{} component direction must be visible in its path",
                connection.name
            );
            assert_eq!(
                connection.component_sha256.len(),
                64,
                "{} digest",
                connection.name
            );
            assert!(
                !connection.capabilities.is_empty(),
                "{} advertises no selectable capabilities",
                connection.name
            );
            let capability_count = connection.capabilities.iter().collect::<HashSet<_>>().len();
            assert_eq!(
                capability_count,
                connection.capabilities.len(),
                "{} has duplicate capabilities",
                connection.name
            );
            let mut fields = HashSet::new();
            for field in &connection.config {
                assert!(
                    fields.insert(&field.name),
                    "{} duplicate config {}",
                    connection.name,
                    field.name
                );
                assert!(
                    !field.doc.trim().is_empty(),
                    "{} config doc",
                    connection.name
                );
                assert!(
                    !field.required || field.example.is_some(),
                    "{}#{} is required but has no example",
                    connection.name,
                    field.name
                );
            }
            for grant in &connection.requests {
                assert!(matches!(grant.purpose, Purpose::Authenticate));
                assert!(matches!(grant.method, Method::Post));
                assert!(grant.path.starts_with('/'));
                assert_eq!(grant.continuation, Continuation::None);
                if let Some(field) = grant.authority.strip_prefix("config:") {
                    assert!(connection.config.iter().any(|candidate| {
                        candidate.name == field && candidate.ty == ConfigType::HttpsOrigin
                    }));
                } else {
                    assert!(grant.authority.starts_with("https://"));
                    assert!(!grant.authority.ends_with('/'));
                }
            }
            assert!(
                !connection.verification_origins.is_empty(),
                "{} has no reviewed sign-in destination",
                connection.name
            );
            let origin_count = connection
                .verification_origins
                .iter()
                .collect::<HashSet<_>>()
                .len();
            assert_eq!(
                origin_count,
                connection.verification_origins.len(),
                "{} has duplicate sign-in destinations",
                connection.name
            );
            for origin in &connection.verification_origins {
                if let Some(field) = origin.strip_prefix("config:") {
                    assert!(connection.config.iter().any(|candidate| {
                        candidate.name == field && candidate.ty == ConfigType::HttpsOrigin
                    }));
                } else {
                    assert!(origin.starts_with("https://"));
                    assert!(!origin.ends_with('/'));
                    assert!(!origin.contains(['?', '#', '@']));
                }
            }
        }

        let microsoft = manifest
            .connections
            .iter()
            .find(|connection| connection.name == "microsoft")
            .expect("Microsoft connection provider");
        assert_eq!(
            microsoft.verification_origins,
            [
                "https://microsoft.com",
                "https://www.microsoft.com",
                "https://login.microsoftonline.com",
            ]
        );
        let salesforce = manifest
            .connections
            .iter()
            .find(|connection| connection.name == "salesforce")
            .expect("Salesforce connection provider");
        assert_eq!(
            salesforce.verification_origins,
            [
                "config:instance_url",
                "https://login.salesforce.com",
                "https://test.salesforce.com",
            ]
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
            if let Some(requirement) = &source.connection {
                let provider = manifest
                    .connections
                    .iter()
                    .find(|provider| provider.name == requirement.provider)
                    .expect("source connection provider exists");
                assert!(
                    requirement
                        .capabilities
                        .iter()
                        .all(|capability| provider.capabilities.contains(capability)),
                    "{} asks for an unadvertised connection capability",
                    source.name
                );
                assert!(source.capabilities.auth.is_none());
                assert!(
                    source
                        .capabilities
                        .requests
                        .iter()
                        .all(|grant| matches!(grant.purpose, Purpose::Observe))
                );
            }

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
                if grant.continuation == Continuation::ProviderDownload {
                    assert!(
                        matches!(grant.purpose, Purpose::Observe)
                            && matches!(grant.method, Method::Get),
                        "{} provider download is not an Observe + GET",
                        source.name
                    );
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
                } else if let Some(field) = grant.authority.strip_prefix("connection:") {
                    let requirement = source.connection.as_ref().expect("connection authority");
                    let provider = manifest
                        .connections
                        .iter()
                        .find(|provider| provider.name == requirement.provider)
                        .expect("connection provider");
                    assert!(provider.config.iter().any(|candidate| {
                        candidate.name == field && candidate.ty == ConfigType::HttpsOrigin
                    }));
                } else {
                    assert!(grant.authority.starts_with("https://"));
                    assert!(!grant.authority.ends_with('/'));
                }
            }
        }

        let microsoft_files = manifest
            .sources
            .iter()
            .find(|source| source.name == "microsoft-files")
            .expect("Microsoft files source is advertised");
        assert!(microsoft_files.capabilities.auth.is_none());
        assert_eq!(
            microsoft_files.connection.as_ref().unwrap().capabilities,
            ["files-read"]
        );
        assert_eq!(
            microsoft_files
                .capabilities
                .requests
                .iter()
                .filter(|grant| grant.continuation == Continuation::ProviderDownload)
                .count(),
            1,
            "only the exact content endpoint delegates its download location"
        );

        for sink in &manifest.sinks {
            assert!(names.insert(&sink.name), "connector names are global");
            assert_eq!(sink.world, "kyyn:sink@1", "{} world", sink.name);
            assert!(!sink.summary.trim().is_empty(), "{} summary", sink.name);
            assert!(
                sink.component.starts_with("components/sinks/"),
                "{} component direction must be visible in its path",
                sink.name
            );
            assert_eq!(sink.component_sha256.len(), 64, "{} digest", sink.name);
            if let Some(requirement) = &sink.connection {
                let provider = manifest
                    .connections
                    .iter()
                    .find(|provider| provider.name == requirement.provider)
                    .expect("sink connection provider exists");
                assert!(
                    requirement
                        .capabilities
                        .iter()
                        .all(|capability| provider.capabilities.contains(capability))
                );
            }
            let mut fields = HashSet::new();
            for field in &sink.config {
                assert!(
                    fields.insert(&field.name),
                    "{} duplicate config {}",
                    sink.name,
                    field.name
                );
                assert!(
                    !field.doc.trim().is_empty(),
                    "{}#{} doc",
                    sink.name,
                    field.name
                );
                assert!(
                    !field.required || field.example.is_some(),
                    "{}#{} is required but has no example",
                    sink.name,
                    field.name
                );
                let _ = &field.default;
            }
        }

        let file = manifest
            .sinks
            .iter()
            .find(|sink| sink.name == "file-replace")
            .expect("file-replace sink");
        assert!(matches!(file.delivery, SinkDelivery::Convergent));
        assert_eq!(file.component, "components/sinks/file-replace.wasm");
        assert_eq!(file.config.len(), 1);
        assert_eq!(file.config[0].name, "path");
        assert_eq!(file.config[0].ty, ConfigType::Path);

        let git = manifest
            .sinks
            .iter()
            .find(|sink| sink.name == "git-ref")
            .expect("git-ref sink");
        assert!(matches!(git.delivery, SinkDelivery::CasConvergent));
        assert_eq!(git.component, "components/sinks/git-ref.wasm");
        assert_eq!(git.config.len(), 2);
        assert_eq!(git.config[0].name, "repository");
        assert_eq!(git.config[1].name, "reference");
        assert!(git.config.iter().all(|field| field.required));

        let microsoft = manifest
            .sinks
            .iter()
            .find(|sink| sink.name == "microsoft-file-replace")
            .expect("microsoft-file-replace sink");
        assert!(matches!(microsoft.delivery, SinkDelivery::Convergent));
        assert_eq!(
            microsoft.component,
            "components/sinks/microsoft-file-replace.wasm"
        );
        assert!(microsoft.config.is_empty());
        assert_eq!(
            microsoft.connection.as_ref().unwrap().capabilities,
            ["files-write"]
        );
    }

    #[test]
    fn committed_component_digests_match_the_manifest() {
        let manifest = manifest();
        for connection in manifest.connections {
            let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(&connection.component);
            let bytes = std::fs::read(&path)
                .unwrap_or_else(|error| panic!("reading {}: {error}", path.display()));
            assert_eq!(
                format!("{:x}", sha2::Sha256::digest(bytes)),
                connection.component_sha256,
                "{} has a stale component_sha256 pin",
                connection.name
            );
        }
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
            "88852bf6838f71b8001a785e2a5ff4fcaeb6b613594aab9323d3cf17ca52301a";
        assert_eq!(
            format!(
                "{:x}",
                sha2::Sha256::digest(include_bytes!("../wit/source.wit"))
            ),
            FROZEN_SOURCE_WIT_SHA256,
            "wit/source.wit drifted from kyyn's frozen kyyn:source@1 contract"
        );
        const FROZEN_SINK_WIT_SHA256: &str =
            "0e70eda60f3bb3834a5ce18144dd56bd66480f8ed8681624fd5b49b84c788968";
        assert_eq!(
            format!(
                "{:x}",
                sha2::Sha256::digest(include_bytes!("../wit/sink.wit"))
            ),
            FROZEN_SINK_WIT_SHA256,
            "wit/sink.wit drifted from kyyn's frozen kyyn:sink@1 contract"
        );
        const FROZEN_CONNECTION_WIT_SHA256: &str =
            "238ca56e8f55feb6f244be50510f3a40bc7d7a694252f11c24dd7cfbda9f6941";
        assert_eq!(
            format!(
                "{:x}",
                sha2::Sha256::digest(include_bytes!("../wit/connection.wit"))
            ),
            FROZEN_CONNECTION_WIT_SHA256,
            "wit/connection.wit drifted from kyyn's frozen kyyn:connection@1 contract"
        );
    }

    #[test]
    fn component_imports_are_a_subset_of_declared_capabilities() {
        let manifest = manifest();
        for connection in &manifest.connections {
            let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(&connection.component);
            let bytes = std::fs::read(&path)
                .unwrap_or_else(|error| panic!("reading {}: {error}", path.display()));
            let mut level = 0usize;
            let mut imports = BTreeSet::new();
            for payload in wasmparser::Parser::new(0).parse_all(&bytes) {
                match payload.unwrap_or_else(|error| {
                    panic!("parsing {} component: {error}", connection.name)
                }) {
                    wasmparser::Payload::Version { .. } => level += 1,
                    wasmparser::Payload::End(_) => level -= 1,
                    wasmparser::Payload::ComponentImportSection(section) if level == 1 => {
                        for import in section {
                            let name = import.expect("component import").name.name;
                            let interface = name
                                .strip_prefix("kyyn:connection/")
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
                BTreeSet::from(["http".into(), "secrets".into()]),
                "{} provider must have only the bounded enrollment host imports",
                connection.name
            );
        }
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
            let expected = BTreeSet::from([sink.name.clone()]);
            assert_eq!(
                imports, expected,
                "{} must import exactly its one host effect operation",
                sink.name
            );
        }
    }
}
