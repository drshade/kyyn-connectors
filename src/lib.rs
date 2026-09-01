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
        #[serde(default = "delegated_human_only")]
        principal_classes: Vec<ConnectionPrincipalClass>,
        #[serde(default)]
        workload_recipes: Vec<ConnectionWorkloadRecipe>,
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
        #[serde(default)]
        configurator: Option<Configurator>,
        #[serde(default)]
        evidence_tools: Vec<EvidenceTool>,
    }

    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct EvidenceTool {
        name: String,
        description: String,
        parameters: ron::Value,
        result: ron::Value,
        world: String,
        execution_profile: String,
        component: String,
        component_sha256: String,
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
        capabilities: SinkCapabilities,
        #[serde(default)]
        config: Vec<ConfigField>,
        #[serde(default)]
        configurator: Option<Configurator>,
    }

    #[derive(Default, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct SinkCapabilities {
        #[serde(default)]
        requests: Vec<SinkRequestGrant>,
    }

    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct SinkRequestGrant {
        name: String,
        phase: SinkRequestPhase,
        authorization: Authorization,
        authority: String,
        method: SinkMethod,
        path: String,
        #[serde(default)]
        path_bindings: Vec<String>,
        body: SinkRequestBody,
        #[serde(default)]
        continuation: Continuation,
        #[serde(default)]
        headers: Vec<String>,
        max_response_bytes: u64,
        timeout_ms: u64,
        max_operations: u32,
    }

    #[derive(Deserialize)]
    enum SinkRequestPhase {
        Observe,
        Apply,
    }

    #[derive(Deserialize)]
    enum SinkMethod {
        Get,
        Put,
    }

    #[derive(Deserialize)]
    enum SinkRequestBody {
        None,
        AcceptedArtifact,
    }

    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct ConnectionRequirement {
        provider: String,
        capabilities: Vec<String>,
        #[serde(default = "delegated_human_only")]
        principal_classes: Vec<ConnectionPrincipalClass>,
    }

    #[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq)]
    enum ConnectionPrincipalClass {
        DelegatedHuman,
        WorkloadApplication,
    }

    fn delegated_human_only() -> Vec<ConnectionPrincipalClass> {
        vec![ConnectionPrincipalClass::DelegatedHuman]
    }

    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct ConnectionWorkloadRecipe {
        name: String,
        summary: String,
        inputs: Vec<ConnectionWorkloadInput>,
    }

    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct ConnectionWorkloadInput {
        name: String,
        label: String,
        doc: String,
        kind: ConnectionWorkloadInputKind,
        max_bytes: u64,
    }

    #[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
    enum ConnectionWorkloadInputKind {
        ClientSecret,
        PrivateKey,
        Assertion,
        AccessToken,
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
        authorization: Authorization,
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
        Configure,
    }

    #[derive(Deserialize)]
    enum Authorization {
        None,
        Connection,
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
        #[serde(default)]
        label: Option<String>,
        doc: String,
        #[serde(default)]
        ty: ConfigType,
        #[serde(default)]
        required: bool,
        #[serde(default)]
        example: Option<String>,
        #[serde(default)]
        default: Option<String>,
        #[serde(default)]
        custody: ConfigCustody,
        #[serde(default)]
        control: ConfigControl,
    }

    #[derive(Debug, Default, Deserialize, PartialEq, Eq)]
    enum ConfigCustody {
        #[default]
        Durable,
        Ephemeral,
        Promotable,
        Secret,
    }

    #[derive(Debug, Default, Deserialize, PartialEq, Eq)]
    enum ConfigControl {
        #[default]
        Text,
        ResourceLink,
        Choice {
            options: Vec<String>,
        },
        Path,
    }

    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Configurator {
        world: String,
        component: String,
        component_sha256: String,
        #[serde(default)]
        requests: Vec<RequestGrant>,
        produces: Vec<String>,
        max_input_bytes: u64,
        max_output_bytes: u64,
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
        assert_eq!(manifest.sources.len(), 10, "ten first-party sources");
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
            assert!(!connection.principal_classes.is_empty());
            assert_eq!(
                connection
                    .principal_classes
                    .iter()
                    .collect::<HashSet<_>>()
                    .len(),
                connection.principal_classes.len(),
                "{} has duplicate principal classes",
                connection.name
            );
            let supports_workload = connection
                .principal_classes
                .contains(&ConnectionPrincipalClass::WorkloadApplication);
            assert_eq!(
                supports_workload,
                !connection.workload_recipes.is_empty(),
                "{} workload class and recipes must be declared together",
                connection.name
            );
            let mut recipe_names = HashSet::new();
            for recipe in &connection.workload_recipes {
                assert!(recipe_names.insert(&recipe.name));
                assert!(!recipe.summary.trim().is_empty());
                assert!(!recipe.inputs.is_empty());
                let mut input_names = HashSet::new();
                for input in &recipe.inputs {
                    assert!(input_names.insert(&input.name));
                    assert!(!input.label.trim().is_empty());
                    assert!(!input.doc.trim().is_empty());
                    assert!(input.max_bytes > 0);
                    let _ = input.kind;
                }
            }
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
                let _ = (&field.label, &field.custody, &field.control);
            }
            for grant in &connection.requests {
                assert!(matches!(grant.purpose, Purpose::Authenticate));
                assert!(matches!(grant.authorization, Authorization::None));
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
                "https://login.microsoft.com",
                "https://login.microsoftonline.com",
            ]
        );
        assert_eq!(
            microsoft.principal_classes,
            [
                ConnectionPrincipalClass::DelegatedHuman,
                ConnectionPrincipalClass::WorkloadApplication,
            ]
        );
        assert_eq!(microsoft.workload_recipes.len(), 1);
        assert_eq!(microsoft.workload_recipes[0].name, "client-secret");
        assert_eq!(microsoft.workload_recipes[0].inputs.len(), 1);
        assert_eq!(
            microsoft.workload_recipes[0].inputs[0].kind,
            ConnectionWorkloadInputKind::ClientSecret
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
        assert_eq!(
            salesforce.principal_classes,
            [
                ConnectionPrincipalClass::DelegatedHuman,
                ConnectionPrincipalClass::WorkloadApplication,
            ]
        );
        assert_eq!(salesforce.workload_recipes.len(), 1);
        assert_eq!(salesforce.workload_recipes[0].name, "client-secret");
        assert_eq!(salesforce.workload_recipes[0].inputs.len(), 1);
        assert_eq!(
            salesforce.workload_recipes[0].inputs[0].kind,
            ConnectionWorkloadInputKind::ClientSecret
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
            let mut tool_names = HashSet::new();
            for tool in &source.evidence_tools {
                assert!(
                    tool_names.insert(&tool.name),
                    "duplicate evidence tool {}",
                    tool.name
                );
                assert!(!tool.description.trim().is_empty());
                assert_eq!(tool.world, "kyyn:evidence-tool@1");
                assert_eq!(tool.execution_profile, "kyyn-evidence-tool-contained-1");
                assert!(tool.component.starts_with("components/evidence-tools/"));
                assert_eq!(tool.component_sha256.len(), 64);
                let _ = (&tool.parameters, &tool.result);
            }
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
                assert!(!requirement.principal_classes.is_empty());
                assert!(
                    requirement
                        .principal_classes
                        .iter()
                        .all(|class| provider.principal_classes.contains(class))
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
                if let ConfigControl::Choice { options } = &field.control {
                    assert!(
                        !options.is_empty(),
                        "{}#{} has no choices",
                        source.name,
                        field.name
                    );
                }
                if field.custody != ConfigCustody::Durable {
                    assert!(
                        field.default.is_none(),
                        "transient config cannot have a default"
                    );
                }
            }
            for grant in &source.capabilities.requests {
                assert!(grant.path.starts_with('/'), "{} request path", source.name);
                match grant.purpose {
                    Purpose::Observe => assert!(matches!(grant.method, Method::Get)),
                    Purpose::Authenticate => assert!(matches!(grant.method, Method::Post)),
                    Purpose::Configure => panic!("source execution grants cannot configure"),
                }
                if matches!(grant.authorization, Authorization::Connection) {
                    assert!(
                        source.connection.is_some(),
                        "{} authorizes a connection without requiring one",
                        source.name
                    );
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
                    assert!(matches!(grant.authorization, Authorization::Connection));
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
            if let Some(configurator) = &source.configurator {
                assert_eq!(configurator.world, "kyyn:configurator@1");
                assert!(
                    configurator
                        .component
                        .starts_with("components/configurators/")
                );
                assert_eq!(configurator.component_sha256.len(), 64);
                assert!(configurator.max_input_bytes > 0);
                assert!(configurator.max_output_bytes > 0);
                assert!(source.config.iter().any(|field| {
                    matches!(
                        field.custody,
                        ConfigCustody::Ephemeral
                            | ConfigCustody::Promotable
                            | ConfigCustody::Secret
                    )
                }));
                let produced = configurator.produces.iter().collect::<HashSet<_>>();
                assert_eq!(produced.len(), configurator.produces.len());
                for name in &configurator.produces {
                    assert!(source.config.iter().any(|field| {
                        field.name == *name && field.custody == ConfigCustody::Durable
                    }));
                }
                for grant in &configurator.requests {
                    assert!(matches!(grant.purpose, Purpose::Configure));
                    assert!(matches!(grant.authorization, Authorization::Connection));
                    assert!(matches!(grant.method, Method::Get));
                    assert_eq!(grant.continuation, Continuation::None);
                    assert!(grant.authority.starts_with("https://"));
                    assert!(grant.path.starts_with('/'));
                    if grant.path.contains("{path}") {
                        assert!(grant.path.ends_with("/{path}"));
                        assert_eq!(grant.path.matches("{path}").count(), 1);
                    }
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
                .connection
                .as_ref()
                .unwrap()
                .principal_classes,
            [
                ConnectionPrincipalClass::DelegatedHuman,
                ConnectionPrincipalClass::WorkloadApplication,
            ]
        );
        assert!(
            manifest
                .sources
                .iter()
                .filter(|source| {
                    source.connection.as_ref().is_some_and(|requirement| {
                        requirement.provider == "microsoft"
                            && !matches!(
                                source.name.as_str(),
                                "microsoft-files" | "graph-org-meetings"
                            )
                    })
                })
                .all(
                    |source| source.connection.as_ref().unwrap().principal_classes
                        == [ConnectionPrincipalClass::DelegatedHuman]
                )
        );
        let graph_org_meetings = manifest
            .sources
            .iter()
            .find(|source| source.name == "graph-org-meetings")
            .expect("workload population meetings are advertised");
        assert_eq!(
            graph_org_meetings.connection.as_ref().unwrap().capabilities,
            ["directory-users-read", "meetings-read"]
        );
        assert_eq!(
            graph_org_meetings
                .connection
                .as_ref()
                .unwrap()
                .principal_classes,
            [ConnectionPrincipalClass::WorkloadApplication]
        );
        assert!(graph_org_meetings.configurator.is_some());
        let salesforce = manifest
            .sources
            .iter()
            .find(|source| source.name == "salesforce")
            .expect("Salesforce source is advertised");
        assert_eq!(
            salesforce.connection.as_ref().unwrap().principal_classes,
            [
                ConnectionPrincipalClass::DelegatedHuman,
                ConnectionPrincipalClass::WorkloadApplication,
            ]
        );
        let configurator = microsoft_files
            .configurator
            .as_ref()
            .expect("Microsoft files has a connector-owned configurator");
        assert_eq!(
            configurator.produces,
            ["drive_id", "item_id", "item_kind", "display_name"]
        );
        let link = microsoft_files
            .config
            .iter()
            .find(|field| field.name == "resource_link")
            .expect("resource link field");
        assert_eq!(link.custody, ConfigCustody::Ephemeral);
        assert_eq!(link.control, ConfigControl::ResourceLink);
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
                assert!(!requirement.principal_classes.is_empty());
                assert!(
                    requirement
                        .principal_classes
                        .iter()
                        .all(|class| provider.principal_classes.contains(class))
                );
            }
            let mut request_names = HashSet::new();
            for grant in &sink.capabilities.requests {
                assert!(
                    request_names.insert(&grant.name),
                    "duplicate sink request grant"
                );
                assert!(!grant.authority.trim().is_empty());
                assert!(grant.path.starts_with('/'));
                assert!(grant.max_response_bytes > 0);
                assert!(grant.timeout_ms > 0);
                assert!(grant.max_operations > 0);
                let _ = (&grant.authorization, &grant.path_bindings, &grant.headers);
                match (&grant.phase, &grant.method, &grant.body) {
                    (SinkRequestPhase::Observe, SinkMethod::Get, SinkRequestBody::None)
                    | (
                        SinkRequestPhase::Apply,
                        SinkMethod::Put,
                        SinkRequestBody::AcceptedArtifact,
                    ) => {}
                    _ => panic!("{} has an incoherent sink request grant", sink.name),
                }
                if grant.continuation == Continuation::ProviderDownload {
                    assert!(matches!(&grant.phase, SinkRequestPhase::Observe));
                    assert!(matches!(&grant.method, SinkMethod::Get));
                }
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
        assert!(!microsoft.config.is_empty());
        assert!(microsoft.configurator.is_some());
        assert!(!microsoft.capabilities.requests.is_empty());
        assert_eq!(
            microsoft.connection.as_ref().unwrap().capabilities,
            ["files-write"]
        );
        assert_eq!(
            microsoft.connection.as_ref().unwrap().principal_classes,
            [
                ConnectionPrincipalClass::DelegatedHuman,
                ConnectionPrincipalClass::WorkloadApplication,
            ]
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
            if let Some(configurator) = source.configurator {
                let path =
                    std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(&configurator.component);
                let bytes = std::fs::read(&path)
                    .unwrap_or_else(|error| panic!("reading {}: {error}", path.display()));
                assert_eq!(
                    format!("{:x}", sha2::Sha256::digest(bytes)),
                    configurator.component_sha256,
                    "{} has a stale configurator component_sha256 pin",
                    source.name
                );
            }
            for tool in &source.evidence_tools {
                let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(&tool.component);
                let bytes = std::fs::read(&path)
                    .unwrap_or_else(|error| panic!("reading {}: {error}", path.display()));
                assert_eq!(
                    format!("{:x}", sha2::Sha256::digest(bytes)),
                    tool.component_sha256,
                    "{} has a stale evidence-tool component_sha256 pin",
                    tool.name
                );
            }
            for tool in &source.evidence_tools {
                let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(&tool.component);
                let bytes = std::fs::read(&path)
                    .unwrap_or_else(|error| panic!("reading {}: {error}", path.display()));
                let mut level = 0usize;
                let mut imports = BTreeSet::new();
                for payload in wasmparser::Parser::new(0).parse_all(&bytes) {
                    match payload.unwrap_or_else(|error| {
                        panic!("parsing {} evidence-tool component: {error}", tool.name)
                    }) {
                        wasmparser::Payload::Version { .. } => level += 1,
                        wasmparser::Payload::End(_) => level -= 1,
                        wasmparser::Payload::ComponentImportSection(section) if level == 1 => {
                            for import in section {
                                let name = import.expect("component import").name.name;
                                let interface = name
                                    .strip_prefix("kyyn:evidence-tool/")
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
                    BTreeSet::from(["evidence".into()]),
                    "{} must import only verified source evidence",
                    tool.name
                );
            }
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
    fn vendored_source_wit_matches_its_reviewed_fingerprint() {
        const FROZEN_SOURCE_WIT_SHA256: &str =
            "40dbb84d331bc6ff90c50d0cff640b923f4117c39d21bdc76564646e825a6177";
        assert_eq!(
            format!(
                "{:x}",
                sha2::Sha256::digest(include_bytes!("../wit/source.wit"))
            ),
            FROZEN_SOURCE_WIT_SHA256,
            "wit/source.wit drifted from its reviewed kyyn:source@1 fingerprint"
        );
        const FROZEN_SINK_WIT_SHA256: &str =
            "76bca92a2c69b8b350d3c26e1851709e670bcc66fdf52855230d5402bb3ead30";
        assert_eq!(
            format!(
                "{:x}",
                sha2::Sha256::digest(include_bytes!("../wit/sink.wit"))
            ),
            FROZEN_SINK_WIT_SHA256,
            "wit/sink.wit drifted from kyyn's frozen kyyn:sink@1 contract"
        );
        const FROZEN_CONNECTION_WIT_SHA256: &str =
            "a1c169fdafdfbac80e7d7496bb75fac9b1a5f5c0a7dd7899376f48854a416bcd";
        assert_eq!(
            format!(
                "{:x}",
                sha2::Sha256::digest(include_bytes!("../wit/connection.wit"))
            ),
            FROZEN_CONNECTION_WIT_SHA256,
            "wit/connection.wit drifted from kyyn's frozen kyyn:connection@1 contract"
        );
        const FROZEN_CONFIGURATOR_WIT_SHA256: &str =
            "dbc345c42d3d4586e71cf006390c9c852673febe08694e2a6c13b6eeeb261907";
        assert_eq!(
            format!(
                "{:x}",
                sha2::Sha256::digest(include_bytes!("../wit/configurator.wit"))
            ),
            FROZEN_CONFIGURATOR_WIT_SHA256,
            "wit/configurator.wit drifted from kyyn's frozen kyyn:configurator@1 contract"
        );
    }

    #[test]
    fn vendored_evidence_tool_wit_matches_kyyn_v1() {
        const FROZEN_EVIDENCE_TOOL_WIT_SHA256: &str =
            "dc1eff0d6ac3f2ebb0038c991f3b74fd5eae3d22fc6d1bffe09392e44065529a";
        let bytes = std::fs::read(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("wit/evidence-tool.wit"),
        )
        .expect("vendored evidence-tool WIT");
        assert_eq!(
            format!("{:x}", sha2::Sha256::digest(bytes)),
            FROZEN_EVIDENCE_TOOL_WIT_SHA256
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
            let mut expected = BTreeSet::from(["http".into(), "secrets".into()]);
            if !connection.workload_recipes.is_empty() {
                expected.insert("invocation-inputs".into());
            }
            assert_eq!(
                imports, expected,
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
            if let Some(configurator) = source.configurator {
                let path =
                    std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(&configurator.component);
                let bytes = std::fs::read(&path)
                    .unwrap_or_else(|error| panic!("reading {}: {error}", path.display()));
                let mut level = 0usize;
                let mut imports = BTreeSet::new();
                for payload in wasmparser::Parser::new(0).parse_all(&bytes) {
                    match payload.unwrap_or_else(|error| {
                        panic!("parsing {} configurator component: {error}", source.name)
                    }) {
                        wasmparser::Payload::Version { .. } => level += 1,
                        wasmparser::Payload::End(_) => level -= 1,
                        wasmparser::Payload::ComponentImportSection(section) if level == 1 => {
                            for import in section {
                                let name = import.expect("component import").name.name;
                                let interface = name
                                    .strip_prefix("kyyn:configurator/")
                                    .and_then(|name| name.split('@').next())
                                    .unwrap_or(name);
                                imports.insert(interface.to_string());
                            }
                        }
                        _ => {}
                    }
                }
                let expected = if configurator.requests.is_empty() {
                    BTreeSet::new()
                } else {
                    BTreeSet::from(["http".into()])
                };
                assert_eq!(
                    imports, expected,
                    "{} configurator imports must match its request authority",
                    source.name
                );
            }
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
            let expected = if sink.capabilities.requests.is_empty() {
                BTreeSet::from([sink.name.clone()])
            } else {
                BTreeSet::from(["request".to_string()])
            };
            assert_eq!(
                imports, expected,
                "{} must import exactly its one host effect operation",
                sink.name
            );
        }
    }
}
