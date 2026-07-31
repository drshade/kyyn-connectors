//! Repository-level contract gates for the first-party component tap.

#[cfg(test)]
use kyyn_core::plugin::SourcePlugin;

#[cfg(test)]
fn plugin_table(name: &str) -> Option<Box<dyn SourcePlugin>> {
    match name {
        "sweep" => Some(Box::new(kyyn_plugin_sweep::SweepPlugin)),
        "git-repo" => Some(Box::new(kyyn_plugin_git::GitRepoPlugin)),
        "salesforce" => Some(Box::new(kyyn_plugin_salesforce::SalesforcePlugin)),
        "pack" => Some(Box::new(kyyn_plugin_pack::PackPlugin)),
        "graph-mail" => Some(Box::new(kyyn_plugin_graph::GraphMailPlugin)),
        "graph-calendar" => Some(Box::new(kyyn_plugin_graph::GraphCalendarPlugin)),
        "graph-meetings" => Some(Box::new(kyyn_plugin_graph::GraphMeetingsPlugin)),
        "graph-chats" => Some(Box::new(kyyn_plugin_graph::GraphChatsPlugin)),
        "sharepoint-file" => Some(Box::new(kyyn_plugin_graph::SharepointFilePlugin)),
        _ => None,
    }
}

#[cfg(test)]
mod manifest_drift {
    use kyyn_core::tap::{TapConfigType, TapManifest};
    use sha2::Digest as _;

    fn manifest() -> TapManifest {
        let text = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/kyyn-tap.ron"))
            .expect("kyyn-tap.ron");
        TapManifest::parse(&text).expect("published SDK accepts the manifest")
    }

    /// THE drift guard: every plugin's declared config spec, filled with its
    /// own examples/defaults, must assemble into a config the plugin's real
    /// validate_config accepts — a spec that promises a field the code
    /// rejects (or mistypes) fails here, not in an owner's install form.
    #[test]
    fn declared_config_specs_satisfy_the_plugins() {
        let manifest = manifest();
        assert_eq!(manifest.plugins.len(), 9);
        for plugin in &manifest.plugins {
            let mut parts: Vec<String> = Vec::new();
            for f in &plugin.config {
                assert!(
                    !f.doc.is_empty(),
                    "{}#{} needs a doc line",
                    plugin.name,
                    f.name
                );
                let Some(value) = f.example.as_ref().or(f.default.as_ref()) else {
                    assert!(
                        !f.required,
                        "{}#{} is required but has no example",
                        plugin.name, f.name
                    );
                    continue;
                };
                let rendered = match f.ty {
                    TapConfigType::Int | TapConfigType::Bool | TapConfigType::Ron => value.clone(),
                    TapConfigType::StrList => format!(
                        "[{}]",
                        value
                            .split(',')
                            .map(|s| format!("{:?}", s.trim()))
                            .collect::<Vec<_>>()
                            .join(", ")
                    ),
                    // Str and Path both RON-quote the raw value.
                    TapConfigType::Str | TapConfigType::Path => format!("{value:?}"),
                };
                parts.push(format!("{}: {rendered}", f.name));
            }
            let config = format!("({})", parts.join(", "));
            let result = super::plugin_table(&plugin.name)
                .unwrap_or_else(|| panic!("manifest advertises unserved plugin '{}'", plugin.name))
                .validate_config(&config);
            assert!(
                result.is_ok(),
                "{}: spec-assembled config rejected: {:?}\n  config: {config}",
                plugin.name,
                result.err()
            );
        }
    }

    #[test]
    fn committed_component_digests_match_the_manifest() {
        for plugin in manifest().plugins {
            let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(&plugin.component);
            let bytes = std::fs::read(&path)
                .unwrap_or_else(|error| panic!("reading {}: {error}", path.display()));
            assert_eq!(
                format!("{:x}", sha2::Sha256::digest(bytes)),
                plugin.component_sha256,
                "{} has a stale component_sha256 pin",
                plugin.name
            );
        }
    }

    #[test]
    fn vendored_wit_matches_the_frozen_engine_contract() {
        const FROZEN_TAP_WIT_SHA256: &str =
            "b8ca45274112e5e2eddbb722b9ad5e67f50db19b5a5f1b7606aa02a2e93e58df";
        assert_eq!(
            format!(
                "{:x}",
                sha2::Sha256::digest(include_bytes!("../wit/tap.wit"))
            ),
            FROZEN_TAP_WIT_SHA256,
            "wit/tap.wit drifted from kyyn's frozen kyyn:tap@1 contract"
        );
    }

    #[test]
    fn component_imports_are_a_subset_of_declared_capabilities() {
        for plugin in manifest().plugins {
            let mut allowed = std::collections::BTreeSet::from(["control", "evidence"]);
            if !plugin.capabilities.network.is_empty() {
                allowed.insert("http");
            }
            if plugin.capabilities.auth.is_some() {
                allowed.insert("secrets");
            }
            if plugin.capabilities.repo {
                allowed.insert("repo");
            }
            if plugin
                .config
                .iter()
                .any(|field| field.ty == TapConfigType::Path)
            {
                allowed.insert("local");
            }

            let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(&plugin.component);
            let bytes = std::fs::read(&path)
                .unwrap_or_else(|error| panic!("reading {}: {error}", path.display()));
            let mut level = 0usize;
            let mut imports = std::collections::BTreeSet::new();
            for payload in wasmparser::Parser::new(0).parse_all(&bytes) {
                match payload
                    .unwrap_or_else(|error| panic!("parsing {} component: {error}", plugin.name))
                {
                    wasmparser::Payload::Version { .. } => level += 1,
                    wasmparser::Payload::End(_) => level -= 1,
                    wasmparser::Payload::ComponentImportSection(section) if level == 1 => {
                        for import in section {
                            let name = import.expect("component import").name.name;
                            let interface = name
                                .strip_prefix("kyyn:tap/")
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
                .cloned()
                .collect::<Vec<_>>();
            assert!(
                excess.is_empty(),
                "{} imports undeclared capabilities {excess:?}; imports={imports:?}, \
                 allowed={allowed:?}",
                plugin.name
            );
        }
    }
}
