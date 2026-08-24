#![cfg_attr(
    not(all(target_arch = "wasm32", target_os = "unknown")),
    allow(dead_code)
)]

use graph_population::{PopulationConfig, SetupInput};

fn configure(ephemeral: &str) -> Result<PopulationConfig, String> {
    let input: SetupInput = ron::from_str(ephemeral)
        .map_err(|_| "population setup input is not valid closed RON".to_string())?;
    PopulationConfig::from_setup(input)
}

#[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
mod guest {
    mod bindings {
        wit_bindgen::generate!({
            path: "../../../wit/configurator.wit",
            world: "configurator",
        });
    }

    use super::*;
    use bindings::exports::kyyn::configurator::api::{
        ConfigureOutput, ConfigureRequest, Diagnostic, DiagnosticClass, Guest,
    };

    struct GraphPopulation;

    impl Guest for GraphPopulation {
        fn configure(request: ConfigureRequest) -> Result<ConfigureOutput, String> {
            let config = configure(&request.ephemeral_config)?;
            let display_summary = config.display_summary();
            Ok(ConfigureOutput {
                durable_config: ron::ser::to_string(&config)
                    .map_err(|_| "could not encode governed population scope".to_string())?,
                display_summary,
                diagnostics: vec![Diagnostic {
                    class: DiagnosticClass::Info,
                    message: "Population scope is explicit".into(),
                    detail: Some(
                        "The selected scope governs connector observation; provider application authority is reviewed separately."
                            .into(),
                    ),
                }],
            })
        }
    }

    bindings::export!(GraphPopulation with_types_in bindings);
}

#[cfg(test)]
mod tests {
    use super::*;
    use graph_population::MemberScope;

    #[test]
    fn setup_emits_only_the_closed_durable_scope() {
        let config =
            configure(r#"(scope_mode:"selected-members",selected_users:["alpha@example.test"])"#)
                .unwrap();
        assert_eq!(
            config.scope,
            MemberScope::SelectedMembers {
                users: vec!["alpha@example.test".into()]
            }
        );
        let durable = ron::to_string(&config).unwrap();
        assert!(durable.contains("scope:SelectedMembers"));
        assert!(!durable.contains("scope_mode"));
        assert_eq!(PopulationConfig::parse(&durable).unwrap(), config);
    }

    #[test]
    fn flat_empty_and_contradictory_setup_states_refuse() {
        for input in [
            r#"(scope_mode:"selected-members",selected_users:[])"#,
            r#"(scope_mode:"all-members",selected_users:["alpha@example.test"])"#,
            r#"(scope_mode:"other",selected_users:[])"#,
            r#"(scope_mode:"all-members",selected_users:[],extra:true)"#,
        ] {
            assert!(configure(input).is_err(), "accepted {input}");
        }
    }
}
