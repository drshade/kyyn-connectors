//! First-party `kyyn:sink@1` Git ref connector. The accepted config identifies
//! the destination for review; only the host binds credentials and transport.

#[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
mod guest {
    mod bindings {
        wit_bindgen::generate!({
            path: "../../../wit/sink.wit",
            world: "git-ref-sink",
        });
    }

    use bindings::exports::kyyn::sink::api::{
        ApplyReport, ConflictOutcome, ConnectorDescribe, Effect, EffectRendering, Guest,
        ObservedOutcome, Outcome, TargetObservation,
    };
    use bindings::kyyn::sink::git_ref;

    const MAX_BUNDLE_BYTES: usize = 16 * 1024 * 1024;

    #[derive(serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Config {
        repository: String,
        reference: String,
    }

    #[derive(serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Transition {
        expected_oid: String,
        new_oid: String,
    }

    fn decode<T: serde::de::DeserializeOwned>(text: &str) -> Result<T, String> {
        let value: ron::Value = ron::from_str(text).map_err(|error| error.to_string())?;
        value.into_rust().map_err(|error| error.to_string())
    }

    fn valid_repository(value: &str) -> bool {
        (value.starts_with("ssh://") || value.starts_with("https://"))
            && value.len() > "ssh://".len()
            && !value.contains(['?', '#'])
            && !value.bytes().any(|byte| byte.is_ascii_whitespace())
    }

    fn valid_branch(value: &str) -> bool {
        let Some(tail) = value.strip_prefix("refs/heads/") else {
            return false;
        };
        !tail.is_empty()
            && !tail.starts_with('/')
            && !tail.ends_with('/')
            && !tail.ends_with('.')
            && !tail.contains("..")
            && !tail.contains("@{")
            && !tail.contains("//")
            && !tail.bytes().any(|byte| {
                byte <= b' '
                    || byte == 0x7f
                    || matches!(byte, b'~' | b'^' | b':' | b'?' | b'*' | b'[' | b'\\')
            })
    }

    fn config(text: &str) -> Result<Config, String> {
        let config: Config = decode(text)?;
        if !valid_repository(&config.repository) {
            return Err("repository must be an absolute ssh:// or https:// URL without query, fragment, or whitespace".into());
        }
        if !valid_branch(&config.reference) {
            return Err("reference must be a canonical full refs/heads/... branch ref".into());
        }
        Ok(config)
    }

    fn oid(value: &str) -> bool {
        value.len() == 40
            && value
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    }

    fn validate(effect: &Effect) -> Result<(Config, Transition), String> {
        let config = config(&effect.config)?;
        let transition: Transition = decode(&effect.expected_target)?;
        if !oid(&transition.expected_oid) || !oid(&transition.new_oid) {
            return Err(
                "expected_oid and new_oid must be lowercase 40-hex SHA-1 commit OIDs".into(),
            );
        }
        if transition.expected_oid == transition.new_oid {
            return Err("new_oid must differ from expected_oid".into());
        }
        if effect.payload_media_type != "application/x-git-bundle" {
            return Err("git-ref payload must be application/x-git-bundle".into());
        }
        if effect.payload.is_empty() || effect.payload.len() > MAX_BUNDLE_BYTES {
            return Err("Git bundle must contain 1..=16777216 bytes".into());
        }
        Ok((config, transition))
    }

    struct GitRef;

    impl Guest for GitRef {
        fn describe() -> ConnectorDescribe {
            ConnectorDescribe {
                name: "git-ref".into(),
            }
        }

        fn validate_config(config_text: String) -> Result<(), String> {
            config(&config_text).map(|_| ())
        }

        fn observe(_config_text: String) -> Result<TargetObservation, String> {
            Err("Git ref observation is host-owned".into())
        }

        fn validate_effect(effect: Effect) -> Result<(), String> {
            validate(&effect).map(|_| ())
        }

        fn render_effect(effect: Effect) -> Result<EffectRendering, String> {
            let (config, transition) = validate(&effect)?;
            Ok(EffectRendering {
                destination: format!("{}#{}", config.repository, config.reference),
                summary: format!(
                    "advance {} -> {} using {}-byte accepted Git bundle",
                    transition.expected_oid,
                    transition.new_oid,
                    effect.payload.len()
                ),
            })
        }

        fn apply(effect: Effect) -> Result<ApplyReport, String> {
            let (_, transition) = validate(&effect)?;
            let result = git_ref::ensure(
                &transition.expected_oid,
                &transition.new_oid,
                &effect.payload,
            )
            .map_err(|failure| format!("{}: {}", failure.code, failure.message))?;
            let outcome = match result {
                git_ref::TransitionOutcome::Applied(observed) => {
                    Outcome::Applied(ObservedOutcome {
                        observed_state: observed.resulting_oid.clone(),
                        note: format!(
                            "applied {} -> {}",
                            observed.previous_oid, observed.resulting_oid
                        ),
                    })
                }
                git_ref::TransitionOutcome::AlreadyConverged(observed) => {
                    Outcome::AlreadyConverged(ObservedOutcome {
                        observed_state: observed.resulting_oid.clone(),
                        note: format!("already converged at {}", observed.resulting_oid),
                    })
                }
                git_ref::TransitionOutcome::Conflict(observed) => match observed.observed_oid {
                    Some(oid) => Outcome::Conflict(ConflictOutcome {
                        observed_state: oid.clone(),
                        message: format!("expected {}, observed {}", observed.expected_oid, oid),
                    }),
                    None => Outcome::Conflict(ConflictOutcome {
                        observed_state: "absent".into(),
                        message: format!(
                            "expected {}, observed absent branch",
                            observed.expected_oid
                        ),
                    }),
                },
            };
            Ok(ApplyReport { outcome })
        }
    }

    bindings::export!(GitRef with_types_in bindings);
}
