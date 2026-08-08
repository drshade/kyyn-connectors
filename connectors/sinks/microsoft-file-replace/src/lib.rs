//! First-party Microsoft file publication connector. The component sees only
//! review text, the accepted expected state and replacement bytes. Canonical
//! target identity, Graph endpoints and credentials remain host-owned.

#[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
mod guest {
    mod bindings {
        wit_bindgen::generate!({
            path: "../../../wit/sink.wit",
            world: "microsoft-file-sink",
        });
    }

    use bindings::exports::kyyn::sink::api::{
        ApplyReport, ConnectorDescribe, Effect, EffectRendering, Guest,
    };
    use bindings::kyyn::sink::microsoft_file_replace;

    const MAX_REPLACEMENT_BYTES: usize = 64 * 1024 * 1024;

    #[derive(serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Config {
        destination: String,
    }

    #[derive(serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Present {
        item_id: String,
        etag: String,
        sha256: String,
        bytes: u64,
    }

    #[derive(serde::Deserialize)]
    enum Expected {
        Absent,
        Present(Present),
    }

    fn config(text: &str) -> Result<Config, String> {
        let config: Config = ron::from_str(text).map_err(|_| "invalid config".to_string())?;
        if config.destination.is_empty()
            || config.destination.len() > 2_048
            || config.destination.chars().any(char::is_control)
        {
            return Err("destination must be bounded display text".into());
        }
        Ok(config)
    }

    fn sha256(value: &str) -> bool {
        value.len() == 64
            && value
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    }

    fn expected(text: &str) -> Result<microsoft_file_replace::ExpectedState, String> {
        match ron::from_str::<Expected>(text).map_err(|_| "invalid expected state".to_string())? {
            Expected::Absent => Ok(microsoft_file_replace::ExpectedState::Absent),
            Expected::Present(value) => {
                if value.item_id.is_empty()
                    || value.item_id.len() > 512
                    || value.etag.is_empty()
                    || value.etag.len() > 1_024
                    || !sha256(&value.sha256)
                    || value.bytes > MAX_REPLACEMENT_BYTES as u64
                {
                    return Err("present state is invalid".into());
                }
                Ok(microsoft_file_replace::ExpectedState::Present(
                    microsoft_file_replace::PresentState {
                        item_id: value.item_id,
                        etag: value.etag,
                        sha256: value.sha256,
                        bytes: value.bytes,
                    },
                ))
            }
        }
    }

    fn validate(
        effect: &Effect,
    ) -> Result<(Config, microsoft_file_replace::ExpectedState), String> {
        let config = config(&effect.config)?;
        let expected = expected(&effect.expected_target)?;
        if effect.payload.is_empty() || effect.payload.len() > MAX_REPLACEMENT_BYTES {
            return Err("replacement must be between 1 byte and 64 MiB".into());
        }
        if effect.payload_media_type.is_empty()
            || effect.payload_media_type.len() > 256
            || !effect.payload_media_type.contains('/')
            || effect.payload_media_type.chars().any(char::is_whitespace)
        {
            return Err("replacement must have a bounded valid media type".into());
        }
        Ok((config, expected))
    }

    struct MicrosoftFileReplace;

    impl Guest for MicrosoftFileReplace {
        fn describe() -> ConnectorDescribe {
            ConnectorDescribe {
                name: "microsoft-file-replace".into(),
            }
        }

        fn validate_config(config_text: String) -> Result<(), String> {
            config(&config_text).map(|_| ())
        }

        fn validate_effect(effect: Effect) -> Result<(), String> {
            validate(&effect).map(|_| ())
        }

        fn render_effect(effect: Effect) -> Result<EffectRendering, String> {
            let (config, expected) = validate(&effect)?;
            let action = match expected {
                microsoft_file_replace::ExpectedState::Absent => "create if still absent",
                microsoft_file_replace::ExpectedState::Present(_) => {
                    "replace if the reviewed Microsoft version still matches"
                }
            };
            Ok(EffectRendering {
                destination: config.destination,
                summary: format!("{action} with {} byte(s)", effect.payload.len()),
            })
        }

        fn apply(effect: Effect) -> Result<ApplyReport, String> {
            let (_, expected) = validate(&effect)?;
            let outcome = microsoft_file_replace::replace(&expected, &effect.payload)
                .map_err(|failure| format!("{}: {}", failure.code, failure.message))?;
            let note = match outcome {
                microsoft_file_replace::ReplaceOutcome::Applied(value) => format!(
                    "applied {} -> {} ({} byte(s))",
                    value.previous_sha256, value.resulting_sha256, value.bytes
                ),
                microsoft_file_replace::ReplaceOutcome::Created(value) => format!(
                    "created {} ({} byte(s))",
                    value.resulting_sha256, value.bytes
                ),
                microsoft_file_replace::ReplaceOutcome::AlreadyConverged(value) => format!(
                    "already converged at {} ({} byte(s))",
                    value.resulting_sha256, value.bytes
                ),
                microsoft_file_replace::ReplaceOutcome::Conflict(value) => format!(
                    "conflict: expected {}, observed {}",
                    value.expected_sha256,
                    value.observed_sha256.as_deref().unwrap_or("absent")
                ),
                microsoft_file_replace::ReplaceOutcome::CreateConflict(value) => format!(
                    "conflict: expected absent, observed {}",
                    value.observed_sha256
                ),
            };
            Ok(ApplyReport { note })
        }
    }

    bindings::export!(MicrosoftFileReplace with_types_in bindings);
}
