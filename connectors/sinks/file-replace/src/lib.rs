//! First-party `kyyn:sink@1` file replacement connector. The accepted config
//! names the destination for review; only the host binds and exercises it.

#[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
mod guest {
    mod bindings {
        wit_bindgen::generate!({
            path: "../../../wit/sink.wit",
            world: "sink",
        });
    }

    use bindings::exports::kyyn::sink::api::{
        ApplyReport, ConnectorDescribe, Effect, EffectRendering, Guest,
    };
    use bindings::kyyn::sink::file_replace;

    #[derive(serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Config {
        path: String,
    }

    fn config(text: &str) -> Result<Config, String> {
        let value: ron::Value = ron::from_str(text).map_err(|error| error.to_string())?;
        let config: Config = value.into_rust().map_err(|error| error.to_string())?;
        if config.path.is_empty() {
            return Err("path must not be empty".into());
        }
        Ok(config)
    }

    fn sha256(value: &str) -> bool {
        value.len() == 64
            && value
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    }

    fn validate(effect: &Effect) -> Result<Config, String> {
        let config = config(&effect.config)?;
        if !sha256(&effect.expected_target) {
            return Err("expected-target must be lowercase SHA-256".into());
        }
        if effect.payload_media_type.is_empty()
            || effect.payload_media_type.len() > 256
            || !effect.payload_media_type.contains('/')
            || effect.payload_media_type.chars().any(char::is_whitespace)
        {
            return Err("file replacement payload must have a bounded valid media type".into());
        }
        Ok(config)
    }

    struct FileReplace;

    impl Guest for FileReplace {
        fn describe() -> ConnectorDescribe {
            ConnectorDescribe {
                name: "file-replace".into(),
            }
        }

        fn validate_config(config_text: String) -> Result<(), String> {
            config(&config_text).map(|_| ())
        }

        fn validate_effect(effect: Effect) -> Result<(), String> {
            validate(&effect).map(|_| ())
        }

        fn render_effect(effect: Effect) -> Result<EffectRendering, String> {
            let config = validate(&effect)?;
            Ok(EffectRendering {
                destination: config.path,
                summary: format!(
                    "replace {} byte(s) if current SHA-256 is {}",
                    effect.payload.len(),
                    effect.expected_target
                ),
            })
        }

        fn apply(effect: Effect) -> Result<ApplyReport, String> {
            validate(&effect)?;
            let result = file_replace::replace(&effect.expected_target, &effect.payload)
                .map_err(|failure| format!("{}: {}", failure.code, failure.message))?;
            let note = match result {
                file_replace::ReplaceOutcome::Applied(observed) => format!(
                    "applied {} -> {} ({} byte(s))",
                    observed.previous_sha256, observed.resulting_sha256, observed.bytes
                ),
                file_replace::ReplaceOutcome::AlreadyConverged(observed) => format!(
                    "already converged at {} ({} byte(s))",
                    observed.resulting_sha256, observed.bytes
                ),
                file_replace::ReplaceOutcome::Conflict(observed) => format!(
                    "conflict: expected {}, observed {}",
                    observed.expected_sha256, observed.observed_sha256
                ),
            };
            Ok(ApplyReport { note })
        }
    }

    bindings::export!(FileReplace with_types_in bindings);
}
