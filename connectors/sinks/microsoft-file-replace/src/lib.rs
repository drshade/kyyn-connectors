//! Microsoft file publication semantics implemented entirely inside the
//! pinned connector guest. The host supplies only exact reviewed request
//! grants, named-connection authorization and the accepted artifact bytes.

#[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
mod guest {
    mod bindings {
        wit_bindgen::generate!({
            path: "../../../wit/sink.wit",
            world: "remote-sink",
        });
    }

    use bindings::exports::kyyn::sink::api::{
        ApplyReport, ConflictOutcome, ConnectorDescribe, Effect, EffectRendering, FailedOutcome,
        Guest, ObservedOutcome, Outcome, TargetObservation,
    };
    use bindings::kyyn::sink::request::{self, BodySource, Operation};
    use serde::{Deserialize, Serialize};
    use sha2::{Digest, Sha256};

    const MAX_ARTIFACT_BYTES: usize = 16 * 1024 * 1024;

    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Config {
        drive_id: String,
        item_id: String,
        item_kind: String,
        display_name: String,
        target_mode: String,
        filename: Option<String>,
    }

    #[derive(Clone, Debug, Deserialize, Serialize)]
    enum Expected {
        Absent,
        Present {
            etag: String,
            sha256: String,
            bytes: u64,
        },
    }

    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct GraphItem {
        id: String,
        name: String,
        #[serde(rename = "eTag")]
        etag: Option<String>,
        size: Option<u64>,
        file: Option<serde_json::Value>,
    }

    enum Current {
        Absent,
        Present {
            etag: String,
            sha256: String,
            bytes: u64,
        },
    }

    fn safe_token(value: &str) -> bool {
        !value.is_empty()
            && value.len() <= 512
            && value
                .bytes()
                .all(|byte| byte.is_ascii_graphic() && !matches!(byte, b'/' | b'\\'))
    }

    fn safe_display(value: &str) -> bool {
        !value.trim().is_empty() && value.len() <= 512 && !value.chars().any(char::is_control)
    }

    fn safe_filename(value: &str) -> bool {
        !value.is_empty()
            && value.len() <= 255
            && !matches!(value, "." | "..")
            && !value
                .chars()
                .any(|character| character.is_control() || "\\/:*?\"<>|".contains(character))
    }

    fn config(text: &str) -> Result<Config, String> {
        let config: Config = ron::from_str(text).map_err(|_| "invalid config".to_string())?;
        if !safe_token(&config.drive_id)
            || !safe_token(&config.item_id)
            || !safe_display(&config.display_name)
        {
            return Err("resolved resource identity is invalid".into());
        }
        match config.target_mode.as_str() {
            "existing-file" if config.item_kind == "file" && config.filename.is_none() => {}
            "folder-child"
                if config.item_kind == "folder"
                    && config.filename.as_deref().is_some_and(safe_filename) => {}
            "existing-file" => {
                return Err("existing-file requires a resolved file and no filename".into());
            }
            "folder-child" => {
                return Err("folder-child requires a resolved folder and safe filename".into());
            }
            _ => return Err("target_mode must be existing-file or folder-child".into()),
        }
        Ok(config)
    }

    fn destination(config: &Config) -> String {
        match config.filename.as_deref() {
            Some(filename) => format!("{}/{}", config.display_name, filename),
            None => config.display_name.clone(),
        }
    }

    fn grant(config: &Config, operation: &str) -> String {
        let target = if config.target_mode == "existing-file" {
            "existing"
        } else {
            "child"
        };
        format!("{target}-{operation}")
    }

    fn fetch(
        grant: String,
        headers: Vec<(String, String)>,
        body: BodySource,
    ) -> Result<request::Response, String> {
        request::fetch(&Operation {
            grant,
            headers,
            body,
        })
        .map_err(|error| error.message)
    }

    fn item(response: &request::Response) -> Result<GraphItem, String> {
        serde_json::from_slice(&response.body)
            .map_err(|_| "Microsoft returned malformed file metadata".to_string())
    }

    fn sha256(bytes: &[u8]) -> String {
        format!("{:x}", Sha256::digest(bytes))
    }

    fn observe_current(config: &Config) -> Result<Current, String> {
        let metadata = fetch(grant(config, "metadata"), Vec::new(), BodySource::None)?;
        if metadata.status == 404 {
            if config.target_mode == "folder-child" {
                return Ok(Current::Absent);
            }
            return Err("The reviewed existing file no longer exists".into());
        }
        if metadata.status != 200 {
            return Err(format!(
                "Microsoft file metadata request failed (HTTP {})",
                metadata.status
            ));
        }
        let item = item(&metadata)?;
        if !safe_token(&item.id)
            || !safe_display(&item.name)
            || item.file.is_none()
            || item.etag.as_deref().is_none_or(str::is_empty)
        {
            return Err("Microsoft returned incomplete file metadata".into());
        }
        let content = fetch(grant(config, "content"), Vec::new(), BodySource::None)?;
        if content.status != 200 {
            return Err(format!(
                "Microsoft file content request failed (HTTP {})",
                content.status
            ));
        }
        let bytes = content.body.len() as u64;
        if item.size.is_some_and(|size| size != bytes) {
            return Err("Microsoft metadata size differs from downloaded content".into());
        }
        Ok(Current::Present {
            etag: item.etag.expect("checked above"),
            sha256: sha256(&content.body),
            bytes,
        })
    }

    fn encode_expected(current: &Current) -> Result<String, String> {
        let value = match current {
            Current::Absent => Expected::Absent,
            Current::Present {
                etag,
                sha256,
                bytes,
            } => Expected::Present {
                etag: etag.clone(),
                sha256: sha256.clone(),
                bytes: *bytes,
            },
        };
        ron::ser::to_string(&value).map_err(|_| "could not encode observed target state".into())
    }

    fn decode_expected(text: &str) -> Result<Expected, String> {
        ron::from_str(text).map_err(|_| "invalid expected target state".into())
    }

    fn validate_effect(effect: &Effect) -> Result<Config, String> {
        let config = config(&effect.config)?;
        let _ = decode_expected(&effect.expected_target)?;
        if effect.payload.is_empty() || effect.payload.len() > MAX_ARTIFACT_BYTES {
            return Err("artifact must contain 1..=16777216 bytes".into());
        }
        if effect.payload_media_type.is_empty()
            || effect.payload_media_type.len() > 256
            || !effect.payload_media_type.contains('/')
            || effect.payload_media_type.chars().any(char::is_whitespace)
        {
            return Err("artifact must have a bounded valid media type".into());
        }
        Ok(config)
    }

    fn current_sha(current: &Current) -> Option<&str> {
        match current {
            Current::Absent => None,
            Current::Present { sha256, .. } => Some(sha256),
        }
    }

    fn expected_matches(expected: &Expected, current: &Current) -> bool {
        match (expected, current) {
            (Expected::Absent, Current::Absent) => true,
            (
                Expected::Present {
                    etag: expected_etag,
                    sha256: expected_sha,
                    bytes: expected_bytes,
                },
                Current::Present {
                    etag,
                    sha256,
                    bytes,
                },
            ) => expected_etag == etag && expected_sha == sha256 && expected_bytes == bytes,
            _ => false,
        }
    }

    fn failed(code: &str, message: String, retryable: bool) -> ApplyReport {
        ApplyReport {
            outcome: Outcome::Failed(FailedOutcome {
                code: code.into(),
                message,
                retryable,
            }),
        }
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

        fn observe(config_text: String) -> Result<TargetObservation, String> {
            let config = config(&config_text)?;
            let current = observe_current(&config)?;
            Ok(TargetObservation {
                expected_target: encode_expected(&current)?,
                destination: destination(&config),
                summary: match current {
                    Current::Absent => "create if the reviewed target remains absent".into(),
                    Current::Present { bytes, .. } => {
                        format!("replace if the reviewed {bytes}-byte target still matches")
                    }
                },
            })
        }

        fn validate_effect(effect: Effect) -> Result<(), String> {
            validate_effect(&effect).map(|_| ())
        }

        fn render_effect(effect: Effect) -> Result<EffectRendering, String> {
            let config = validate_effect(&effect)?;
            let expected = decode_expected(&effect.expected_target)?;
            Ok(EffectRendering {
                destination: destination(&config),
                summary: format!(
                    "{} with {} exact accepted byte(s)",
                    if matches!(expected, Expected::Absent) {
                        "create if still absent"
                    } else {
                        "replace if the reviewed state still matches"
                    },
                    effect.payload.len()
                ),
            })
        }

        fn apply(effect: Effect) -> Result<ApplyReport, String> {
            let config = validate_effect(&effect)?;
            let expected = decode_expected(&effect.expected_target)?;
            let current = match observe_current(&config) {
                Ok(current) => current,
                Err(message) => return Ok(failed("observe-failed", message, true)),
            };
            let desired_sha = sha256(&effect.payload);
            if current_sha(&current) == Some(desired_sha.as_str()) {
                return Ok(ApplyReport {
                    outcome: Outcome::AlreadyConverged(ObservedOutcome {
                        observed_state: desired_sha,
                        note: "already converged".into(),
                    }),
                });
            }
            if !expected_matches(&expected, &current) {
                return Ok(ApplyReport {
                    outcome: Outcome::Conflict(ConflictOutcome {
                        observed_state: current_sha(&current).unwrap_or("absent").into(),
                        message: "target changed after publication preparation".into(),
                    }),
                });
            }

            let mut headers = vec![("Content-Type".into(), effect.payload_media_type.clone())];
            match &expected {
                Expected::Absent => headers.push(("If-None-Match".into(), "*".into())),
                Expected::Present { etag, .. } => headers.push(("If-Match".into(), etag.clone())),
            }
            let upload = match fetch(
                grant(&config, "upload"),
                headers,
                BodySource::AcceptedArtifact,
            ) {
                Ok(response) => response,
                Err(message) => return Ok(failed("upload-failed", message, true)),
            };
            if upload.status == 409 || upload.status == 412 {
                return Ok(ApplyReport {
                    outcome: Outcome::Conflict(ConflictOutcome {
                        observed_state: current_sha(&current).unwrap_or("absent").into(),
                        message:
                            "Microsoft refused the conditional write because the target changed"
                                .into(),
                    }),
                });
            }
            if !matches!(upload.status, 200 | 201) {
                return Ok(failed(
                    "upload-refused",
                    format!("Microsoft file upload failed (HTTP {})", upload.status),
                    upload.status >= 500,
                ));
            }
            let confirmed = match observe_current(&config) {
                Ok(current) => current,
                Err(message) => return Ok(failed("confirmation-failed", message, true)),
            };
            if current_sha(&confirmed) != Some(desired_sha.as_str()) {
                return Ok(failed(
                    "confirmation-mismatch",
                    "Microsoft confirmation did not match the accepted artifact".into(),
                    false,
                ));
            }
            Ok(ApplyReport {
                outcome: Outcome::Applied(ObservedOutcome {
                    observed_state: desired_sha,
                    note: if matches!(expected, Expected::Absent) {
                        "created and confirmed".into()
                    } else {
                        "replaced and confirmed".into()
                    },
                }),
            })
        }
    }

    bindings::export!(MicrosoftFileReplace with_types_in bindings);
}
