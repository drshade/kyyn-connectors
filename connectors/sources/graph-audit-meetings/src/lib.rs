#[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
mod guest {
    mod bindings {
        wit_bindgen::generate!({
            path: "../../../wit/source.wit",
            world: "source",
        });
    }

    use std::collections::BTreeMap;

    use bindings::exports::kyyn::source::api::{
        AuthChallenge, AuthPollResult, AuthStatus, ConnectorDescribe, FetchCompletion,
        FetchRequest, FetchResult, FetchStyle, Guest, Item, Pending, RunSpec,
    };
    use bindings::kyyn::source::http::{self, Method as HostMethod, Purpose};
    use bindings::kyyn::source::{control, evidence};
    use graph_population::{
        AuditCompletion, Method, PopulationConfig, Request, Response, Transport,
    };
    use sha2::{Digest, Sha256};

    const GRAPH_ORIGIN: &str = "https://graph.microsoft.com";
    const RESPONSE_CAP: u64 = 64 * 1024 * 1024;

    struct GraphTransport;

    impl Transport for GraphTransport {
        fn send(&mut self, request: &Request) -> Result<Response, String> {
            let method = match request.method {
                Method::Get => HostMethod::Get,
                Method::Post => HostMethod::Post,
            };
            let response = http::fetch(&http::Request {
                purpose: Purpose::Observe,
                method,
                url: format!("{GRAPH_ORIGIN}{}", request.path),
                headers: request
                    .headers
                    .iter()
                    .map(|(name, value)| (name.clone(), value.clone()))
                    .collect(),
                body: request.body.clone(),
                secret_authorization: None,
                max_response_bytes: RESPONSE_CAP,
                timeout_ms: 120_000,
            })
            .map_err(|error| error.message)?;
            Ok(Response {
                status: response.status,
                headers: response
                    .headers
                    .into_iter()
                    .map(|(name, value)| (name.to_ascii_lowercase(), value))
                    .collect::<BTreeMap<_, _>>(),
                body: response.body,
            })
        }

        fn sleep_ms(&mut self, milliseconds: u64) {
            control::progress("Microsoft Graph asked the audit observation to retry");
            control::sleep_ms(milliseconds);
        }
    }

    fn write_evidence(path: &str, bytes: &[u8]) -> Result<String, String> {
        let file = evidence::open(path)?;
        file.write(bytes)?;
        Ok(file.finish()?.sha256)
    }

    fn audit_display_name(config: &PopulationConfig, start: &str, until: &str) -> String {
        let mut digest = Sha256::new();
        digest.update(b"kyyn:graph-audit-meetings:v1\0");
        digest.update(config.canonical_identity().as_bytes());
        digest.update(b"\0");
        digest.update(start.as_bytes());
        digest.update(b"\0");
        digest.update(until.as_bytes());
        let hex = format!("{:x}", digest.finalize());
        format!("kyyn-audit-{}", &hex[..32])
    }

    struct GraphAuditMeetings;

    impl Guest for GraphAuditMeetings {
        fn describe() -> ConnectorDescribe {
            ConnectorDescribe {
                name: "graph-audit-meetings".into(),
                link_namespace: "graph-audit".into(),
                fetch_style: FetchStyle::Windowed,
                auth_realm: None,
            }
        }

        fn validate_config(config: String) -> Result<(), String> {
            PopulationConfig::parse(&config).map(|_| ())
        }

        fn config_auth_realm(_config: String) -> Result<Option<String>, String> {
            Ok(None)
        }

        fn status(_config: String) -> Result<AuthStatus, String> {
            Ok(AuthStatus::NotRequired)
        }

        fn auth_begin(_config: String) -> Result<AuthChallenge, String> {
            Err("authentication belongs to the selected workload Connection".into())
        }

        fn auth_poll(_config: String, _handle: String) -> Result<AuthPollResult, String> {
            Err("authentication belongs to the selected workload Connection".into())
        }

        fn fetch(request: FetchRequest) -> Result<FetchResult, String> {
            let config = PopulationConfig::parse(&request.config)?;
            let RunSpec::Window(window) = request.spec else {
                return Err("graph-audit-meetings is a windowed source".into());
            };
            let mut transport = GraphTransport;
            let roster = graph_population::resolve_population(&mut transport, &config)?;
            let roster_bytes = serde_json::to_vec_pretty(&roster)
                .map_err(|_| "could not encode population roster evidence".to_string())?;
            let roster_sha256 = write_evidence("population.json", &roster_bytes)?;
            let display_name = audit_display_name(&config, &window.start, &window.until);
            let run = graph_population::fetch_audit(
                &mut transport,
                &config,
                &window.start,
                &window.until,
                &display_name,
                request.checkpoint.as_deref(),
            )?;
            let query_bytes = serde_json::to_vec_pretty(&run.query)
                .map_err(|_| "could not encode audit-query evidence".to_string())?;
            let query_sha256 = write_evidence("audit-query.json", &query_bytes)?;
            let record_bytes = serde_json::to_vec_pretty(&run.records)
                .map_err(|_| "could not encode audit-record evidence".to_string())?;
            write_evidence("audit-records.json", &record_bytes)?;
            let items = run
                .records
                .iter()
                .map(|record| {
                    Ok(Item {
                        id: record.id.clone(),
                        kind: "meeting-audit-record".into(),
                        version: None,
                        content_hash: kyyn_source_bundle::canonical_record_sha256(record)
                            .map_err(|error| error.to_string())?,
                        files: vec![
                            "population.json".into(),
                            "audit-query.json".into(),
                            "audit-records.json".into(),
                        ],
                        primary: "audit-records.json".into(),
                        file_hashes: vec![
                            ("population.json".into(), roster_sha256.clone()),
                            ("audit-query.json".into(), query_sha256.clone()),
                        ],
                        locator: Some(record.id.clone()),
                        meta: "Microsoft 365 meeting audit record".into(),
                    })
                })
                .collect::<Result<Vec<_>, String>>()?;
            let diagnostic = run
                .diagnostic
                .as_ref()
                .map(|diagnostic| format!("; {}", diagnostic.outcome))
                .unwrap_or_default();
            let notes = format!(
                "{} members; population sha256 {roster_sha256}{diagnostic}",
                roster.len()
            );
            match run.completion {
                AuditCompletion::Pending {
                    checkpoint,
                    retry_after_seconds,
                } => {
                    if !items.is_empty() {
                        return Err("pending audit observation unexpectedly carried items".into());
                    }
                    control::progress("Microsoft 365 audit query is pending");
                    Ok(FetchResult {
                        completion: FetchCompletion::Pending(Pending {
                            retry_after_seconds,
                        }),
                        attempt_context_sha256: Some(roster_sha256.clone()),
                        items,
                        notes,
                        next_checkpoint: Some(checkpoint),
                    })
                }
                AuditCompletion::Complete => {
                    control::progress(&format!(
                        "{} Microsoft 365 audit records observed across {} members",
                        items.len(),
                        roster.len()
                    ));
                    Ok(FetchResult {
                        completion: FetchCompletion::Complete,
                        attempt_context_sha256: Some(roster_sha256),
                        items,
                        notes,
                        next_checkpoint: None,
                    })
                }
            }
        }
    }

    bindings::export!(GraphAuditMeetings with_types_in bindings);
}
