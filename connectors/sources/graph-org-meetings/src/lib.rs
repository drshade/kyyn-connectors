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
        ArtifactOutcome, BatchCompletion, Method, PopulationConfig, Request, Response, Transport,
        meeting_occurrence_digest,
    };

    const GRAPH_ORIGIN: &str = "https://graph.microsoft.com";
    // A single provider response remains well below the component's 128 MiB
    // linear-memory ceiling even while its compact evidence representation is
    // being encoded. Logical result cardinality is handled by Pending batches.
    const RESPONSE_CAP: u64 = 8 * 1024 * 1024;

    struct GraphTransport;

    impl Transport for GraphTransport {
        fn send(&mut self, request: &Request) -> Result<Response, String> {
            let method = match request.method {
                Method::Get => HostMethod::Get,
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

        fn send_many(
            &mut self,
            requests: &[Request],
        ) -> Result<Vec<Result<Response, String>>, String> {
            let requests = requests
                .iter()
                .map(|request| http::Request {
                    purpose: Purpose::Observe,
                    method: match request.method {
                        Method::Get => HostMethod::Get,
                    },
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
                .collect::<Vec<_>>();
            http::fetch_many(&requests)
                .map_err(|error| error.message)
                .map(|results| {
                    results
                        .into_iter()
                        .map(|result| {
                            result
                                .map_err(|error| error.message)
                                .map(|response| Response {
                                    status: response.status,
                                    headers: response
                                        .headers
                                        .into_iter()
                                        .map(|(name, value)| (name.to_ascii_lowercase(), value))
                                        .collect::<BTreeMap<_, _>>(),
                                    body: response.body,
                                })
                        })
                        .collect()
                })
        }

        fn sleep_ms(&mut self, milliseconds: u64) {
            control::progress("Microsoft Graph asked the meeting observation to retry");
            control::sleep_ms(milliseconds);
        }
    }

    fn write_evidence(path: &str, bytes: &[u8]) -> Result<String, String> {
        let file = evidence::open(path)?;
        file.write(bytes)?;
        Ok(file.finish()?.sha256)
    }

    struct GraphOrgMeetings;

    impl Guest for GraphOrgMeetings {
        fn describe() -> ConnectorDescribe {
            ConnectorDescribe {
                name: "graph-org-meetings".into(),
                link_namespace: "graph-org".into(),
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
                return Err("graph-org-meetings is a windowed source".into());
            };
            let mut item_drafts = Vec::new();
            let mut unavailable = 0usize;
            let run = graph_population::fetch_meeting_batch(
                &mut GraphTransport,
                &config,
                &window.start,
                &window.until,
                request.checkpoint.as_deref(),
                |meeting| {
                    unavailable += usize::from(matches!(
                        meeting.transcript,
                        ArtifactOutcome::Unavailable { .. }
                    )) + usize::from(matches!(
                        meeting.attendance,
                        ArtifactOutcome::Unavailable { .. }
                    ));
                    let meeting_bytes = serde_json::to_vec(&meeting)
                        .map_err(|_| "could not encode joined meeting evidence".to_string())?;
                    let file_name =
                        format!("meetings/{}.json", meeting_occurrence_digest(&meeting.id)?);
                    let meeting_sha256 = write_evidence(&file_name, &meeting_bytes)?;
                    item_drafts.push((
                        meeting.id,
                        meeting.observed_by_user_principal_name,
                        file_name,
                        meeting_sha256,
                    ));
                    Ok(())
                },
            )?;
            if item_drafts.len() != run.item_count {
                return Err("joined meeting batch item count changed during emission".into());
            }
            let roster_bytes = serde_json::to_vec(&run.roster)
                .map_err(|_| "could not encode population roster evidence".to_string())?;
            let roster_sha256 = write_evidence("population.json", &roster_bytes)?;
            let mut items = item_drafts
                .into_iter()
                .map(|(id, observer, file_name, meeting_sha256)| Item {
                    id,
                    kind: "org-meeting".into(),
                    version: None,
                    content_hash: meeting_sha256,
                    files: vec!["population.json".into(), file_name.clone()],
                    primary: file_name,
                    file_hashes: vec![("population.json".into(), roster_sha256.clone())],
                    locator: None,
                    meta: format!("meeting evidence for {observer}"),
                })
                .collect::<Vec<_>>();
            for unavailable_member in &run.unavailable_members {
                let member_bytes = serde_json::to_vec(unavailable_member)
                    .map_err(|_| "could not encode unavailable member evidence".to_string())?;
                let file_name = format!(
                    "members/{}.json",
                    unavailable_member
                        .id
                        .strip_prefix("member-observation:v1:")
                        .ok_or_else(|| "member observation identity is invalid".to_string())?
                );
                let member_sha256 = write_evidence(&file_name, &member_bytes)?;
                items.push(Item {
                    id: unavailable_member.id.clone(),
                    kind: "org-member-observation".into(),
                    version: None,
                    content_hash: member_sha256,
                    files: vec!["population.json".into(), file_name.clone()],
                    primary: file_name,
                    file_hashes: vec![("population.json".into(), roster_sha256.clone())],
                    locator: None,
                    meta: format!(
                        "mailbox unavailable for {}",
                        unavailable_member.user_principal_name
                    ),
                });
            }
            control::progress(&format!(
                "{} population item(s) observed across {} members",
                items.len(),
                run.roster.len()
            ));
            let (completion, next_checkpoint) = match run.completion {
                BatchCompletion::Complete => (FetchCompletion::Complete, None),
                BatchCompletion::Pending { checkpoint } => (
                    FetchCompletion::Pending(Pending {
                        retry_after_seconds: None,
                    }),
                    Some(checkpoint),
                ),
            };
            Ok(FetchResult {
                completion,
                attempt_context_sha256: Some(roster_sha256.clone()),
                items,
                notes: format!(
                    "{} members; {} mailbox-unavailable member(s); {unavailable} unavailable artifact outcome(s); population sha256 {roster_sha256}",
                    run.roster.len(),
                    run.unavailable_members.len(),
                ),
                next_checkpoint,
            })
        }
    }

    bindings::export!(GraphOrgMeetings with_types_in bindings);
}
