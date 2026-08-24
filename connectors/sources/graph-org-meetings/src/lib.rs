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
        FetchRequest, FetchResult, FetchStyle, Guest, Item, RunSpec,
    };
    use bindings::kyyn::source::http::{self, Method as HostMethod, Purpose};
    use bindings::kyyn::source::{control, evidence};
    use graph_population::{Method, PopulationConfig, Request, Response, Transport};

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
            let run = graph_population::fetch_meetings(
                &mut GraphTransport,
                &config,
                &window.start,
                &window.until,
            )?;
            let roster_bytes = serde_json::to_vec_pretty(&run.roster)
                .map_err(|_| "could not encode population roster evidence".to_string())?;
            let roster_sha256 = write_evidence("population.json", &roster_bytes)?;
            let meeting_bytes = serde_json::to_vec_pretty(&run.meetings)
                .map_err(|_| "could not encode population meeting evidence".to_string())?;
            write_evidence("meetings.json", &meeting_bytes)?;
            let items = run
                .meetings
                .iter()
                .map(|meeting| {
                    Ok(Item {
                        id: meeting.id.clone(),
                        kind: "org-meeting".into(),
                        version: None,
                        content_hash: kyyn_source_bundle::canonical_record_sha256(meeting)
                            .map_err(|error| error.to_string())?,
                        files: vec!["population.json".into(), "meetings.json".into()],
                        file_hashes: Vec::new(),
                        locator: Some(meeting.id.clone()),
                        meta: format!(
                            "meeting evidence for {}",
                            meeting.member_user_principal_name
                        ),
                    })
                })
                .collect::<Result<Vec<_>, String>>()?;
            let unavailable = run
                .meetings
                .iter()
                .flat_map(|meeting| &meeting.diagnostics)
                .count();
            control::progress(&format!(
                "{} population meetings observed across {} members",
                items.len(),
                run.roster.len()
            ));
            Ok(FetchResult {
                completion: FetchCompletion::Complete,
                items,
                notes: format!(
                    "{} members; {unavailable} unavailable artifact outcome(s); population sha256 {roster_sha256}",
                    run.roster.len(),
                ),
                next_checkpoint: None,
            })
        }
    }

    bindings::export!(GraphOrgMeetings with_types_in bindings);
}
