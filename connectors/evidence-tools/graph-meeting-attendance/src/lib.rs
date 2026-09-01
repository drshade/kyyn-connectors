#[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
mod guest {
    mod bindings {
        wit_bindgen::generate!({ path: "../../../wit/evidence-tool.wit", world: "evidence-tool" });
    }
    use bindings::exports::kyyn::evidence_tool::api::{
        Body, Diagnostic, Guest, Output, ViewMember,
    };
    use graph_evidence_views::{
        EvidenceReadManyRequest, EvidenceReadManyResponse, EvidenceReadSelector,
        OccurrenceParameters,
    };
    struct Tool;
    fn fail(code: &str, message: impl Into<String>) -> Diagnostic {
        Diagnostic {
            code: code.into(),
            message: message.into(),
        }
    }
    impl Guest for Tool {
        fn invoke(parameters: String) -> Result<Output, Diagnostic> {
            let p: OccurrenceParameters = graph_evidence_views::decode(&parameters)
                .map_err(|e| fail("invalid-parameters", e))?;
            if p.items.is_empty() || p.items.len() > 128 {
                return Err(fail(
                    "invalid-parameters",
                    "items must contain 1..=128 exact keys",
                ));
            }
            let request = EvidenceReadManyRequest {
                items: p
                    .items
                    .iter()
                    .map(|item| EvidenceReadSelector {
                        item: item.clone(),
                        file: None,
                        cursor: None,
                        max_bytes: Some(262_144),
                    })
                    .collect(),
            };
            let raw = bindings::kyyn::evidence_tool::evidence::read_many(
                &graph_evidence_views::encode(&request).map_err(|e| fail("encode-request", e))?,
            )
            .map_err(|e| fail(&e.code, e.message))?;
            let response: EvidenceReadManyResponse =
                graph_evidence_views::decode(&raw).map_err(|e| fail("invalid-host-envelope", e))?;
            let mut meetings = Vec::new();
            for (wanted, item) in p.items.iter().zip(response.evidence) {
                if item.key != *wanted {
                    return Err(fail(
                        "invalid-host-envelope",
                        "meeting evidence was reordered",
                    ));
                }
                let item = graph_evidence_views::complete_evidence(item, |request| {
                    let raw = bindings::kyyn::evidence_tool::evidence::read(
                        &graph_evidence_views::encode(&request)?,
                    )
                    .map_err(|e| e.message)?;
                    graph_evidence_views::decode::<graph_evidence_views::EvidenceReadResponse>(&raw)
                        .map(|response| response.evidence)
                })
                .map_err(|e| fail("incomplete-evidence", e))?;
                let parsed = graph_evidence_views::parse_meeting(&item.key, &item.content, false)
                    .map_err(|e| fail("unsupported", e))?;
                if parsed.occurrence_id != p.occurrence_id {
                    return Err(fail(
                        "mixed-occurrences",
                        "every item must belong to occurrence_id",
                    ));
                }
                meetings.push(parsed);
            }
            let view = graph_evidence_views::attendance_view(&p.occurrence_id, &meetings);
            let subjects = view.subjects.clone();
            Ok(Output {
                body: Body::Text(
                    graph_evidence_views::encode(&view).map_err(|e| fail("encode-result", e))?,
                ),
                members: vec![ViewMember {
                    local_id: p.occurrence_id,
                    subjects,
                }],
            })
        }
    }
    bindings::export!(Tool with_types_in bindings);
}
