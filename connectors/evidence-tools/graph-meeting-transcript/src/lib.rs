#[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
mod guest {
    mod bindings {
        wit_bindgen::generate!({ path: "../../../wit/evidence-tool.wit", world: "evidence-tool" });
    }
    use bindings::exports::kyyn::evidence_tool::api::{
        Body, Diagnostic, Guest, Output, ViewMember,
    };
    use graph_evidence_views::{EvidenceReadRequest, EvidenceReadResponse, TranscriptParameters};
    struct Tool;
    fn fail(code: &str, message: impl Into<String>) -> Diagnostic {
        Diagnostic {
            code: code.into(),
            message: message.into(),
        }
    }
    impl Guest for Tool {
        fn invoke(parameters: String) -> Result<Output, Diagnostic> {
            let p: TranscriptParameters = graph_evidence_views::decode(&parameters)
                .map_err(|e| fail("invalid-parameters", e))?;
            let max = p.max_bytes.unwrap_or(32_768).clamp(1, 131_072);
            let request = EvidenceReadRequest {
                item: p.item.clone(),
                file: None,
                cursor: None,
                max_bytes: Some(262_144),
            };
            let raw = bindings::kyyn::evidence_tool::evidence::read(
                &graph_evidence_views::encode(&request).map_err(|e| fail("encode-request", e))?,
            )
            .map_err(|e| fail(&e.code, e.message))?;
            let response: EvidenceReadResponse =
                graph_evidence_views::decode(&raw).map_err(|e| fail("invalid-host-envelope", e))?;
            if response.evidence.key != p.item {
                return Err(fail(
                    "invalid-host-envelope",
                    "meeting evidence key differs from request",
                ));
            }
            let evidence = graph_evidence_views::complete_evidence(response.evidence, |request| {
                let raw = bindings::kyyn::evidence_tool::evidence::read(
                    &graph_evidence_views::encode(&request)?,
                )
                .map_err(|e| e.message)?;
                graph_evidence_views::decode::<EvidenceReadResponse>(&raw)
                    .map(|response| response.evidence)
            })
            .map_err(|e| fail("incomplete-evidence", e))?;
            let meeting =
                graph_evidence_views::parse_meeting(&evidence.key, &evidence.content, true)
                    .map_err(|e| fail("unsupported", e))?;
            let view = graph_evidence_views::transcript_view(&meeting, p.cursor.unwrap_or(0), max)
                .map_err(|e| fail("transcript-unavailable", e))?;
            let local_id = format!("{}:{}", view.occurrence_id, view.byte_start);
            Ok(Output {
                body: Body::Text(
                    graph_evidence_views::encode(&view).map_err(|e| fail("encode-result", e))?,
                ),
                members: vec![ViewMember {
                    local_id,
                    subjects: vec![evidence.key],
                }],
            })
        }
    }
    bindings::export!(Tool with_types_in bindings);
}
