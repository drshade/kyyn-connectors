#[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
mod guest {
    mod bindings {
        wit_bindgen::generate!({ path: "../../../wit/evidence-tool.wit", world: "evidence-tool" });
    }
    use bindings::exports::kyyn::evidence_tool::api::{
        Body, Diagnostic, Guest, Output, ViewMember,
    };
    use graph_evidence_views::{
        EvidenceReadManyRequest, EvidenceReadManyResponse, EvidenceReadSelector, ItemsParameters,
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
            let p: ItemsParameters = graph_evidence_views::decode(&parameters)
                .map_err(|error| fail("invalid-parameters", error))?;
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
                &graph_evidence_views::encode(&request)
                    .map_err(|error| fail("encode-request", error))?,
            )
            .map_err(|error| fail(&error.code, error.message))?;
            let response: EvidenceReadManyResponse = graph_evidence_views::decode(&raw)
                .map_err(|error| fail("invalid-host-envelope", error))?;
            if response.evidence.len() != p.items.len() {
                return Err(fail(
                    "invalid-host-envelope",
                    "plural response length differs from request",
                ));
            }
            let mut views = Vec::with_capacity(p.items.len());
            for (wanted, item) in p.items.iter().zip(response.evidence) {
                if item.key != *wanted {
                    return Err(fail(
                        "invalid-host-envelope",
                        "member observation evidence was reordered",
                    ));
                }
                let item = graph_evidence_views::complete_evidence(item, |request| {
                    let raw = bindings::kyyn::evidence_tool::evidence::read(
                        &graph_evidence_views::encode(&request)?,
                    )
                    .map_err(|error| error.message)?;
                    graph_evidence_views::decode::<graph_evidence_views::EvidenceReadResponse>(&raw)
                        .map(|response| response.evidence)
                })
                .map_err(|error| fail("incomplete-evidence", error))?;
                views.push(
                    graph_evidence_views::parse_member_observation(&item.key, &item.content)
                        .map_err(|error| fail("unsupported", error))?,
                );
            }
            let members = views
                .iter()
                .map(|view| ViewMember {
                    local_id: view.observation_id.clone(),
                    subjects: vec![view.source_item.clone()],
                })
                .collect();
            Ok(Output {
                body: Body::Text(
                    graph_evidence_views::encode(&views)
                        .map_err(|error| fail("encode-result", error))?,
                ),
                members,
            })
        }
    }

    bindings::export!(Tool with_types_in bindings);
}
