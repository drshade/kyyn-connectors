//! Frozen, synthetic provider conversations for ADR 0037 population sources.

use std::collections::BTreeMap;

use serde::Deserialize;
use serde_json::Value;

const FIXTURE: &str = include_str!("../fixtures/graph-population-v1.json");

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Suite {
    pub fixture_version: u32,
    pub scenarios: Vec<Scenario>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Scenario {
    pub id: String,
    pub leg: Leg,
    pub proves: Vec<Proof>,
    pub scope: Scope,
    pub invocations: Vec<Invocation>,
    pub expected: Expected,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub enum Leg {
    Calendar,
    MeetingArtifacts,
    Audit,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd)]
#[serde(rename_all = "kebab-case")]
pub enum Proof {
    StableRoster,
    Throttling,
    MissingSelectedMember,
    IneligibleSelectedMember,
    PartialPopulation,
    TranscriptUnavailable,
    TranscriptNegotiation,
    AttendanceArtifact,
    AuditPending,
    CrashAfterQueryCreation,
    ExactQueryRediscovery,
    AmbiguousQueryRefusal,
    AuditTerminalOutcome,
    AuditPagination,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(tag = "kind", rename_all = "camelCase", deny_unknown_fields)]
pub enum Scope {
    AllMembers,
    SelectedMembers { users: Vec<String> },
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Invocation {
    pub checkpoint: Option<String>,
    pub exchanges: Vec<Exchange>,
    pub interrupt_after_exchange: Option<usize>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Exchange {
    pub request: Request,
    pub responses: Vec<Response>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Request {
    pub method: Method,
    pub path: String,
    #[serde(default)]
    pub headers: BTreeMap<String, String>,
    pub body: Option<Value>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "UPPERCASE")]
pub enum Method {
    Get,
    Post,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Response {
    pub status: u16,
    #[serde(default)]
    pub headers: BTreeMap<String, String>,
    pub body: Value,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Expected {
    pub outcome: Outcome,
    pub publishes_manifest: bool,
    pub item_count: usize,
    #[serde(default)]
    pub roster_user_ids: Vec<String>,
    #[serde(default)]
    pub unavailable_user_ids: Vec<String>,
    pub checkpoint: Option<String>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub enum Outcome {
    Complete,
    Pending,
    RefusedBeforeObservation,
    FailedNoPublication,
    Interrupted,
}

pub fn suite() -> Suite {
    serde_json::from_str(FIXTURE).expect("committed Graph population fixture parses")
}

pub fn scenario(id: &str) -> Scenario {
    suite()
        .scenarios
        .into_iter()
        .find(|scenario| scenario.id == id)
        .unwrap_or_else(|| panic!("unknown Graph population fixture scenario '{id}'"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    #[test]
    fn corpus_is_closed_synthetic_and_covers_every_adr_adversary() {
        let suite = suite();
        assert_eq!(suite.fixture_version, 1);
        assert_eq!(suite.scenarios.len(), 11);
        assert!(!FIXTURE.contains("synthesis"));
        assert!(!FIXTURE.contains("bee-skills"));

        let mut ids = BTreeSet::new();
        let mut proofs = BTreeSet::new();
        for scenario in &suite.scenarios {
            assert!(
                ids.insert(&scenario.id),
                "duplicate scenario {}",
                scenario.id
            );
            assert!(
                !scenario.invocations.is_empty(),
                "{} has no invocation",
                scenario.id
            );
            proofs.extend(scenario.proves.iter().copied());

            if let Scope::SelectedMembers { users } = &scenario.scope {
                assert!(
                    !users.is_empty(),
                    "{} has an empty selected scope",
                    scenario.id
                );
                let normalized = users
                    .iter()
                    .map(|user| user.to_ascii_lowercase())
                    .collect::<BTreeSet<_>>();
                assert_eq!(
                    normalized.len(),
                    users.len(),
                    "{} repeats a selected user",
                    scenario.id
                );
                assert!(
                    users.iter().all(|user| user.ends_with("@example.test")),
                    "{} contains a non-synthetic selected identity",
                    scenario.id
                );
                assert!(
                    users.iter().all(|user| user == &user.to_ascii_lowercase()),
                    "{} contains a non-normalized selected identity",
                    scenario.id
                );
            }

            for invocation in &scenario.invocations {
                assert!(!invocation.exchanges.is_empty());
                if let Some(index) = invocation.interrupt_after_exchange {
                    assert!(index > 0 && index <= invocation.exchanges.len());
                }
                for exchange in &invocation.exchanges {
                    assert!(exchange.request.path.starts_with("/v1.0/"));
                    assert!(!exchange.responses.is_empty());
                    assert!(
                        exchange
                            .responses
                            .iter()
                            .all(|response| response.status >= 100)
                    );
                }
            }

            assert_eq!(
                scenario.expected.publishes_manifest,
                matches!(
                    scenario.expected.outcome,
                    Outcome::Complete | Outcome::Pending
                ),
                "{} publication expectation contradicts outcome",
                scenario.id
            );
            if scenario.expected.outcome == Outcome::Pending {
                assert!(scenario.expected.checkpoint.is_some());
                assert_eq!(scenario.expected.item_count, 0);
            }
            if !scenario.expected.publishes_manifest {
                assert!(scenario.expected.checkpoint.is_none());
                assert_eq!(scenario.expected.item_count, 0);
            }
            assert!(is_stably_sorted(&scenario.expected.roster_user_ids));
        }

        assert_eq!(
            proofs,
            BTreeSet::from([
                Proof::StableRoster,
                Proof::Throttling,
                Proof::MissingSelectedMember,
                Proof::IneligibleSelectedMember,
                Proof::PartialPopulation,
                Proof::TranscriptUnavailable,
                Proof::TranscriptNegotiation,
                Proof::AttendanceArtifact,
                Proof::AuditPending,
                Proof::CrashAfterQueryCreation,
                Proof::ExactQueryRediscovery,
                Proof::AmbiguousQueryRefusal,
                Proof::AuditTerminalOutcome,
                Proof::AuditPagination,
            ])
        );
    }

    #[test]
    fn crash_fixture_crosses_an_invocation_boundary_after_the_remote_post() {
        let scenario = scenario("audit-crash-after-create-rediscover");
        assert_eq!(scenario.invocations.len(), 2);
        let first = &scenario.invocations[0];
        let interrupted_at = first.interrupt_after_exchange.expect("crash point");
        assert!(first.exchanges[..interrupted_at].iter().any(|exchange| {
            exchange.request.method == Method::Post
                && exchange.request.path == "/v1.0/security/auditLog/queries"
                && exchange
                    .responses
                    .last()
                    .is_some_and(|response| response.status == 201)
        }));
        assert!(scenario.invocations[1].exchanges.iter().any(|exchange| {
            exchange.request.method == Method::Get
                && exchange
                    .request
                    .path
                    .starts_with("/v1.0/security/auditLog/queries")
        }));
        assert!(!scenario.invocations[1].exchanges.iter().any(|exchange| {
            exchange.request.method == Method::Post
                && exchange.request.path == "/v1.0/security/auditLog/queries"
        }));
    }

    #[test]
    fn transcript_fixture_uses_current_accept_negotiation() {
        let scenario = scenario("meeting-artifacts-mixed-availability");
        let content = scenario
            .invocations
            .iter()
            .flat_map(|invocation| &invocation.exchanges)
            .filter(|exchange| exchange.request.path.ends_with("/content"))
            .collect::<Vec<_>>();
        assert_eq!(content.len(), 2);
        assert_eq!(
            content[0].request.headers.get("accept").map(String::as_str),
            Some("text/vtt")
        );
        assert_eq!(content[0].responses[0].status, 403);
        assert_eq!(
            content[1].request.headers.get("accept").map(String::as_str),
            Some("application/vnd.microsoft.graph.transcript+text")
        );
        assert_eq!(content[1].responses[0].status, 200);
    }

    fn is_stably_sorted(values: &[String]) -> bool {
        values.windows(2).all(|pair| pair[0] < pair[1])
    }
}
