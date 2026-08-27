//! Frozen synthetic provider conversations for the amended ADR 0037 source.

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
    pub proves: Vec<Proof>,
    pub exchanges: Vec<Exchange>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd)]
#[serde(rename_all = "kebab-case")]
pub enum Proof {
    StableRoster,
    BoundedBatch,
    ExactCalendarSelection,
    OrganizerRouting,
    OccurrenceDeduplication,
    OccurrenceArtifactJoin,
    PermissionOutcome,
    EmptyAttendanceObserved,
    ClosedArtifactOutcome,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Exchange {
    pub request: Request,
    pub response: Response,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Request {
    pub method: Method,
    pub path: String,
    #[serde(default)]
    pub headers: BTreeMap<String, String>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "UPPERCASE")]
pub enum Method {
    Get,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Response {
    pub status: u16,
    pub body: Value,
}

pub fn suite() -> Suite {
    serde_json::from_str(FIXTURE).expect("committed joined-meeting fixture parses")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    #[test]
    fn corpus_is_closed_synthetic_and_covers_the_amended_boundary() {
        let suite = suite();
        assert_eq!(suite.fixture_version, 3);
        assert_eq!(suite.scenarios.len(), 5);
        assert!(!FIXTURE.contains("bee-skills"));
        assert!(!FIXTURE.contains("auditLog"));
        assert!(!FIXTURE.contains("/me/"));

        let mut ids = BTreeSet::new();
        let mut proofs = BTreeSet::new();
        for scenario in &suite.scenarios {
            assert!(ids.insert(&scenario.id));
            assert!(!scenario.exchanges.is_empty());
            proofs.extend(scenario.proves.iter().copied());
            for exchange in &scenario.exchanges {
                assert!(exchange.request.path.starts_with("/v1.0/"));
                assert_eq!(exchange.request.method, Method::Get);
                assert!(exchange.response.status >= 100);
            }
        }

        assert_eq!(
            proofs,
            BTreeSet::from([
                Proof::StableRoster,
                Proof::BoundedBatch,
                Proof::ExactCalendarSelection,
                Proof::OrganizerRouting,
                Proof::OccurrenceDeduplication,
                Proof::OccurrenceArtifactJoin,
                Proof::PermissionOutcome,
                Proof::EmptyAttendanceObserved,
                Proof::ClosedArtifactOutcome,
            ])
        );
    }

    #[test]
    fn fixture_never_routes_meeting_apis_through_the_attendee() {
        let scenario = suite()
            .scenarios
            .into_iter()
            .find(|scenario| scenario.id == "organizer-routed-artifacts")
            .unwrap();
        assert!(scenario.exchanges.iter().any(|exchange| {
            exchange
                .request
                .path
                .contains("/users/user-organizer/onlineMeetings")
        }));
        assert!(!scenario.exchanges.iter().any(|exchange| {
            exchange
                .request
                .path
                .contains("/users/user-attendee/onlineMeetings")
        }));
    }
}
