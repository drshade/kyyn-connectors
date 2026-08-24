//! Provider-neutral execution core for ADR 0037 Microsoft Graph population
//! sources. Shipped components supply the contained transport and evidence
//! adapters; this crate owns no ambient network or filesystem authority.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::Value;

const MAX_PAGES: usize = 500;
const MAX_MEMBERS: usize = 100_000;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PopulationConfig {
    pub scope: MemberScope,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum MemberScope {
    AllMembers,
    SelectedMembers { users: Vec<String> },
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SetupInput {
    pub scope_mode: String,
    #[serde(default)]
    pub selected_users: Vec<String>,
}

impl PopulationConfig {
    pub fn parse(text: &str) -> Result<Self, String> {
        let config: Self = ron::from_str(text).map_err(|_| {
            "population config must contain exactly one AllMembers or SelectedMembers scope"
                .to_string()
        })?;
        config.validate()?;
        Ok(config)
    }

    pub fn from_setup(input: SetupInput) -> Result<Self, String> {
        let scope = match input.scope_mode.as_str() {
            "all-members" if input.selected_users.is_empty() => MemberScope::AllMembers,
            "all-members" => {
                return Err("All members cannot also carry selected users".into());
            }
            "selected-members" => MemberScope::SelectedMembers {
                users: input.selected_users,
            },
            _ => return Err("population setup requires All members or Selected members".into()),
        };
        let config = Self { scope };
        config.validate()?;
        Ok(config)
    }

    pub fn validate(&self) -> Result<(), String> {
        let MemberScope::SelectedMembers { users } = &self.scope else {
            return Ok(());
        };
        if users.is_empty() {
            return Err("Selected members requires at least one user principal name".into());
        }
        if users.len() > MAX_MEMBERS {
            return Err(format!(
                "Selected members exceeds the {MAX_MEMBERS} member ceiling"
            ));
        }
        let mut unique = BTreeSet::new();
        for user in users {
            validate_upn(user)?;
            if user != &user.to_ascii_lowercase() {
                return Err("Selected user principal names must be lowercase".into());
            }
            if !unique.insert(user) {
                return Err("Selected user principal names must be unique".into());
            }
        }
        Ok(())
    }

    pub fn display_summary(&self) -> String {
        match &self.scope {
            MemberScope::AllMembers => "All enabled organization members".into(),
            MemberScope::SelectedMembers { users } => {
                format!("{} selected organization member(s)", users.len())
            }
        }
    }
}

fn validate_upn(value: &str) -> Result<(), String> {
    if value.is_empty()
        || value.len() > 320
        || !value.is_ascii()
        || value.chars().any(char::is_whitespace)
    {
        return Err("Selected user principal name is not syntactically valid".into());
    }
    let mut parts = value.split('@');
    let (Some(local), Some(domain), None) = (parts.next(), parts.next(), parts.next()) else {
        return Err("Selected user principal name is not syntactically valid".into());
    };
    if local.is_empty()
        || domain.is_empty()
        || !domain.contains('.')
        || domain.starts_with('.')
        || domain.ends_with('.')
        || domain.split('.').any(|label| {
            label.is_empty()
                || label.starts_with('-')
                || label.ends_with('-')
                || !label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        })
    {
        return Err("Selected user principal name is not syntactically valid".into());
    }
    Ok(())
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Method {
    Get,
    Post,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Request {
    pub method: Method,
    pub path: String,
    pub headers: BTreeMap<String, String>,
    pub body: Option<Vec<u8>>,
}

#[derive(Clone, Debug)]
pub struct Response {
    pub status: u16,
    pub headers: BTreeMap<String, String>,
    pub body: Vec<u8>,
}

pub trait Transport {
    fn send(&mut self, request: &Request) -> Result<Response, String>;
    fn sleep_ms(&mut self, milliseconds: u64);
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RosterMember {
    pub id: String,
    pub user_principal_name: String,
    pub display_name: Option<String>,
    pub mail: Option<String>,
    pub observation: MemberObservation,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum MemberObservation {
    Observed,
    MailboxUnavailable { provider_code: Option<String> },
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PopulationEvent {
    pub id: String,
    pub member_id: String,
    pub member_user_principal_name: String,
    pub provider_event_id: String,
    pub event: Value,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CalendarRun {
    pub roster: Vec<RosterMember>,
    pub events: Vec<PopulationEvent>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct GraphUser {
    id: String,
    user_principal_name: String,
    display_name: Option<String>,
    mail: Option<String>,
    account_enabled: Option<bool>,
    user_type: Option<String>,
}

#[derive(Deserialize)]
struct Collection<T> {
    value: Vec<T>,
    #[serde(rename = "@odata.nextLink")]
    next_link: Option<String>,
}

pub fn fetch_calendar<T: Transport>(
    transport: &mut T,
    config: &PopulationConfig,
    start: &str,
    until: &str,
) -> Result<CalendarRun, String> {
    config.validate()?;
    let mut roster = resolve_roster(transport, &config.scope)?;
    let mut events = Vec::new();
    for member in &mut roster {
        let path = format!(
            "/v1.0/users/{}/calendarView?startDateTime={}&endDateTime={}&$top=500",
            encode_segment(&member.id),
            encode_query_value(start),
            encode_query_value(until)
        );
        match get_json::<Collection<Value>, _>(transport, &path) {
            Ok(page) => {
                let mut pages = vec![page];
                while let Some(next) = pages.last().and_then(|page| page.next_link.as_deref()) {
                    let next = graph_path(next)?;
                    pages.push(get_json(transport, &next)?);
                    if pages.len() > MAX_PAGES {
                        return Err("Graph calendar paging exceeded its ceiling".into());
                    }
                }
                for event in pages.into_iter().flat_map(|page| page.value) {
                    let provider_event_id = event
                        .get("id")
                        .and_then(Value::as_str)
                        .filter(|id| !id.is_empty())
                        .ok_or_else(|| "Graph calendar event has no identity".to_string())?;
                    let id = format!("{}:{}", member.id, provider_event_id);
                    events.push(PopulationEvent {
                        id,
                        member_id: member.id.clone(),
                        member_user_principal_name: member.user_principal_name.clone(),
                        provider_event_id: provider_event_id.into(),
                        event,
                    });
                }
            }
            Err(error) if error.starts_with("mailbox-unavailable:") => {
                member.observation = MemberObservation::MailboxUnavailable {
                    provider_code: error
                        .strip_prefix("mailbox-unavailable:")
                        .and_then(|code| (!code.is_empty()).then(|| code.to_string())),
                };
            }
            Err(error) => return Err(error),
        }
    }
    roster.sort_by(|left, right| {
        left.user_principal_name
            .cmp(&right.user_principal_name)
            .then_with(|| left.id.cmp(&right.id))
    });
    events.sort_by(|left, right| left.id.cmp(&right.id));
    events.dedup_by(|left, right| left.id == right.id);
    Ok(CalendarRun { roster, events })
}

fn resolve_roster<T: Transport>(
    transport: &mut T,
    scope: &MemberScope,
) -> Result<Vec<RosterMember>, String> {
    let users = match scope {
        MemberScope::AllMembers => {
            let first = "/v1.0/users?$filter=accountEnabled%20eq%20true%20and%20userType%20eq%20'Member'&$select=id,displayName,userPrincipalName,mail,accountEnabled,userType&$top=999";
            let mut page: Collection<GraphUser> = get_json(transport, first)?;
            let mut users = page.value;
            let mut pages = 1;
            while let Some(next) = page.next_link {
                page = get_json(transport, &graph_path(&next)?)?;
                users.extend(page.value);
                pages += 1;
                if pages > MAX_PAGES {
                    return Err("Graph directory paging exceeded its ceiling".into());
                }
            }
            users.into_iter().filter(eligible).collect::<Vec<_>>()
        }
        MemberScope::SelectedMembers { users } => {
            let mut resolved = Vec::with_capacity(users.len());
            for upn in users {
                let path = format!(
                    "/v1.0/users/{}?$select=id,displayName,userPrincipalName,mail,accountEnabled,userType",
                    encode_segment(upn)
                );
                let user: GraphUser = match get_json(transport, &path) {
                    Ok(user) => user,
                    Err(error) if error.starts_with("not-found:") => {
                        return Err(format!("selected member '{upn}' was not found"));
                    }
                    Err(error) => return Err(error),
                };
                if !eligible(&user) {
                    return Err(format!(
                        "selected member '{upn}' is not an enabled organization member"
                    ));
                }
                if user.user_principal_name.to_ascii_lowercase() != *upn {
                    return Err(format!(
                        "selected member '{upn}' resolved to another identity"
                    ));
                }
                resolved.push(user);
            }
            resolved
        }
    };
    if users.len() > MAX_MEMBERS {
        return Err(format!(
            "Graph population exceeds the {MAX_MEMBERS} member ceiling"
        ));
    }
    let mut roster = users
        .into_iter()
        .map(|user| RosterMember {
            id: user.id,
            user_principal_name: user.user_principal_name.to_ascii_lowercase(),
            display_name: user.display_name,
            mail: user.mail.map(|mail| mail.to_ascii_lowercase()),
            observation: MemberObservation::Observed,
        })
        .collect::<Vec<_>>();
    roster.sort_by(|left, right| {
        left.user_principal_name
            .cmp(&right.user_principal_name)
            .then_with(|| left.id.cmp(&right.id))
    });
    let ids = roster
        .iter()
        .map(|member| &member.id)
        .collect::<BTreeSet<_>>();
    let upns = roster
        .iter()
        .map(|member| &member.user_principal_name)
        .collect::<BTreeSet<_>>();
    if ids.len() != roster.len() || upns.len() != roster.len() {
        return Err("Graph population contains duplicate member identities".into());
    }
    Ok(roster)
}

fn eligible(user: &GraphUser) -> bool {
    user.account_enabled == Some(true) && user.user_type.as_deref() == Some("Member")
}

fn get_json<D: for<'de> Deserialize<'de>, T: Transport>(
    transport: &mut T,
    path: &str,
) -> Result<D, String> {
    let response = request_with_retry(
        transport,
        &Request {
            method: Method::Get,
            path: path.into(),
            headers: BTreeMap::from([("accept".into(), "application/json".into())]),
            body: None,
        },
    )?;
    if response.status == 404 {
        let code = provider_error_code(&response.body).unwrap_or_default();
        if path.contains("/calendarView") {
            return Err(format!("mailbox-unavailable:{code}"));
        }
        return Err(format!("not-found:{code}"));
    }
    if !(200..300).contains(&response.status) {
        return Err(format!(
            "Graph observation failed (HTTP {})",
            response.status
        ));
    }
    serde_json::from_slice(&response.body).map_err(|_| "Graph returned invalid JSON".into())
}

fn request_with_retry<T: Transport>(
    transport: &mut T,
    request: &Request,
) -> Result<Response, String> {
    for attempt in 1..=5u64 {
        let response = transport.send(request)?;
        if response.status == 429 && attempt < 5 {
            let seconds = response
                .headers
                .get("retry-after")
                .and_then(|value| value.parse::<u64>().ok())
                .unwrap_or(5)
                .min(60);
            transport.sleep_ms(seconds * 1_000);
            continue;
        }
        if response.status >= 500 && attempt < 5 {
            transport.sleep_ms((1u64 << attempt).min(30) * 1_000);
            continue;
        }
        return Ok(response);
    }
    Err("Graph observation exhausted retries".into())
}

fn provider_error_code(body: &[u8]) -> Option<String> {
    let value = serde_json::from_slice::<Value>(body).ok()?;
    let code = value.get("error")?.get("code")?.as_str().filter(|code| {
        !code.is_empty()
            && code.len() <= 128
            && code
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    })?;
    Some(code.to_string())
}

fn graph_path(url: &str) -> Result<String, String> {
    url.strip_prefix("https://graph.microsoft.com")
        .filter(|path| path.starts_with("/v1.0/"))
        .map(str::to_string)
        .ok_or_else(|| "Graph continuation escaped the reviewed origin or API family".into())
}

fn encode_segment(value: &str) -> String {
    percent_encode(value, false)
}

fn encode_query_value(value: &str) -> String {
    percent_encode(value, true)
}

fn percent_encode(value: &str, allow_colon: bool) -> String {
    let mut encoded = String::with_capacity(value.len());
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric()
            || matches!(byte, b'-' | b'_' | b'.' | b'~')
            || (allow_colon && byte == b':')
        {
            encoded.push(byte as char);
        } else {
            encoded.push_str(&format!("%{byte:02X}"));
        }
    }
    encoded
}

#[cfg(test)]
mod tests {
    use super::*;
    use graph_population_fixture::{Method as FixtureMethod, Scenario};

    struct FixtureTransport {
        exchanges: std::collections::VecDeque<graph_population_fixture::Exchange>,
        current_responses: std::collections::VecDeque<graph_population_fixture::Response>,
        sleeps: Vec<u64>,
    }

    impl FixtureTransport {
        fn new(scenario: Scenario) -> Self {
            assert_eq!(scenario.invocations.len(), 1);
            Self {
                exchanges: scenario.invocations[0].exchanges.clone().into(),
                current_responses: Default::default(),
                sleeps: Vec::new(),
            }
        }

        fn exhausted(&self) -> bool {
            self.exchanges.is_empty() && self.current_responses.is_empty()
        }
    }

    impl Transport for FixtureTransport {
        fn send(&mut self, request: &Request) -> Result<Response, String> {
            if self.current_responses.is_empty() {
                let exchange = self.exchanges.pop_front().expect("unexpected request");
                assert_eq!(exchange.request.method, FixtureMethod::Get);
                assert_eq!(exchange.request.path, request.path);
                self.current_responses = exchange.responses.into();
            }
            let response = self
                .current_responses
                .pop_front()
                .expect("fixture response");
            Ok(Response {
                status: response.status,
                headers: response.headers,
                body: match response.body {
                    Value::String(text) => text.into_bytes(),
                    value => serde_json::to_vec(&value).unwrap(),
                },
            })
        }

        fn sleep_ms(&mut self, milliseconds: u64) {
            self.sleeps.push(milliseconds);
        }
    }

    #[test]
    fn all_members_fixture_is_sorted_complete_and_keeps_unavailable_mailbox() {
        let fixture = graph_population_fixture::scenario("all-members-calendar-complete");
        let expected = fixture.expected.clone();
        let mut transport = FixtureTransport::new(fixture);
        let run = fetch_calendar(
            &mut transport,
            &PopulationConfig {
                scope: MemberScope::AllMembers,
            },
            "2026-08-01T00:00:00Z",
            "2026-08-02T00:00:00Z",
        )
        .unwrap();
        assert!(transport.exhausted());
        assert_eq!(transport.sleeps, [2_000]);
        assert_eq!(run.events.len(), expected.item_count);
        assert_eq!(
            run.roster
                .iter()
                .map(|member| &member.id)
                .collect::<Vec<_>>(),
            expected.roster_user_ids.iter().collect::<Vec<_>>()
        );
        assert!(matches!(
            run.roster[1].observation,
            MemberObservation::MailboxUnavailable { .. }
        ));
    }

    #[test]
    fn selected_member_refusals_finish_before_any_calendar_observation() {
        for id in [
            "selected-member-missing-refusal",
            "selected-member-disabled-refusal",
            "selected-member-guest-refusal",
        ] {
            let fixture = graph_population_fixture::scenario(id);
            let scope = match &fixture.scope {
                graph_population_fixture::Scope::SelectedMembers { users } => {
                    MemberScope::SelectedMembers {
                        users: users.clone(),
                    }
                }
                _ => panic!("selected fixture"),
            };
            let mut transport = FixtureTransport::new(fixture);
            let error = fetch_calendar(
                &mut transport,
                &PopulationConfig { scope },
                "2026-08-01T00:00:00Z",
                "2026-08-02T00:00:00Z",
            )
            .unwrap_err();
            assert!(error.contains("selected member"));
            assert!(transport.exhausted());
        }
    }

    #[test]
    fn later_member_failure_never_returns_the_first_members_partial_run() {
        let fixture =
            graph_population_fixture::scenario("selected-calendar-partial-population-refusal");
        let users = match &fixture.scope {
            graph_population_fixture::Scope::SelectedMembers { users } => users.clone(),
            _ => panic!("selected fixture"),
        };
        let mut transport = FixtureTransport::new(fixture);
        let error = fetch_calendar(
            &mut transport,
            &PopulationConfig {
                scope: MemberScope::SelectedMembers { users },
            },
            "2026-08-01T00:00:00Z",
            "2026-08-02T00:00:00Z",
        )
        .unwrap_err();
        assert_eq!(error, "Graph observation failed (HTTP 503)");
        assert!(transport.exhausted());
        assert_eq!(transport.sleeps.len(), 4);
    }

    #[test]
    fn configuration_is_one_closed_normalized_sum_type() {
        let all = PopulationConfig::from_setup(SetupInput {
            scope_mode: "all-members".into(),
            selected_users: vec![],
        })
        .unwrap();
        assert_eq!(all.scope, MemberScope::AllMembers);
        for users in [
            vec![],
            vec!["UPPER@example.test".into()],
            vec!["same@example.test".into(), "same@example.test".into()],
            vec!["not-an-upn".into()],
        ] {
            assert!(
                PopulationConfig::from_setup(SetupInput {
                    scope_mode: "selected-members".into(),
                    selected_users: users,
                })
                .is_err()
            );
        }
    }
}
