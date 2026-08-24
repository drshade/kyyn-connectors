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

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MeetingRun {
    pub roster: Vec<RosterMember>,
    pub meetings: Vec<PopulationMeeting>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PopulationMeeting {
    pub id: String,
    pub member_id: String,
    pub member_user_principal_name: String,
    pub provider_event_id: String,
    pub calendar_event: Value,
    pub online_meeting: Option<Value>,
    pub transcripts: Vec<TranscriptArtifact>,
    pub attendance: Vec<AttendanceArtifact>,
    pub diagnostics: Vec<ArtifactDiagnostic>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TranscriptArtifact {
    pub id: String,
    pub created_date_time: Option<String>,
    pub media_type: String,
    pub content: String,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AttendanceArtifact {
    pub report_id: String,
    pub records: Vec<Value>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ArtifactDiagnostic {
    pub artifact: String,
    pub outcome: String,
    pub provider_code: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AuditRun {
    pub completion: AuditCompletion,
    pub query: Value,
    pub records: Vec<AuditRecord>,
    pub diagnostic: Option<AuditDiagnostic>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum AuditCompletion {
    Pending {
        checkpoint: String,
        retry_after_seconds: Option<u32>,
    },
    Complete,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AuditRecord {
    pub id: String,
    pub record: Value,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AuditDiagnostic {
    pub outcome: String,
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

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct AuditQuery {
    id: String,
    #[serde(default)]
    display_name: Option<String>,
    status: String,
    #[serde(default)]
    filter_start_date_time: Option<String>,
    #[serde(default)]
    filter_end_date_time: Option<String>,
    #[serde(default)]
    record_type_filters: Vec<String>,
    #[serde(default)]
    operation_filters: Vec<String>,
    #[serde(default)]
    user_principal_name_filters: Vec<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct AuditQueryRequest<'a> {
    display_name: &'a str,
    filter_start_date_time: &'a str,
    filter_end_date_time: &'a str,
    record_type_filters: [&'static str; 1],
    operation_filters: [&'static str; 2],
    #[serde(skip_serializing_if = "Vec::is_empty")]
    user_principal_name_filters: Vec<String>,
}

#[derive(Clone, Copy)]
enum MissingOutcome {
    Unavailable,
    NotFound,
}

enum ObservationError {
    Unavailable(Option<String>),
    NotFound(Option<String>),
    Failed(String),
}

impl ObservationError {
    fn into_failure(self) -> String {
        match self {
            Self::Unavailable(code) => format!(
                "Graph resource is unavailable{}",
                code.map(|code| format!(" ({code})")).unwrap_or_default()
            ),
            Self::NotFound(code) => format!(
                "Graph resource was not found{}",
                code.map(|code| format!(" ({code})")).unwrap_or_default()
            ),
            Self::Failed(error) => error,
        }
    }
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
        match get_collection(
            transport,
            &path,
            "Graph calendar paging",
            MissingOutcome::Unavailable,
        ) {
            Ok(observed) => {
                for event in observed {
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
            Err(ObservationError::Unavailable(provider_code)) => {
                member.observation = MemberObservation::MailboxUnavailable { provider_code };
            }
            Err(error) => return Err(error.into_failure()),
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

pub fn fetch_meetings<T: Transport>(
    transport: &mut T,
    config: &PopulationConfig,
    start: &str,
    until: &str,
) -> Result<MeetingRun, String> {
    config.validate()?;
    let mut roster = resolve_roster(transport, &config.scope)?;
    let mut meetings = Vec::new();
    for member in &mut roster {
        let path = format!(
            "/v1.0/users/{}/calendarView?startDateTime={}&endDateTime={}&$top=500",
            encode_segment(&member.id),
            encode_query_value(start),
            encode_query_value(until)
        );
        let events = match get_collection(
            transport,
            &path,
            "Graph meeting calendar paging",
            MissingOutcome::Unavailable,
        ) {
            Ok(events) => events,
            Err(ObservationError::Unavailable(provider_code)) => {
                member.observation = MemberObservation::MailboxUnavailable { provider_code };
                continue;
            }
            Err(error) => return Err(error.into_failure()),
        };
        for event in events {
            let Some(join_url) = event
                .get("onlineMeeting")
                .and_then(|meeting| meeting.get("joinUrl"))
                .and_then(Value::as_str)
                .filter(|url| !url.is_empty())
            else {
                continue;
            };
            let provider_event_id = event
                .get("id")
                .and_then(Value::as_str)
                .filter(|id| !id.is_empty())
                .ok_or_else(|| "Graph meeting event has no identity".to_string())?;
            let id = format!("{}:{}", member.id, provider_event_id);
            let lookup = format!(
                "/v1.0/users/{}/onlineMeetings?$filter=JoinWebUrl%20eq%20'{}'",
                encode_segment(&member.id),
                encode_strict_query_value(join_url)
            );
            let resolved = get_collection(
                transport,
                &lookup,
                "Graph meeting lookup paging",
                MissingOutcome::NotFound,
            )
            .map_err(ObservationError::into_failure)?;
            if resolved.len() > 1 {
                return Err("Graph meeting lookup returned an ambiguous identity".into());
            }
            let Some(online_meeting) = resolved.into_iter().next() else {
                meetings.push(PopulationMeeting {
                    id,
                    member_id: member.id.clone(),
                    member_user_principal_name: member.user_principal_name.clone(),
                    provider_event_id: provider_event_id.into(),
                    calendar_event: event,
                    online_meeting: None,
                    transcripts: Vec::new(),
                    attendance: Vec::new(),
                    diagnostics: vec![unavailable("meeting-metadata", None)],
                });
                continue;
            };
            let meeting_id = online_meeting
                .get("id")
                .and_then(Value::as_str)
                .filter(|id| !id.is_empty())
                .ok_or_else(|| "Graph online meeting has no identity".to_string())?;
            let (transcripts, transcript_diagnostic) =
                fetch_transcripts(transport, &member.id, meeting_id)?;
            let (attendance, attendance_diagnostic) =
                fetch_attendance(transport, &member.id, meeting_id)?;
            let mut diagnostics = Vec::new();
            if let Some(diagnostic) = transcript_diagnostic {
                diagnostics.push(diagnostic);
            }
            if let Some(diagnostic) = attendance_diagnostic {
                diagnostics.push(diagnostic);
            }
            meetings.push(PopulationMeeting {
                id,
                member_id: member.id.clone(),
                member_user_principal_name: member.user_principal_name.clone(),
                provider_event_id: provider_event_id.into(),
                calendar_event: event,
                online_meeting: Some(online_meeting),
                transcripts,
                attendance,
                diagnostics,
            });
        }
    }
    roster.sort_by(|left, right| {
        left.user_principal_name
            .cmp(&right.user_principal_name)
            .then_with(|| left.id.cmp(&right.id))
    });
    meetings.sort_by(|left, right| left.id.cmp(&right.id));
    meetings.dedup_by(|left, right| left.id == right.id);
    Ok(MeetingRun { roster, meetings })
}

fn fetch_transcripts<T: Transport>(
    transport: &mut T,
    user_id: &str,
    meeting_id: &str,
) -> Result<(Vec<TranscriptArtifact>, Option<ArtifactDiagnostic>), String> {
    let path = format!(
        "/v1.0/users/{}/onlineMeetings/{}/transcripts",
        encode_segment(user_id),
        encode_segment(meeting_id)
    );
    let metadata = match get_collection(
        transport,
        &path,
        "Graph transcript paging",
        MissingOutcome::Unavailable,
    ) {
        Ok(metadata) => metadata,
        Err(ObservationError::Unavailable(code)) => {
            return Ok((Vec::new(), Some(unavailable("transcript", code))));
        }
        Err(error) => return Err(error.into_failure()),
    };
    if metadata.is_empty() {
        return Ok((Vec::new(), Some(unavailable("transcript", None))));
    }
    let mut artifacts = Vec::with_capacity(metadata.len());
    for transcript in metadata {
        let transcript_id = transcript
            .get("id")
            .and_then(Value::as_str)
            .filter(|id| !id.is_empty())
            .ok_or_else(|| "Graph transcript has no identity".to_string())?;
        let content_path = format!(
            "/v1.0/users/{}/onlineMeetings/{}/transcripts/{}/content",
            encode_segment(user_id),
            encode_segment(meeting_id),
            encode_segment(transcript_id)
        );
        let first = get_content(transport, &content_path, "text/vtt")?;
        let response = if first.status == 403
            && provider_inner_error_code(&first.body).as_deref()
                == Some("SpeakerAttributionNotAllowed")
        {
            get_content(
                transport,
                &content_path,
                "application/vnd.microsoft.graph.transcript+text",
            )?
        } else {
            first
        };
        if response.status == 403 || response.status == 404 {
            return Ok((
                artifacts,
                Some(unavailable(
                    "transcript",
                    provider_inner_error_code(&response.body)
                        .or_else(|| provider_error_code(&response.body)),
                )),
            ));
        }
        if !(200..300).contains(&response.status) {
            return Err(format!(
                "Graph transcript observation failed (HTTP {})",
                response.status
            ));
        }
        let content = String::from_utf8(response.body)
            .map_err(|_| "Graph transcript content was not UTF-8".to_string())?;
        artifacts.push(TranscriptArtifact {
            id: transcript_id.into(),
            created_date_time: transcript
                .get("createdDateTime")
                .and_then(Value::as_str)
                .map(str::to_string),
            media_type: response
                .headers
                .get("content-type")
                .cloned()
                .unwrap_or_else(|| "text/vtt".into()),
            content,
        });
    }
    Ok((artifacts, None))
}

fn fetch_attendance<T: Transport>(
    transport: &mut T,
    user_id: &str,
    meeting_id: &str,
) -> Result<(Vec<AttendanceArtifact>, Option<ArtifactDiagnostic>), String> {
    let path = format!(
        "/v1.0/users/{}/onlineMeetings/{}/attendanceReports",
        encode_segment(user_id),
        encode_segment(meeting_id)
    );
    let reports = match get_collection(
        transport,
        &path,
        "Graph attendance paging",
        MissingOutcome::Unavailable,
    ) {
        Ok(reports) => reports,
        Err(ObservationError::Unavailable(code)) => {
            return Ok((Vec::new(), Some(unavailable("attendance", code))));
        }
        Err(error) => return Err(error.into_failure()),
    };
    if reports.is_empty() {
        return Ok((Vec::new(), Some(unavailable("attendance", None))));
    }
    let mut artifacts = Vec::with_capacity(reports.len());
    for report in reports {
        let report_id = report
            .get("id")
            .and_then(Value::as_str)
            .filter(|id| !id.is_empty())
            .ok_or_else(|| "Graph attendance report has no identity".to_string())?;
        let records_path = format!(
            "/v1.0/users/{}/onlineMeetings/{}/attendanceReports/{}/attendanceRecords",
            encode_segment(user_id),
            encode_segment(meeting_id),
            encode_segment(report_id)
        );
        let records = match get_collection(
            transport,
            &records_path,
            "Graph attendance-record paging",
            MissingOutcome::Unavailable,
        ) {
            Ok(records) => records,
            Err(ObservationError::Unavailable(code)) => {
                return Ok((artifacts, Some(unavailable("attendance", code))));
            }
            Err(error) => return Err(error.into_failure()),
        };
        artifacts.push(AttendanceArtifact {
            report_id: report_id.into(),
            records,
        });
    }
    Ok((artifacts, None))
}

fn unavailable(artifact: &str, provider_code: Option<String>) -> ArtifactDiagnostic {
    ArtifactDiagnostic {
        artifact: artifact.into(),
        outcome: "unavailable".into(),
        provider_code,
    }
}

pub fn resolve_population<T: Transport>(
    transport: &mut T,
    config: &PopulationConfig,
) -> Result<Vec<RosterMember>, String> {
    config.validate()?;
    resolve_roster(transport, &config.scope)
}

pub fn fetch_audit<T: Transport>(
    transport: &mut T,
    config: &PopulationConfig,
    start: &str,
    until: &str,
    display_name: &str,
    checkpoint: Option<&str>,
) -> Result<AuditRun, String> {
    config.validate()?;
    validate_audit_display_name(display_name)?;
    let selected_users = match &config.scope {
        MemberScope::AllMembers => Vec::new(),
        MemberScope::SelectedMembers { users } => users.clone(),
    };
    let query = if let Some(checkpoint) = checkpoint {
        let query_id = parse_audit_checkpoint(checkpoint)?;
        get_audit_query(transport, query_id)?
    } else {
        let values = get_collection(
            transport,
            "/v1.0/security/auditLog/queries",
            "Graph audit-query paging",
            MissingOutcome::NotFound,
        )
        .map_err(ObservationError::into_failure)?;
        let mut exact = values
            .into_iter()
            .map(|value| {
                serde_json::from_value::<AuditQuery>(value)
                    .map_err(|_| "Graph returned an invalid audit query".to_string())
            })
            .collect::<Result<Vec<_>, _>>()?
            .into_iter()
            .filter(|query| {
                audit_query_matches(query, display_name, start, until, selected_users.as_slice())
            })
            .collect::<Vec<_>>();
        if exact.len() > 1 {
            return Err("Graph returned multiple indistinguishable audit queries".into());
        }
        if let Some(query) = exact.pop() {
            get_audit_query(transport, &query.id)?
        } else {
            create_audit_query(transport, display_name, start, until, selected_users)?
        }
    };
    finish_audit_query(transport, query)
}

fn validate_audit_display_name(value: &str) -> Result<(), String> {
    if value.is_empty()
        || value.len() > 128
        || !value.is_ascii()
        || value
            .bytes()
            .any(|byte| !(byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_')))
    {
        return Err("audit query display identity is invalid".into());
    }
    Ok(())
}

fn parse_audit_checkpoint(checkpoint: &str) -> Result<&str, String> {
    let query_id = checkpoint
        .strip_prefix("audit:v1:")
        .filter(|id| {
            !id.is_empty()
                && id.len() <= 256
                && id
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
        })
        .ok_or_else(|| "audit checkpoint is invalid".to_string())?;
    Ok(query_id)
}

fn audit_query_matches(
    query: &AuditQuery,
    display_name: &str,
    start: &str,
    until: &str,
    selected_users: &[String],
) -> bool {
    query.display_name.as_deref() == Some(display_name)
        && query.filter_start_date_time.as_deref() == Some(start)
        && query.filter_end_date_time.as_deref() == Some(until)
        && query.record_type_filters == ["microsoftTeams"]
        && query.operation_filters == ["MeetingDetail", "MeetingParticipantDetail"]
        && query.user_principal_name_filters == selected_users
}

fn get_audit_query<T: Transport>(transport: &mut T, query_id: &str) -> Result<AuditQuery, String> {
    let path = format!(
        "/v1.0/security/auditLog/queries/{}",
        encode_segment(query_id)
    );
    get_json(transport, &path, MissingOutcome::NotFound).map_err(ObservationError::into_failure)
}

fn create_audit_query<T: Transport>(
    transport: &mut T,
    display_name: &str,
    start: &str,
    until: &str,
    selected_users: Vec<String>,
) -> Result<AuditQuery, String> {
    let body = serde_json::to_vec(&AuditQueryRequest {
        display_name,
        filter_start_date_time: start,
        filter_end_date_time: until,
        record_type_filters: ["microsoftTeams"],
        operation_filters: ["MeetingDetail", "MeetingParticipantDetail"],
        user_principal_name_filters: selected_users,
    })
    .map_err(|_| "could not encode the audit query".to_string())?;
    // Do not retry a remote query creation: a lost response may still have
    // created it, and the next invocation must rediscover the exact query.
    let response = transport.send(&Request {
        method: Method::Post,
        path: "/v1.0/security/auditLog/queries".into(),
        headers: BTreeMap::from([
            ("accept".into(), "application/json".into()),
            ("content-type".into(), "application/json".into()),
        ]),
        body: Some(body),
    })?;
    if response.status != 201 {
        return Err(format!(
            "Graph audit query creation failed (HTTP {})",
            response.status
        ));
    }
    serde_json::from_slice(&response.body)
        .map_err(|_| "Graph returned an invalid created audit query".into())
}

fn finish_audit_query<T: Transport>(
    transport: &mut T,
    query: AuditQuery,
) -> Result<AuditRun, String> {
    let query_value = serde_json::to_value(&query)
        .map_err(|_| "could not encode audit query evidence".to_string())?;
    match query.status.as_str() {
        "notStarted" | "running" => Ok(AuditRun {
            completion: AuditCompletion::Pending {
                checkpoint: format!("audit:v1:{}", query.id),
                retry_after_seconds: Some(120),
            },
            query: query_value,
            records: Vec::new(),
            diagnostic: None,
        }),
        "succeeded" => {
            let path = format!(
                "/v1.0/security/auditLog/queries/{}/records?$top=500",
                encode_segment(&query.id)
            );
            let values = get_collection(
                transport,
                &path,
                "Graph audit-record paging",
                MissingOutcome::NotFound,
            )
            .map_err(ObservationError::into_failure)?;
            let mut records = values
                .into_iter()
                .map(|record| {
                    let id = record
                        .get("id")
                        .and_then(Value::as_str)
                        .filter(|id| !id.is_empty())
                        .ok_or_else(|| "Graph audit record has no identity".to_string())?;
                    Ok(AuditRecord {
                        id: id.into(),
                        record,
                    })
                })
                .collect::<Result<Vec<_>, String>>()?;
            records.sort_by(|left, right| left.id.cmp(&right.id));
            if records.windows(2).any(|pair| pair[0].id == pair[1].id) {
                return Err("Graph audit result contains duplicate record identities".into());
            }
            Ok(AuditRun {
                completion: AuditCompletion::Complete,
                query: query_value,
                records,
                diagnostic: None,
            })
        }
        "failed" | "cancelled" | "timedOut" | "expired" => Ok(AuditRun {
            completion: AuditCompletion::Complete,
            query: query_value,
            records: Vec::new(),
            diagnostic: Some(AuditDiagnostic {
                outcome: format!("query-{}", query.status),
            }),
        }),
        _ => Err("Graph audit query returned an unknown status".into()),
    }
}

fn resolve_roster<T: Transport>(
    transport: &mut T,
    scope: &MemberScope,
) -> Result<Vec<RosterMember>, String> {
    let users = match scope {
        MemberScope::AllMembers => {
            let first = "/v1.0/users?$filter=accountEnabled%20eq%20true%20and%20userType%20eq%20'Member'&$select=id,displayName,userPrincipalName,mail,accountEnabled,userType&$top=999";
            let mut page: Collection<GraphUser> =
                get_json(transport, first, MissingOutcome::NotFound)
                    .map_err(ObservationError::into_failure)?;
            let mut users = page.value;
            let mut pages = 1;
            while let Some(next) = page.next_link {
                page = get_json(transport, &graph_path(&next)?, MissingOutcome::NotFound)
                    .map_err(ObservationError::into_failure)?;
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
                let user: GraphUser = match get_json(transport, &path, MissingOutcome::NotFound) {
                    Ok(user) => user,
                    Err(ObservationError::NotFound(_)) => {
                        return Err(format!("selected member '{upn}' was not found"));
                    }
                    Err(error) => return Err(error.into_failure()),
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
    missing: MissingOutcome,
) -> Result<D, ObservationError> {
    let response = request_with_retry(
        transport,
        &Request {
            method: Method::Get,
            path: path.into(),
            headers: BTreeMap::from([("accept".into(), "application/json".into())]),
            body: None,
        },
    )
    .map_err(ObservationError::Failed)?;
    if response.status == 404 {
        let code = provider_error_code(&response.body);
        return Err(match missing {
            MissingOutcome::Unavailable => ObservationError::Unavailable(code),
            MissingOutcome::NotFound => ObservationError::NotFound(code),
        });
    }
    if response.status == 403 {
        return Err(ObservationError::Failed(format!(
            "Graph observation failed (HTTP {})",
            response.status
        )));
    }
    if !(200..300).contains(&response.status) {
        return Err(ObservationError::Failed(format!(
            "Graph observation failed (HTTP {})",
            response.status
        )));
    }
    serde_json::from_slice(&response.body)
        .map_err(|_| ObservationError::Failed("Graph returned invalid JSON".into()))
}

fn get_collection<T: Transport>(
    transport: &mut T,
    path: &str,
    paging_label: &str,
    missing: MissingOutcome,
) -> Result<Vec<Value>, ObservationError> {
    let mut next = Some(path.to_string());
    let mut values = Vec::new();
    let mut pages = 0;
    while let Some(path) = next {
        let response = request_with_retry(
            transport,
            &Request {
                method: Method::Get,
                path,
                headers: BTreeMap::from([("accept".into(), "application/json".into())]),
                body: None,
            },
        )
        .map_err(ObservationError::Failed)?;
        if response.status == 403 || response.status == 404 {
            let code = provider_inner_error_code(&response.body)
                .or_else(|| provider_error_code(&response.body));
            return Err(match missing {
                MissingOutcome::Unavailable => ObservationError::Unavailable(code),
                MissingOutcome::NotFound => ObservationError::NotFound(code),
            });
        }
        if !(200..300).contains(&response.status) {
            return Err(ObservationError::Failed(format!(
                "Graph observation failed (HTTP {})",
                response.status
            )));
        }
        let page: Collection<Value> = serde_json::from_slice(&response.body)
            .map_err(|_| ObservationError::Failed("Graph returned invalid JSON".into()))?;
        values.extend(page.value);
        next = page
            .next_link
            .map(|url| graph_path(&url))
            .transpose()
            .map_err(ObservationError::Failed)?;
        pages += 1;
        if pages > MAX_PAGES {
            return Err(ObservationError::Failed(format!(
                "{paging_label} exceeded its ceiling"
            )));
        }
    }
    Ok(values)
}

fn get_content<T: Transport>(
    transport: &mut T,
    path: &str,
    accept: &str,
) -> Result<Response, String> {
    request_with_retry(
        transport,
        &Request {
            method: Method::Get,
            path: path.into(),
            headers: BTreeMap::from([("accept".into(), accept.into())]),
            body: None,
        },
    )
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

fn provider_inner_error_code(body: &[u8]) -> Option<String> {
    let value = serde_json::from_slice::<Value>(body).ok()?;
    let code = value
        .get("error")?
        .get("innerError")?
        .get("code")?
        .as_str()
        .filter(|code| safe_provider_code(code))?;
    Some(code.to_string())
}

fn safe_provider_code(code: &str) -> bool {
    !code.is_empty()
        && code.len() <= 128
        && code
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
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

fn encode_strict_query_value(value: &str) -> String {
    percent_encode(value, false)
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
            Self::invocation(&scenario.invocations[0])
        }

        fn invocation(invocation: &graph_population_fixture::Invocation) -> Self {
            Self {
                exchanges: invocation.exchanges.clone().into(),
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
                assert_eq!(
                    exchange.request.method,
                    match request.method {
                        Method::Get => FixtureMethod::Get,
                        Method::Post => FixtureMethod::Post,
                    }
                );
                assert_eq!(exchange.request.path, request.path);
                for (name, value) in &exchange.request.headers {
                    assert_eq!(request.headers.get(name), Some(value));
                }
                assert_eq!(
                    exchange.request.body,
                    request
                        .body
                        .as_ref()
                        .map(|body| serde_json::from_slice(body).expect("JSON request body"))
                );
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
    fn meeting_artifacts_use_member_routes_and_keep_unavailable_outcomes() {
        let fixture = graph_population_fixture::scenario("meeting-artifacts-mixed-availability");
        let expected = fixture.expected.clone();
        let users = match &fixture.scope {
            graph_population_fixture::Scope::SelectedMembers { users } => users.clone(),
            _ => panic!("selected fixture"),
        };
        let mut transport = FixtureTransport::new(fixture);
        let run = fetch_meetings(
            &mut transport,
            &PopulationConfig {
                scope: MemberScope::SelectedMembers { users },
            },
            "2026-08-01T00:00:00Z",
            "2026-08-02T00:00:00Z",
        )
        .unwrap();
        assert!(transport.exhausted());
        assert_eq!(run.meetings.len(), expected.item_count);
        assert_eq!(run.meetings[0].transcripts.len(), 1);
        assert_eq!(
            run.meetings[0].transcripts[0].media_type,
            "application/vnd.microsoft.graph.transcript+text"
        );
        assert_eq!(run.meetings[0].attendance.len(), 1);
        assert!(run.meetings[0].diagnostics.is_empty());
        assert!(run.meetings[1].transcripts.is_empty());
        assert!(run.meetings[1].attendance.is_empty());
        assert_eq!(run.meetings[1].diagnostics.len(), 2);
        assert!(
            run.meetings
                .iter()
                .all(|meeting| meeting.member_id == "user-alpha")
        );
    }

    fn all_members() -> PopulationConfig {
        PopulationConfig {
            scope: MemberScope::AllMembers,
        }
    }

    #[test]
    fn audit_creation_returns_a_durable_pending_checkpoint() {
        let fixture = graph_population_fixture::scenario("audit-create-pending");
        let expected = fixture.expected.clone();
        let mut transport = FixtureTransport::new(fixture);
        let run = fetch_audit(
            &mut transport,
            &all_members(),
            "2026-08-01T00:00:00Z",
            "2026-08-02T00:00:00Z",
            "kyyn-source-audit-window-001",
            None,
        )
        .unwrap();
        assert!(transport.exhausted());
        assert_eq!(run.records.len(), expected.item_count);
        assert_eq!(
            run.completion,
            AuditCompletion::Pending {
                checkpoint: expected.checkpoint.unwrap(),
                retry_after_seconds: Some(120),
            }
        );
    }

    #[test]
    fn selected_audit_scope_is_an_exact_provider_query_filter() {
        use graph_population_fixture::{Exchange, Invocation, Request as FixtureRequest, Response};
        use serde_json::json;

        let invocation = Invocation {
            checkpoint: None,
            interrupt_after_exchange: None,
            exchanges: vec![
                Exchange {
                    request: FixtureRequest {
                        method: FixtureMethod::Get,
                        path: "/v1.0/security/auditLog/queries".into(),
                        headers: BTreeMap::new(),
                        body: None,
                    },
                    responses: vec![Response {
                        status: 200,
                        headers: BTreeMap::new(),
                        body: json!({ "value": [] }),
                    }],
                },
                Exchange {
                    request: FixtureRequest {
                        method: FixtureMethod::Post,
                        path: "/v1.0/security/auditLog/queries".into(),
                        headers: BTreeMap::new(),
                        body: Some(json!({
                            "displayName": "kyyn-source-audit-window-001",
                            "filterStartDateTime": "2026-08-01T00:00:00Z",
                            "filterEndDateTime": "2026-08-02T00:00:00Z",
                            "recordTypeFilters": ["microsoftTeams"],
                            "operationFilters": ["MeetingDetail", "MeetingParticipantDetail"],
                            "userPrincipalNameFilters": ["alpha@example.test"]
                        })),
                    },
                    responses: vec![Response {
                        status: 201,
                        headers: BTreeMap::new(),
                        body: json!({
                            "id": "query-selected",
                            "displayName": "kyyn-source-audit-window-001",
                            "status": "notStarted",
                            "filterStartDateTime": "2026-08-01T00:00:00Z",
                            "filterEndDateTime": "2026-08-02T00:00:00Z",
                            "recordTypeFilters": ["microsoftTeams"],
                            "operationFilters": ["MeetingDetail", "MeetingParticipantDetail"],
                            "userPrincipalNameFilters": ["alpha@example.test"]
                        }),
                    }],
                },
            ],
        };
        let mut transport = FixtureTransport::invocation(&invocation);
        let run = fetch_audit(
            &mut transport,
            &PopulationConfig {
                scope: MemberScope::SelectedMembers {
                    users: vec!["alpha@example.test".into()],
                },
            },
            "2026-08-01T00:00:00Z",
            "2026-08-02T00:00:00Z",
            "kyyn-source-audit-window-001",
            None,
        )
        .unwrap();
        assert!(transport.exhausted());
        assert!(matches!(run.completion, AuditCompletion::Pending { .. }));
    }

    #[test]
    fn audit_rediscovery_is_exact_and_ambiguous_matches_refuse() {
        let fixture = graph_population_fixture::scenario("audit-crash-after-create-rediscover");
        let mut transport = FixtureTransport::invocation(&fixture.invocations[1]);
        let run = fetch_audit(
            &mut transport,
            &all_members(),
            "2026-08-01T00:00:00Z",
            "2026-08-02T00:00:00Z",
            "kyyn-source-audit-window-001",
            None,
        )
        .unwrap();
        assert!(transport.exhausted());
        assert!(matches!(run.completion, AuditCompletion::Pending { .. }));

        let fixture = graph_population_fixture::scenario("audit-ambiguous-query-refusal");
        let mut transport = FixtureTransport::new(fixture);
        let error = fetch_audit(
            &mut transport,
            &all_members(),
            "2026-08-01T00:00:00Z",
            "2026-08-02T00:00:00Z",
            "kyyn-source-audit-window-001",
            None,
        )
        .unwrap_err();
        assert_eq!(
            error,
            "Graph returned multiple indistinguishable audit queries"
        );
        assert!(transport.exhausted());
    }

    #[test]
    fn audit_checkpoint_downloads_all_pages_and_terminal_failure_is_complete() {
        let fixture = graph_population_fixture::scenario("audit-checkpoint-complete-paged");
        let expected = fixture.expected.clone();
        let checkpoint = fixture.invocations[0].checkpoint.clone().unwrap();
        let mut transport = FixtureTransport::new(fixture);
        let run = fetch_audit(
            &mut transport,
            &all_members(),
            "2026-08-01T00:00:00Z",
            "2026-08-02T00:00:00Z",
            "kyyn-source-audit-window-001",
            Some(&checkpoint),
        )
        .unwrap();
        assert!(transport.exhausted());
        assert_eq!(run.completion, AuditCompletion::Complete);
        assert_eq!(run.records.len(), expected.item_count);

        let fixture = graph_population_fixture::scenario("audit-terminal-failure-complete");
        let checkpoint = fixture.invocations[0].checkpoint.clone().unwrap();
        let mut transport = FixtureTransport::new(fixture);
        let run = fetch_audit(
            &mut transport,
            &all_members(),
            "2026-08-01T00:00:00Z",
            "2026-08-02T00:00:00Z",
            "kyyn-source-audit-window-001",
            Some(&checkpoint),
        )
        .unwrap();
        assert!(transport.exhausted());
        assert_eq!(run.completion, AuditCompletion::Complete);
        assert!(run.records.is_empty());
        assert_eq!(run.diagnostic.unwrap().outcome, "query-failed");
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
