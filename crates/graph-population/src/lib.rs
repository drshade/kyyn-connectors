//! Provider-neutral execution core for ADR 0037 Microsoft Graph population
//! sources. Shipped components supply the contained transport and evidence
//! adapters; this crate owns no ambient network or filesystem authority.

use std::collections::{BTreeMap, BTreeSet};

use chrono::{DateTime, NaiveDateTime, SecondsFormat, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

const MAX_PAGES: usize = 500;
const MAX_COLLECTION_BYTES: usize = 16 * 1024 * 1024;
// A worst-case accepted 320-byte UPN plus serialization overhead must fit both
// sides of Kyyn's immutable 1 MiB configurator envelope.
const MAX_MEMBERS: usize = 3_000;
const CALENDAR_PAGE_SIZE: usize = 500;
const CALENDAR_BATCH_WIDTH: usize = 8;
// One evidence file per emitted item plus the shared roster must fit Kyyn's
// 4,096-file source invocation allowance. Thirty-two sparse waves also bound
// provider calls and guest execution without turning one wave into one batch.
const MAX_BATCH_ITEMS: usize = 4_095;
const MAX_CALENDAR_WAVES: usize = 32;
const CALENDAR_FIELDS: &str = "iCalUId,subject,start,end,organizer,attendees,isOnlineMeeting,onlineMeeting,isCancelled,categories,type,seriesMasterId,responseStatus";

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PopulationConfig {
    pub scope: MemberScope,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
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
        let invalid = || {
            "population config must contain exactly one AllMembers or SelectedMembers scope"
                .to_string()
        };
        let config: Self = match ron::from_str(text) {
            Ok(config) => config,
            Err(_) => {
                // Kyyn stores accepted connector configuration as `ron::Value`.
                // RON then renders the map with braces, which is the same
                // provider-neutral data but not Rust struct syntax. Decode the
                // closed tagged sum from that exact map without accepting any
                // additional states.
                let value: ron::Value = ron::from_str(text).map_err(|_| invalid())?;
                let ron::Value::Map(config) = value else {
                    return Err(invalid());
                };
                if config.len() != 1 {
                    return Err(invalid());
                }
                let scope = config
                    .get(&ron::Value::String("scope".into()))
                    .ok_or_else(&invalid)?;
                let ron::Value::Map(scope) = scope else {
                    return Err(invalid());
                };
                let kind = scope
                    .get(&ron::Value::String("kind".into()))
                    .and_then(|value| match value {
                        ron::Value::String(value) => Some(value.as_str()),
                        _ => None,
                    })
                    .ok_or_else(&invalid)?;
                let scope = match kind {
                    "all-members" if scope.len() == 1 => MemberScope::AllMembers,
                    "selected-members" if scope.len() == 2 => {
                        let users = scope
                            .get(&ron::Value::String("users".into()))
                            .and_then(|value| match value {
                                ron::Value::Seq(values) => values
                                    .iter()
                                    .map(|value| match value {
                                        ron::Value::String(value) => Some(value.clone()),
                                        _ => None,
                                    })
                                    .collect::<Option<Vec<_>>>(),
                                _ => None,
                            })
                            .ok_or_else(&invalid)?;
                        MemberScope::SelectedMembers { users }
                    }
                    _ => return Err(invalid()),
                };
                Self { scope }
            }
        };
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
    fn send_many(&mut self, requests: &[Request]) -> Result<Vec<Result<Response, String>>, String> {
        Ok(requests.iter().map(|request| self.send(request)).collect())
    }
    fn sleep_ms(&mut self, milliseconds: u64);
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RosterMember {
    pub id: String,
    pub user_principal_name: String,
    pub display_name: Option<String>,
    pub mail: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BatchCompletion {
    Pending { checkpoint: String },
    Complete,
}

#[derive(Clone, Debug)]
pub struct MeetingBatch {
    pub roster: Vec<RosterMember>,
    pub item_count: usize,
    pub unavailable_members: Vec<MemberUnavailable>,
    pub completion: BatchCompletion,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MemberUnavailable {
    pub id: String,
    pub member_id: String,
    pub user_principal_name: String,
    pub window_start: String,
    pub window_until: String,
    pub reason: MemberUnavailableReason,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub provider_code: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum MemberUnavailableReason {
    MailboxUnavailable,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PopulationMeeting {
    pub id: String,
    pub observed_by_member_id: String,
    pub observed_by_user_principal_name: String,
    pub provider_event_id: String,
    pub calendar_event: Value,
    pub online_meeting: Option<Value>,
    pub transcript: ArtifactOutcome<Vec<TranscriptArtifact>>,
    pub attendance: ArtifactOutcome<Vec<AttendanceArtifact>>,
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
#[serde(tag = "outcome", rename_all = "kebab-case")]
pub enum ArtifactOutcome<T> {
    Observed {
        material: T,
    },
    Unavailable {
        reason: UnavailableReason,
        #[serde(skip_serializing_if = "Option::is_none")]
        provider_code: Option<String>,
    },
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum UnavailableReason {
    NotRetained,
    NotPermitted,
    NotProduced,
    ExternalOrganizer,
    UnsupportedMeeting,
    ProviderUnavailable,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct BatchCheckpoint {
    version: u8,
    next_member_index: usize,
    pending: Vec<MemberCursor>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct MemberCursor {
    member_index: usize,
    page_path: String,
}

#[derive(Clone, Debug)]
struct CollectionPage {
    values: Vec<Value>,
    next_path: Option<String>,
}

#[derive(Clone, Debug)]
struct Organizer {
    id: String,
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

#[derive(Clone, Copy)]
enum MissingOutcome {
    Unavailable,
    NotFound,
}

enum ObservationError {
    Unavailable(Option<String>),
    NotFound(Option<String>),
    Forbidden(Option<String>),
    Unauthorized(Option<String>),
    Limit(String),
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
            Self::Forbidden(code) => format!(
                "Graph observation was forbidden{}",
                code.map(|code| format!(" ({code})")).unwrap_or_default()
            ),
            Self::Unauthorized(code) => format!(
                "Graph authentication was rejected{}",
                code.map(|code| format!(" ({code})")).unwrap_or_default()
            ),
            Self::Limit(error) => error,
            Self::Failed(error) => error,
        }
    }
}

pub fn fetch_meeting_batch<T: Transport, F: FnMut(PopulationMeeting) -> Result<(), String>>(
    transport: &mut T,
    config: &PopulationConfig,
    start: &str,
    until: &str,
    checkpoint: Option<&str>,
    mut emit: F,
) -> Result<MeetingBatch, String> {
    config.validate()?;
    let roster = resolve_roster(transport, &config.scope)?;
    let mut cursor = parse_batch_checkpoint(checkpoint)?;
    validate_batch_checkpoint(&cursor, &roster)?;
    let mut item_count = 0usize;
    let mut unavailable_members = Vec::new();
    let mut waves = 0usize;
    loop {
        let used_items = item_count
            .checked_add(unavailable_members.len())
            .ok_or_else(|| "meeting batch item count overflowed".to_string())?;
        let remaining_items = MAX_BATCH_ITEMS.saturating_sub(used_items);
        let wave_width = CALENDAR_BATCH_WIDTH.min(remaining_items / CALENDAR_PAGE_SIZE);
        if waves == MAX_CALENDAR_WAVES || wave_width == 0 || cursor.pending.len() > wave_width {
            break;
        }
        while cursor.pending.len() < wave_width && cursor.next_member_index < roster.len() {
            let member_index = cursor.next_member_index;
            cursor.next_member_index += 1;
            cursor.pending.push(MemberCursor {
                member_index,
                page_path: calendar_path(&roster[member_index], start, until),
            });
        }
        if cursor.pending.is_empty() {
            break;
        }

        let active = std::mem::take(&mut cursor.pending);
        let requests = active
            .iter()
            .map(|member| calendar_request(member.page_path.clone()))
            .collect::<Vec<_>>();
        let responses = request_many_with_retry(transport, &requests)?;
        if responses.len() != active.len() {
            return Err("concurrent Graph transport changed the calendar result count".into());
        }

        let mut pending = Vec::new();
        for (member_cursor, response) in active.into_iter().zip(responses) {
            let member = &roster[member_cursor.member_index];
            let page = match collection_page_from_response(response, MissingOutcome::Unavailable) {
                Ok(page) => page,
                Err(ObservationError::Unavailable(code))
                    if mailbox_unavailable(code.as_deref()) =>
                {
                    unavailable_members.push(member_unavailable(member, start, until, code));
                    continue;
                }
                Err(error) => return Err(error.into_failure()),
            };
            if page.values.len() > CALENDAR_PAGE_SIZE {
                return Err("Graph calendar page exceeded the requested item bound".into());
            }

            let mut events = Vec::new();
            for event in page.values {
                if !is_canonical_observer(&event, member, &roster) {
                    continue;
                }
                let id = event_occurrence_identity(&event)?;
                events.push((id, event));
            }
            events.sort_by(|left, right| left.0.cmp(&right.0));
            if events.windows(2).any(|pair| pair[0].0 == pair[1].0) {
                return Err("Graph calendar page contains duplicate meeting occurrences".into());
            }
            item_count = item_count
                .checked_add(events.len())
                .ok_or_else(|| "meeting batch item count overflowed".to_string())?;
            for (expected_id, event) in events {
                let meeting = observe_meeting(transport, member, &roster, event)?;
                if meeting.id != expected_id {
                    return Err("meeting occurrence identity changed during observation".into());
                }
                emit(meeting)?;
            }
            if let Some(page_path) = page.next_path {
                validate_calendar_checkpoint_path(&page_path, member)?;
                pending.push(MemberCursor {
                    member_index: member_cursor.member_index,
                    page_path,
                });
            }
        }
        cursor.pending = pending;
        waves += 1;
    }
    let completion = if cursor.next_member_index == roster.len() && cursor.pending.is_empty() {
        BatchCompletion::Complete
    } else {
        BatchCompletion::Pending {
            checkpoint: encode_batch_checkpoint(&cursor)?,
        }
    };
    Ok(MeetingBatch {
        roster,
        item_count,
        unavailable_members,
        completion,
    })
}

fn observe_meeting<T: Transport>(
    transport: &mut T,
    member: &RosterMember,
    roster: &[RosterMember],
    event: Value,
) -> Result<PopulationMeeting, String> {
    let provider_event_id = required_string(&event, "id", "Graph meeting event has no identity")?;
    let id = event_occurrence_identity(&event)?;
    let calendar_event = project_calendar_event(&event);
    let Some(join_url) = event
        .get("onlineMeeting")
        .and_then(|meeting| meeting.get("joinUrl"))
        .and_then(Value::as_str)
        .filter(|url| !url.is_empty())
    else {
        return Ok(PopulationMeeting {
            id,
            observed_by_member_id: member.id.clone(),
            observed_by_user_principal_name: member.user_principal_name.clone(),
            provider_event_id: provider_event_id.into(),
            calendar_event,
            online_meeting: None,
            transcript: unavailable_outcome(UnavailableReason::UnsupportedMeeting, None),
            attendance: unavailable_outcome(UnavailableReason::UnsupportedMeeting, None),
        });
    };
    let Some(organizer) = resolve_organizer(transport, roster, &event)? else {
        return Ok(PopulationMeeting {
            id,
            observed_by_member_id: member.id.clone(),
            observed_by_user_principal_name: member.user_principal_name.clone(),
            provider_event_id: provider_event_id.into(),
            calendar_event,
            online_meeting: None,
            transcript: unavailable_outcome(UnavailableReason::ExternalOrganizer, None),
            attendance: unavailable_outcome(UnavailableReason::ExternalOrganizer, None),
        });
    };
    let lookup = format!(
        "/v1.0/users/{}/onlineMeetings?$filter=JoinWebUrl%20eq%20'{}'",
        encode_segment(&organizer.id),
        encode_strict_query_value(join_url)
    );
    let resolved = match get_collection(
        transport,
        &lookup,
        "Graph meeting lookup paging",
        MissingOutcome::NotFound,
    ) {
        Ok(values) => values,
        Err(ObservationError::Forbidden(code)) => {
            return Ok(unavailable_meeting(
                id,
                member,
                provider_event_id,
                calendar_event,
                UnavailableReason::NotPermitted,
                code,
            ));
        }
        Err(ObservationError::NotFound(code)) => {
            return Ok(unavailable_meeting(
                id,
                member,
                provider_event_id,
                calendar_event,
                UnavailableReason::NotRetained,
                code,
            ));
        }
        Err(error @ ObservationError::Unauthorized(_)) => return Err(error.into_failure()),
        Err(error @ ObservationError::Limit(_)) => return Err(error.into_failure()),
        Err(error) => {
            return Ok(unavailable_meeting(
                id,
                member,
                provider_event_id,
                calendar_event,
                UnavailableReason::ProviderUnavailable,
                observation_code(&error),
            ));
        }
    };
    if resolved.len() > 1 {
        return Err("Graph meeting lookup returned an ambiguous identity".into());
    }
    let Some(online_meeting) = resolved.into_iter().next() else {
        return Ok(unavailable_meeting(
            id,
            member,
            provider_event_id,
            calendar_event,
            UnavailableReason::NotProduced,
            None,
        ));
    };
    let meeting_id = required_string(
        &online_meeting,
        "id",
        "Graph online meeting has no identity",
    )?;
    let transcript = fetch_transcripts(transport, &organizer.id, meeting_id)?;
    let attendance = fetch_attendance(transport, &organizer.id, meeting_id)?;
    Ok(PopulationMeeting {
        id,
        observed_by_member_id: member.id.clone(),
        observed_by_user_principal_name: member.user_principal_name.clone(),
        provider_event_id: provider_event_id.into(),
        calendar_event,
        online_meeting: Some(online_meeting),
        transcript,
        attendance,
    })
}

fn fetch_transcripts<T: Transport>(
    transport: &mut T,
    organizer_id: &str,
    meeting_id: &str,
) -> Result<ArtifactOutcome<Vec<TranscriptArtifact>>, String> {
    let path = format!(
        "/v1.0/users/{}/onlineMeetings/{}/transcripts",
        encode_segment(organizer_id),
        encode_segment(meeting_id)
    );
    let metadata = match get_collection(
        transport,
        &path,
        "Graph transcript paging",
        MissingOutcome::Unavailable,
    ) {
        Ok(metadata) => metadata,
        Err(error @ ObservationError::Unauthorized(_)) => return Err(error.into_failure()),
        Err(error @ ObservationError::Limit(_)) => return Err(error.into_failure()),
        Err(error) => return Ok(artifact_error(error)),
    };
    if metadata.is_empty() {
        return Ok(ArtifactOutcome::Unavailable {
            reason: UnavailableReason::NotProduced,
            provider_code: None,
        });
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
            encode_segment(organizer_id),
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
            return Ok(ArtifactOutcome::Unavailable {
                reason: if response.status == 403 {
                    UnavailableReason::NotPermitted
                } else {
                    UnavailableReason::NotRetained
                },
                provider_code: provider_inner_error_code(&response.body)
                    .or_else(|| provider_error_code(&response.body)),
            });
        }
        if response.status == 401 {
            return Err(
                "Graph authentication was rejected while reading transcript content".into(),
            );
        }
        if !(200..300).contains(&response.status) {
            return Ok(ArtifactOutcome::Unavailable {
                reason: UnavailableReason::ProviderUnavailable,
                provider_code: provider_inner_error_code(&response.body)
                    .or_else(|| provider_error_code(&response.body)),
            });
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
    Ok(ArtifactOutcome::Observed {
        material: artifacts,
    })
}

fn fetch_attendance<T: Transport>(
    transport: &mut T,
    organizer_id: &str,
    meeting_id: &str,
) -> Result<ArtifactOutcome<Vec<AttendanceArtifact>>, String> {
    let path = format!(
        "/v1.0/users/{}/onlineMeetings/{}/attendanceReports",
        encode_segment(organizer_id),
        encode_segment(meeting_id)
    );
    let reports = match get_collection(
        transport,
        &path,
        "Graph attendance paging",
        MissingOutcome::Unavailable,
    ) {
        Ok(reports) => reports,
        Err(error @ ObservationError::Unauthorized(_)) => return Err(error.into_failure()),
        Err(error @ ObservationError::Limit(_)) => return Err(error.into_failure()),
        Err(error) => return Ok(artifact_error(error)),
    };
    if reports.is_empty() {
        return Ok(ArtifactOutcome::Unavailable {
            reason: UnavailableReason::NotProduced,
            provider_code: None,
        });
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
            encode_segment(organizer_id),
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
            Err(error) => return Ok(artifact_error(error)),
        };
        artifacts.push(AttendanceArtifact {
            report_id: report_id.into(),
            records,
        });
    }
    Ok(ArtifactOutcome::Observed {
        material: artifacts,
    })
}

fn artifact_error<T>(error: ObservationError) -> ArtifactOutcome<T> {
    let (reason, provider_code) = match error {
        ObservationError::Forbidden(code) => (UnavailableReason::NotPermitted, code),
        ObservationError::Unauthorized(_) => unreachable!("authentication is a run failure"),
        ObservationError::Limit(_) => unreachable!("connector limits are a run failure"),
        ObservationError::NotFound(code) => (UnavailableReason::NotRetained, code),
        ObservationError::Unavailable(code) => (UnavailableReason::NotRetained, code),
        ObservationError::Failed(_) => (UnavailableReason::ProviderUnavailable, None),
    };
    ArtifactOutcome::Unavailable {
        reason,
        provider_code,
    }
}

fn unavailable_meeting(
    id: String,
    member: &RosterMember,
    provider_event_id: &str,
    calendar_event: Value,
    reason: UnavailableReason,
    provider_code: Option<String>,
) -> PopulationMeeting {
    PopulationMeeting {
        id,
        observed_by_member_id: member.id.clone(),
        observed_by_user_principal_name: member.user_principal_name.clone(),
        provider_event_id: provider_event_id.into(),
        calendar_event,
        online_meeting: None,
        transcript: unavailable_outcome(reason.clone(), provider_code.clone()),
        attendance: unavailable_outcome(reason, provider_code),
    }
}

fn unavailable_outcome<T>(
    reason: UnavailableReason,
    provider_code: Option<String>,
) -> ArtifactOutcome<T> {
    ArtifactOutcome::Unavailable {
        reason,
        provider_code,
    }
}

fn observation_code(error: &ObservationError) -> Option<String> {
    match error {
        ObservationError::Unavailable(code)
        | ObservationError::NotFound(code)
        | ObservationError::Forbidden(code)
        | ObservationError::Unauthorized(code) => code.clone(),
        ObservationError::Limit(_) => None,
        ObservationError::Failed(_) => None,
    }
}

fn calendar_path(member: &RosterMember, start: &str, until: &str) -> String {
    format!(
        "/v1.0/users/{}/calendarView?startDateTime={}&endDateTime={}&$select={CALENDAR_FIELDS}&$top={CALENDAR_PAGE_SIZE}",
        encode_segment(&member.id),
        encode_query_value(start),
        encode_query_value(until),
    )
}

fn calendar_request(path: String) -> Request {
    Request {
        method: Method::Get,
        path,
        headers: BTreeMap::from([
            ("accept".into(), "application/json".into()),
            ("prefer".into(), "outlook.timezone=\"UTC\"".into()),
        ]),
        body: None,
    }
}

fn mailbox_unavailable(code: Option<&str>) -> bool {
    matches!(
        code,
        Some("MailboxNotEnabledForRESTAPI" | "ErrorMailboxNotEnabledForRESTAPI")
    )
}

fn member_unavailable(
    member: &RosterMember,
    start: &str,
    until: &str,
    provider_code: Option<String>,
) -> MemberUnavailable {
    let digest =
        Sha256::digest(format!("{}\0{start}\0{until}\0mailbox-unavailable", member.id).as_bytes());
    MemberUnavailable {
        id: format!("member-observation:v1:{digest:x}"),
        member_id: member.id.clone(),
        user_principal_name: member.user_principal_name.clone(),
        window_start: start.into(),
        window_until: until.into(),
        reason: MemberUnavailableReason::MailboxUnavailable,
        provider_code,
    }
}

fn parse_batch_checkpoint(checkpoint: Option<&str>) -> Result<BatchCheckpoint, String> {
    let Some(checkpoint) = checkpoint else {
        return Ok(BatchCheckpoint {
            version: 2,
            next_member_index: 0,
            pending: Vec::new(),
        });
    };
    let parsed: BatchCheckpoint = serde_json::from_str(checkpoint)
        .map_err(|_| "meeting batch checkpoint is invalid".to_string())?;
    if parsed.version != 2 {
        return Err("meeting batch checkpoint has an unsupported version".into());
    }
    Ok(parsed)
}

fn encode_batch_checkpoint(checkpoint: &BatchCheckpoint) -> Result<String, String> {
    serde_json::to_string(checkpoint)
        .map_err(|_| "could not encode meeting batch checkpoint".to_string())
}

fn validate_batch_checkpoint(
    checkpoint: &BatchCheckpoint,
    roster: &[RosterMember],
) -> Result<(), String> {
    if checkpoint.next_member_index > roster.len()
        || checkpoint.pending.len() > CALENDAR_BATCH_WIDTH
    {
        return Err("meeting batch checkpoint is outside the resolved population".into());
    }
    let mut members = BTreeSet::new();
    for pending in &checkpoint.pending {
        if pending.member_index >= checkpoint.next_member_index
            || !members.insert(pending.member_index)
        {
            return Err("meeting batch checkpoint has an invalid pending member set".into());
        }
        let member = roster.get(pending.member_index).ok_or_else(|| {
            "meeting batch checkpoint is outside the resolved population".to_string()
        })?;
        validate_calendar_checkpoint_path(&pending.page_path, member)?;
    }
    Ok(())
}

fn validate_calendar_checkpoint_path(path: &str, member: &RosterMember) -> Result<(), String> {
    let prefix = format!("/v1.0/users/{}/calendarView?", encode_segment(&member.id));
    if !path.starts_with(&prefix) || path.len() > 8_192 {
        return Err("meeting batch checkpoint does not address the current member calendar".into());
    }
    Ok(())
}

fn required_string<'a>(value: &'a Value, key: &str, message: &str) -> Result<&'a str, String> {
    value
        .get(key)
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| message.to_string())
}

fn occurrence_identity(i_cal_uid: &str, start: &str) -> Result<String, String> {
    let normalized_uid = i_cal_uid.trim();
    if normalized_uid.is_empty() {
        return Err("Graph meeting event has an empty normalized iCalUId".into());
    }
    let start = DateTime::parse_from_rfc3339(start)
        .map_err(|_| "Graph meeting event start is not RFC3339".to_string())?
        .with_timezone(&Utc)
        .to_rfc3339_opts(SecondsFormat::AutoSi, true);
    let digest = Sha256::digest(format!("{normalized_uid}\0{start}").as_bytes());
    Ok(format!("occurrence:v1:{digest:x}"))
}

fn event_occurrence_identity(event: &Value) -> Result<String, String> {
    let i_cal_uid = required_string(event, "iCalUId", "Graph meeting event has no iCalUId")?;
    let start = event
        .get("start")
        .and_then(Value::as_object)
        .ok_or_else(|| "Graph meeting event has no start instant".to_string())?;
    let date_time = start
        .get("dateTime")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| "Graph meeting event has no start instant".to_string())?;
    let canonical = if let Ok(parsed) = DateTime::parse_from_rfc3339(date_time) {
        parsed
            .with_timezone(&Utc)
            .to_rfc3339_opts(SecondsFormat::AutoSi, true)
    } else if start.get("timeZone").and_then(Value::as_str) == Some("UTC") {
        NaiveDateTime::parse_from_str(date_time, "%Y-%m-%dT%H:%M:%S%.f")
            .map_err(|_| "Graph meeting event start is not a supported UTC instant".to_string())?
            .and_utc()
            .to_rfc3339_opts(SecondsFormat::AutoSi, true)
    } else {
        return Err("Graph meeting event start is not a supported UTC instant".into());
    };
    occurrence_identity(i_cal_uid, &canonical)
}

fn project_calendar_event(event: &Value) -> Value {
    let mut projected = serde_json::Map::new();
    for field in CALENDAR_FIELDS.split(',') {
        projected.insert(
            field.to_string(),
            event.get(field).cloned().unwrap_or(Value::Null),
        );
    }
    Value::Object(projected)
}

fn event_addresses(event: &Value) -> BTreeSet<String> {
    let mut addresses = BTreeSet::new();
    if let Some(address) = organizer_address(event) {
        addresses.insert(address);
    }
    if let Some(attendees) = event.get("attendees").and_then(Value::as_array) {
        for attendee in attendees {
            if let Some(address) = attendee
                .get("emailAddress")
                .and_then(|value| value.get("address"))
                .and_then(Value::as_str)
                .map(|value| value.to_ascii_lowercase())
            {
                addresses.insert(address);
            }
        }
    }
    addresses
}

fn member_matches(member: &RosterMember, addresses: &BTreeSet<String>) -> bool {
    addresses.contains(&member.user_principal_name)
        || member
            .mail
            .as_ref()
            .is_some_and(|mail| addresses.contains(mail))
}

fn is_canonical_observer(event: &Value, member: &RosterMember, roster: &[RosterMember]) -> bool {
    let addresses = event_addresses(event);
    roster
        .iter()
        .filter(|candidate| member_matches(candidate, &addresses))
        .min_by(|left, right| {
            left.user_principal_name
                .cmp(&right.user_principal_name)
                .then_with(|| left.id.cmp(&right.id))
        })
        .is_none_or(|candidate| candidate.id == member.id)
}

fn organizer_address(event: &Value) -> Option<String> {
    event
        .get("organizer")
        .and_then(|value| value.get("emailAddress"))
        .and_then(|value| value.get("address"))
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .map(|value| value.to_ascii_lowercase())
}

fn resolve_organizer<T: Transport>(
    transport: &mut T,
    roster: &[RosterMember],
    event: &Value,
) -> Result<Option<Organizer>, String> {
    let Some(address) = organizer_address(event) else {
        return Ok(None);
    };
    if let Some(member) = roster.iter().find(|member| {
        member.user_principal_name == address || member.mail.as_deref() == Some(address.as_str())
    }) {
        return Ok(Some(Organizer {
            id: member.id.clone(),
        }));
    }
    let path = format!(
        "/v1.0/users/{}?$select=id,displayName,userPrincipalName,mail,accountEnabled,userType",
        encode_segment(&address)
    );
    let user: GraphUser = match get_json(transport, &path, MissingOutcome::NotFound) {
        Ok(user) => user,
        Err(ObservationError::NotFound(_)) => return Ok(None),
        Err(error) => return Err(error.into_failure()),
    };
    if !eligible(&user) {
        return Ok(None);
    }
    validate_graph_user(&user)?;
    Ok(Some(Organizer { id: user.id }))
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
            let mut users = Vec::new();
            let mut pages = 1;
            loop {
                for user in page.value {
                    if eligible(&user) {
                        validate_graph_user(&user)?;
                        users.push(user);
                        if users.len() > MAX_MEMBERS {
                            return Err(format!(
                                "Graph population exceeds the {MAX_MEMBERS} member ceiling"
                            ));
                        }
                    }
                }
                let Some(next) = page.next_link else {
                    break;
                };
                page = get_json(transport, &graph_path(&next)?, MissingOutcome::NotFound)
                    .map_err(ObservationError::into_failure)?;
                pages += 1;
                if pages > MAX_PAGES {
                    return Err("Graph directory paging exceeded its ceiling".into());
                }
            }
            users
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
                validate_graph_user(&user)?;
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

fn validate_graph_user(user: &GraphUser) -> Result<(), String> {
    if user.id.is_empty() || user.id.len() > 256 || !user.id.is_ascii() {
        return Err("Graph directory member has an invalid provider identity".into());
    }
    validate_upn(&user.user_principal_name.to_ascii_lowercase())
        .map_err(|_| "Graph directory member has an invalid user principal name".to_string())?;
    if user
        .display_name
        .as_ref()
        .is_some_and(|value| value.len() > 512)
        || user
            .mail
            .as_ref()
            .is_some_and(|value| value.len() > 320 || !value.is_ascii())
    {
        return Err("Graph directory member display metadata exceeds its bound".into());
    }
    Ok(())
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
    if response.status == 401 {
        return Err(ObservationError::Unauthorized(provider_error_code(
            &response.body,
        )));
    }
    if response.status == 404 {
        let code = provider_error_code(&response.body);
        return Err(match missing {
            MissingOutcome::Unavailable => ObservationError::Unavailable(code),
            MissingOutcome::NotFound => ObservationError::NotFound(code),
        });
    }
    if response.status == 403 {
        return Err(ObservationError::Forbidden(
            provider_inner_error_code(&response.body)
                .or_else(|| provider_error_code(&response.body)),
        ));
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
    let mut observed_bytes = 0usize;
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
        if response.status == 401 {
            return Err(ObservationError::Unauthorized(provider_error_code(
                &response.body,
            )));
        }
        if response.status == 403 {
            let code = provider_inner_error_code(&response.body)
                .or_else(|| provider_error_code(&response.body));
            return Err(ObservationError::Forbidden(code));
        }
        if response.status == 404 {
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
        observed_bytes = observed_bytes
            .checked_add(response.body.len())
            .ok_or_else(|| {
                ObservationError::Limit(format!("{paging_label} exceeded its byte ceiling"))
            })?;
        if observed_bytes > MAX_COLLECTION_BYTES {
            return Err(ObservationError::Limit(format!(
                "{paging_label} exceeded its {MAX_COLLECTION_BYTES}-byte ceiling"
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
            return Err(ObservationError::Limit(format!(
                "{paging_label} exceeded its ceiling"
            )));
        }
    }
    Ok(values)
}

fn collection_page_from_response(
    response: Response,
    missing: MissingOutcome,
) -> Result<CollectionPage, ObservationError> {
    let code = || {
        provider_inner_error_code(&response.body).or_else(|| provider_error_code(&response.body))
    };
    if response.status == 401 {
        return Err(ObservationError::Unauthorized(code()));
    }
    if response.status == 403 {
        return Err(ObservationError::Forbidden(code()));
    }
    if response.status == 404 {
        return Err(match missing {
            MissingOutcome::Unavailable => ObservationError::Unavailable(code()),
            MissingOutcome::NotFound => ObservationError::NotFound(code()),
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
    Ok(CollectionPage {
        values: page.value,
        next_path: page
            .next_link
            .map(|url| graph_path(&url))
            .transpose()
            .map_err(ObservationError::Failed)?,
    })
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

fn request_many_with_retry<T: Transport>(
    transport: &mut T,
    requests: &[Request],
) -> Result<Vec<Response>, String> {
    if requests.is_empty() || requests.len() > CALENDAR_BATCH_WIDTH {
        return Err("concurrent Graph request group is outside its bound".into());
    }
    let mut pending = requests
        .iter()
        .cloned()
        .enumerate()
        .map(|(index, request)| (index, request, 1u64))
        .collect::<Vec<_>>();
    let mut completed = (0..requests.len()).map(|_| None).collect::<Vec<_>>();
    while !pending.is_empty() {
        let wave = pending
            .iter()
            .map(|(_, request, _)| request.clone())
            .collect::<Vec<_>>();
        let results = transport.send_many(&wave)?;
        if results.len() != pending.len() {
            return Err("concurrent Graph transport changed its result count".into());
        }
        let mut retry = Vec::new();
        let mut sleep_milliseconds = 0u64;
        for ((index, request, attempt), result) in pending.into_iter().zip(results) {
            let response = result?;
            if (response.status == 429 || response.status >= 500) && attempt < 5 {
                let milliseconds = if response.status == 429 {
                    response
                        .headers
                        .get("retry-after")
                        .and_then(|value| value.parse::<u64>().ok())
                        .unwrap_or(5)
                        .min(60)
                        * 1_000
                } else {
                    (1u64 << attempt).min(30) * 1_000
                };
                sleep_milliseconds = sleep_milliseconds.max(milliseconds);
                retry.push((index, request, attempt + 1));
            } else {
                completed[index] = Some(response);
            }
        }
        if !retry.is_empty() {
            transport.sleep_ms(sleep_milliseconds);
        }
        pending = retry;
    }
    completed
        .into_iter()
        .map(|response| response.ok_or_else(|| "concurrent Graph response is missing".into()))
        .collect()
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
    use serde_json::json;
    use std::collections::VecDeque;

    struct ScriptTransport {
        exchanges: VecDeque<(String, Response)>,
        requested: Vec<String>,
        concurrent: Vec<Vec<String>>,
        sleeps: Vec<u64>,
    }

    impl ScriptTransport {
        fn new(exchanges: Vec<(String, Response)>) -> Self {
            Self {
                exchanges: exchanges.into(),
                requested: Vec::new(),
                concurrent: Vec::new(),
                sleeps: Vec::new(),
            }
        }

        fn exhausted(&self) -> bool {
            self.exchanges.is_empty()
        }
    }

    impl Transport for ScriptTransport {
        fn send(&mut self, request: &Request) -> Result<Response, String> {
            let (expected, response) = self.exchanges.pop_front().expect("unexpected request");
            assert_eq!(request.method, Method::Get);
            assert_eq!(request.path, expected);
            if request.path.contains("/calendarView?") {
                assert_eq!(
                    request.headers.get("prefer").map(String::as_str),
                    Some("outlook.timezone=\"UTC\"")
                );
            }
            self.requested.push(request.path.clone());
            Ok(response)
        }

        fn send_many(
            &mut self,
            requests: &[Request],
        ) -> Result<Vec<Result<Response, String>>, String> {
            self.concurrent.push(
                requests
                    .iter()
                    .map(|request| request.path.clone())
                    .collect(),
            );
            requests
                .iter()
                .map(|request| self.send(request).map(Ok))
                .collect()
        }

        fn sleep_ms(&mut self, milliseconds: u64) {
            self.sleeps.push(milliseconds);
        }
    }

    fn response(status: u16, body: Value) -> Response {
        Response {
            status,
            headers: BTreeMap::new(),
            body: serde_json::to_vec(&body).unwrap(),
        }
    }

    fn selected_user(upn: &str, id: &str) -> (String, Response) {
        (
            format!(
                "/v1.0/users/{}?$select=id,displayName,userPrincipalName,mail,accountEnabled,userType",
                encode_segment(upn)
            ),
            response(
                200,
                json!({
                    "id": id,
                    "displayName": upn,
                    "userPrincipalName": upn,
                    "mail": upn,
                    "accountEnabled": true,
                    "userType": "Member"
                }),
            ),
        )
    }

    fn selected(users: &[&str]) -> PopulationConfig {
        PopulationConfig {
            scope: MemberScope::SelectedMembers {
                users: users.iter().map(|user| (*user).to_string()).collect(),
            },
        }
    }

    fn meeting_event(provider_id: &str, organizer: &str) -> Value {
        json!({
            "id": provider_id,
            "iCalUId": "SYNTHETIC-OCCURRENCE",
            "subject": "Synthetic planning",
            "start": { "dateTime": "2026-08-01T10:00:00Z", "timeZone": "UTC" },
            "end": { "dateTime": "2026-08-01T11:00:00Z", "timeZone": "UTC" },
            "organizer": { "emailAddress": { "address": organizer } },
            "attendees": [
                { "emailAddress": { "address": "alpha@example.test" }, "type": "required" },
                { "emailAddress": { "address": "beta@example.test" }, "type": "required" }
            ],
            "isOnlineMeeting": true,
            "onlineMeeting": { "joinUrl": "https://teams.example.test/meet/one" },
            "isCancelled": false,
            "categories": [],
            "type": "singleInstance",
            "seriesMasterId": null,
            "responseStatus": { "response": "accepted" }
        })
    }

    #[test]
    fn batches_member_calendars_concurrently_and_deduplicates_under_the_organizer_route() {
        let config = selected(&["alpha@example.test", "beta@example.test"]);
        let alpha = RosterMember {
            id: "user-alpha".into(),
            user_principal_name: "alpha@example.test".into(),
            display_name: Some("Alpha".into()),
            mail: Some("alpha@example.test".into()),
        };
        let beta = RosterMember {
            id: "user-beta".into(),
            user_principal_name: "beta@example.test".into(),
            display_name: Some("Beta".into()),
            mail: Some("beta@example.test".into()),
        };
        let first_calendar = calendar_path(&alpha, "2026-08-01T00:00:00Z", "2026-08-02T00:00:00Z");
        let second_calendar = calendar_path(&beta, "2026-08-01T00:00:00Z", "2026-08-02T00:00:00Z");
        let lookup = "/v1.0/users/user-beta/onlineMeetings?$filter=JoinWebUrl%20eq%20'https%3A%2F%2Fteams.example.test%2Fmeet%2Fone'";
        let mut first = ScriptTransport::new(vec![
            selected_user("alpha@example.test", "user-alpha"),
            selected_user("beta@example.test", "user-beta"),
            (
                first_calendar.clone(),
                response(200, json!({ "value": [meeting_event("copy-alpha", "beta@example.test")] })),
            ),
            (
                second_calendar.clone(),
                response(200, json!({ "value": [meeting_event("copy-beta", "beta@example.test")] })),
            ),
            (
                lookup.into(),
                response(200, json!({ "value": [{ "id": "meeting-one" }] })),
            ),
            (
                "/v1.0/users/user-beta/onlineMeetings/meeting-one/transcripts".into(),
                response(200, json!({ "value": [] })),
            ),
            (
                "/v1.0/users/user-beta/onlineMeetings/meeting-one/attendanceReports".into(),
                response(200, json!({ "value": [{ "id": "report-one" }] })),
            ),
            (
                "/v1.0/users/user-beta/onlineMeetings/meeting-one/attendanceReports/report-one/attendanceRecords".into(),
                response(200, json!({ "value": [] })),
            ),
        ]);
        let mut emitted = Vec::new();
        let batch = fetch_meeting_batch(
            &mut first,
            &config,
            "2026-08-01T00:00:00Z",
            "2026-08-02T00:00:00Z",
            None,
            |meeting| {
                emitted.push(meeting);
                Ok(())
            },
        )
        .unwrap();
        assert!(first.exhausted());
        assert_eq!(
            first.concurrent,
            [vec![first_calendar.clone(), second_calendar.clone()]]
        );
        assert_eq!(batch.item_count, 1);
        assert!(batch.unavailable_members.is_empty());
        assert_eq!(batch.completion, BatchCompletion::Complete);
        let meeting = &emitted[0];
        assert_eq!(meeting.observed_by_member_id, "user-alpha");
        assert!(matches!(
            meeting.transcript,
            ArtifactOutcome::Unavailable {
                reason: UnavailableReason::NotProduced,
                ..
            }
        ));
        assert!(matches!(
            &meeting.attendance,
            ArtifactOutcome::Observed { material }
                if material.len() == 1 && material[0].records.is_empty()
        ));
        assert_eq!(
            meeting
                .calendar_event
                .as_object()
                .expect("calendar projection")
                .keys()
                .cloned()
                .collect::<BTreeSet<_>>(),
            CALENDAR_FIELDS.split(',').map(str::to_string).collect()
        );
    }

    #[test]
    fn mailbox_unavailable_is_bounded_member_evidence_not_a_run_failure() {
        let config = selected(&["alpha@example.test", "beta@example.test"]);
        let alpha = RosterMember {
            id: "user-alpha".into(),
            user_principal_name: "alpha@example.test".into(),
            display_name: Some("Alpha".into()),
            mail: Some("alpha@example.test".into()),
        };
        let beta = RosterMember {
            id: "user-beta".into(),
            user_principal_name: "beta@example.test".into(),
            display_name: Some("Beta".into()),
            mail: Some("beta@example.test".into()),
        };
        let alpha_calendar = calendar_path(&alpha, "2026-08-01T00:00:00Z", "2026-08-02T00:00:00Z");
        let beta_calendar = calendar_path(&beta, "2026-08-01T00:00:00Z", "2026-08-02T00:00:00Z");
        let mut transport = ScriptTransport::new(vec![
            selected_user("alpha@example.test", "user-alpha"),
            selected_user("beta@example.test", "user-beta"),
            (
                alpha_calendar.clone(),
                response(
                    404,
                    json!({ "error": { "code": "MailboxNotEnabledForRESTAPI" } }),
                ),
            ),
            (beta_calendar.clone(), response(200, json!({ "value": [] }))),
        ]);

        let batch = fetch_meeting_batch(
            &mut transport,
            &config,
            "2026-08-01T00:00:00Z",
            "2026-08-02T00:00:00Z",
            None,
            |_| panic!("empty calendars must not emit meetings"),
        )
        .unwrap();

        assert!(transport.exhausted());
        assert_eq!(transport.concurrent, [vec![alpha_calendar, beta_calendar]]);
        assert_eq!(batch.item_count, 0);
        assert_eq!(batch.completion, BatchCompletion::Complete);
        assert_eq!(batch.unavailable_members.len(), 1);
        let unavailable = &batch.unavailable_members[0];
        assert_eq!(unavailable.member_id, "user-alpha");
        assert_eq!(unavailable.user_principal_name, "alpha@example.test");
        assert_eq!(
            unavailable.reason,
            MemberUnavailableReason::MailboxUnavailable
        );
        assert_eq!(
            unavailable.provider_code.as_deref(),
            Some("MailboxNotEnabledForRESTAPI")
        );
        assert!(unavailable.id.starts_with("member-observation:v1:"));
    }

    #[test]
    fn sparse_population_runs_successive_waves_until_execution_bound() {
        let users = (0..257)
            .map(|index| format!("member-{index}@example.test"))
            .collect::<Vec<_>>();
        let user_refs = users.iter().map(String::as_str).collect::<Vec<_>>();
        let config = selected(&user_refs);
        let mut members = users
            .iter()
            .enumerate()
            .map(|(index, upn)| RosterMember {
                id: format!("user-{index}"),
                user_principal_name: upn.clone(),
                display_name: Some(upn.clone()),
                mail: Some(upn.clone()),
            })
            .collect::<Vec<_>>();
        members.sort_by(|left, right| {
            left.user_principal_name
                .cmp(&right.user_principal_name)
                .then_with(|| left.id.cmp(&right.id))
        });
        let roster_exchanges = || {
            users
                .iter()
                .enumerate()
                .map(|(index, upn)| selected_user(upn, &format!("user-{index}")))
                .collect::<Vec<_>>()
        };
        let calendar_exchange = |member: &RosterMember| {
            (
                calendar_path(member, "2026-08-01T00:00:00Z", "2026-08-02T00:00:00Z"),
                response(200, json!({ "value": [] })),
            )
        };

        let mut first_exchanges = roster_exchanges();
        first_exchanges.extend(members[..256].iter().map(calendar_exchange));
        let mut first = ScriptTransport::new(first_exchanges);
        let first_batch = fetch_meeting_batch(
            &mut first,
            &config,
            "2026-08-01T00:00:00Z",
            "2026-08-02T00:00:00Z",
            None,
            |_| panic!("empty calendars must not emit meetings"),
        )
        .unwrap();
        assert!(first.exhausted());
        assert_eq!(first.concurrent.len(), MAX_CALENDAR_WAVES);
        assert!(
            first
                .concurrent
                .iter()
                .all(|wave| wave.len() == CALENDAR_BATCH_WIDTH)
        );
        assert!(
            first.concurrent[0]
                .iter()
                .all(|path| path.contains("$top=500"))
        );
        let BatchCompletion::Pending { checkpoint } = first_batch.completion else {
            panic!("member beyond the execution-wave bound must remain checkpointed");
        };

        let mut second_exchanges = roster_exchanges();
        second_exchanges.push(calendar_exchange(&members[256]));
        let mut second = ScriptTransport::new(second_exchanges);
        let second_batch = fetch_meeting_batch(
            &mut second,
            &config,
            "2026-08-01T00:00:00Z",
            "2026-08-02T00:00:00Z",
            Some(&checkpoint),
            |_| panic!("empty calendars must not emit meetings"),
        )
        .unwrap();
        assert!(second.exhausted());
        assert_eq!(second.concurrent.len(), 1);
        assert_eq!(second.concurrent[0].len(), 1);
        assert_eq!(second_batch.completion, BatchCompletion::Complete);
    }

    #[test]
    fn concurrent_retry_replays_only_retryable_positions_and_preserves_order() {
        let first = calendar_request("/v1.0/users/first/calendarView?one".into());
        let second = calendar_request("/v1.0/users/second/calendarView?two".into());
        let mut throttled = response(429, json!({ "error": { "code": "TooManyRequests" } }));
        throttled.headers.insert("retry-after".into(), "7".into());
        let mut transport = ScriptTransport::new(vec![
            (first.path.clone(), throttled),
            (
                second.path.clone(),
                response(200, json!({ "value": ["second"] })),
            ),
            (
                first.path.clone(),
                response(200, json!({ "value": ["first"] })),
            ),
        ]);

        let responses =
            request_many_with_retry(&mut transport, &[first.clone(), second.clone()]).unwrap();

        assert!(transport.exhausted());
        assert_eq!(
            transport.concurrent,
            [
                vec![first.path.clone(), second.path.clone()],
                vec![first.path]
            ]
        );
        assert_eq!(transport.sleeps, [7_000]);
        assert_eq!(
            responses[0].body,
            serde_json::to_vec(&json!({ "value": ["first"] })).unwrap()
        );
        assert_eq!(
            responses[1].body,
            serde_json::to_vec(&json!({ "value": ["second"] })).unwrap()
        );
    }

    #[test]
    fn organizer_lookup_uses_singleton_directory_and_collection_403_stays_permission() {
        let config = selected(&["alpha@example.test"]);
        let alpha = RosterMember {
            id: "user-alpha".into(),
            user_principal_name: "alpha@example.test".into(),
            display_name: Some("Alpha".into()),
            mail: Some("alpha@example.test".into()),
        };
        let mut transport = ScriptTransport::new(vec![
            selected_user("alpha@example.test", "user-alpha"),
            (
                calendar_path(
                    &alpha,
                    "2026-08-01T00:00:00Z",
                    "2026-08-02T00:00:00Z",
                ),
                response(200, json!({ "value": [meeting_event("copy-alpha", "organizer@example.test")] })),
            ),
            selected_user("organizer@example.test", "user-organizer"),
            (
                "/v1.0/users/user-organizer/onlineMeetings?$filter=JoinWebUrl%20eq%20'https%3A%2F%2Fteams.example.test%2Fmeet%2Fone'".into(),
                response(
                    403,
                    json!({ "error": { "code": "Forbidden", "innerError": { "code": "3003" } } }),
                ),
            ),
        ]);
        let mut emitted = Vec::new();
        let batch = fetch_meeting_batch(
            &mut transport,
            &config,
            "2026-08-01T00:00:00Z",
            "2026-08-02T00:00:00Z",
            None,
            |meeting| {
                emitted.push(meeting);
                Ok(())
            },
        )
        .unwrap();
        assert!(transport.exhausted());
        assert_eq!(batch.item_count, 1);
        assert!(matches!(
            &emitted[0].transcript,
            ArtifactOutcome::Unavailable {
                reason: UnavailableReason::NotPermitted,
                provider_code: Some(code),
            } if code == "3003"
        ));
        assert!(matches!(
            &emitted[0].attendance,
            ArtifactOutcome::Unavailable {
                reason: UnavailableReason::NotPermitted,
                provider_code: Some(code),
            } if code == "3003"
        ));
    }

    #[test]
    fn singleton_403_is_never_reported_as_not_found() {
        let mut transport = ScriptTransport::new(vec![(
            "/v1.0/users/alpha".into(),
            response(403, json!({ "error": { "code": "Forbidden" } })),
        )]);
        let error = get_json::<Value, _>(
            &mut transport,
            "/v1.0/users/alpha",
            MissingOutcome::NotFound,
        )
        .unwrap_err();
        assert!(matches!(
            error,
            ObservationError::Forbidden(Some(code)) if code == "Forbidden"
        ));
    }

    #[test]
    fn graph_utc_datetime_shape_has_the_same_occurrence_identity_as_rfc3339() {
        let mut graph = meeting_event("copy-one", "beta@example.test");
        graph["start"] = json!({
            "dateTime": "2026-08-01T10:00:00.0000000",
            "timeZone": "UTC"
        });
        assert_eq!(
            event_occurrence_identity(&graph).unwrap(),
            occurrence_identity("SYNTHETIC-OCCURRENCE", "2026-08-01T10:00:00Z").unwrap()
        );
    }

    #[test]
    fn checkpoint_cannot_retarget_a_different_population_member() {
        let config = selected(&["alpha@example.test"]);
        let checkpoint = serde_json::to_string(&BatchCheckpoint {
            version: 2,
            next_member_index: 1,
            pending: vec![MemberCursor {
                member_index: 0,
                page_path: "/v1.0/users/another/calendarView?$skiptoken=escape".into(),
            }],
        })
        .unwrap();
        let mut transport =
            ScriptTransport::new(vec![selected_user("alpha@example.test", "user-alpha")]);
        let error = fetch_meeting_batch(
            &mut transport,
            &config,
            "2026-08-01T00:00:00Z",
            "2026-08-02T00:00:00Z",
            Some(&checkpoint),
            |_| Ok(()),
        )
        .unwrap_err();
        assert!(error.contains("current member calendar"));
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

    #[test]
    fn durable_scope_survives_the_engine_value_boundary() {
        for config in [
            PopulationConfig {
                scope: MemberScope::AllMembers,
            },
            PopulationConfig {
                scope: MemberScope::SelectedMembers {
                    users: vec!["member@example.test".into()],
                },
            },
        ] {
            let guest_output = ron::to_string(&config).unwrap();
            let engine_value: ron::Value = ron::from_str(&guest_output).unwrap();
            let source_input = ron::to_string(&engine_value).unwrap();
            assert_eq!(PopulationConfig::parse(&source_input).unwrap(), config);
        }
    }
}
