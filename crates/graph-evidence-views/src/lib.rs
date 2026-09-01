//! Provider-shape interpretation shared by the first-party Graph evidence tools.

use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

pub const MAX_PRIMARY_BYTES: usize = 2 * 1024 * 1024;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ItemsParameters {
    pub items: Vec<String>,
}
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OccurrenceParameters {
    pub items: Vec<String>,
    pub occurrence_id: String,
}
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TranscriptParameters {
    pub item: String,
    #[serde(default)]
    pub cursor: Option<usize>,
    #[serde(default)]
    pub max_bytes: Option<usize>,
}
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MailParameters {
    pub item: String,
    #[serde(default)]
    pub cursor: Option<usize>,
    #[serde(default)]
    pub max_bytes: Option<usize>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceReadRequest {
    pub item: String,
    pub file: Option<String>,
    pub cursor: Option<usize>,
    pub max_bytes: Option<usize>,
}
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceReadManyRequest {
    pub items: Vec<EvidenceReadSelector>,
}
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceReadSelector {
    pub item: String,
    pub file: Option<String>,
    pub cursor: Option<usize>,
    pub max_bytes: Option<usize>,
}
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceReadResponse {
    pub format: String,
    pub evidence: Evidence,
}
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceReadManyResponse {
    pub format: String,
    pub evidence: Vec<Evidence>,
}
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Evidence {
    pub source: String,
    pub run_id: String,
    pub key: String,
    pub file: String,
    pub content: String,
    pub byte_start: usize,
    pub total_len: usize,
    pub hash_verified: bool,
    pub meta: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct Person {
    pub name: String,
    pub address: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub response: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub minutes: Option<u64>,
}
#[derive(Clone, Debug)]
pub struct Meeting {
    pub item: String,
    pub occurrence_id: String,
    pub subject: String,
    pub start: String,
    pub end: String,
    pub organizer_name: String,
    pub organizer_address: String,
    pub observed_by: String,
    pub is_organizer: bool,
    pub invitees: Vec<Person>,
    pub attendance: Vec<Person>,
    pub attendance_observed: bool,
    pub transcript_observed: bool,
    pub transcript: Option<String>,
}
#[derive(Debug, Serialize)]
pub struct OccurrenceView {
    pub occurrence_id: String,
    pub subject: String,
    pub start: String,
    pub end: String,
    pub organizer_name: String,
    pub organizer_address: String,
    pub invitee_count: usize,
    pub attendance_count: usize,
    pub transcript_available: bool,
    pub subjects: Vec<String>,
}
#[derive(Debug, Serialize)]
pub struct DetailView {
    pub occurrence: OccurrenceView,
    pub observations: Vec<ObservationView>,
    pub invitees: Vec<Person>,
    pub attendance: Vec<Person>,
}
#[derive(Debug, Serialize)]
pub struct ObservationView {
    pub source_item: String,
    pub observed_by: String,
    pub organizer_copy: bool,
    pub attendance_observed: bool,
    pub transcript_observed: bool,
}
#[derive(Debug, Serialize)]
pub struct TranscriptView {
    pub occurrence_id: String,
    pub source_item: String,
    pub byte_start: usize,
    pub byte_end: usize,
    pub total_bytes: usize,
    pub ended_at_cue_boundary: bool,
    pub next_cursor: Option<usize>,
    pub content: String,
}
#[derive(Debug, Serialize)]
pub struct AttendanceView {
    pub occurrence_id: String,
    pub observed: bool,
    pub people: Vec<Person>,
    pub subjects: Vec<String>,
}
#[derive(Debug, Serialize)]
pub struct MailTextView {
    pub message_id: String,
    pub subject: Option<String>,
    pub from: Address,
    pub to: Vec<Address>,
    pub cc: Vec<Address>,
    pub byte_start: usize,
    pub byte_end: usize,
    pub total_bytes: usize,
    pub next_cursor: Option<usize>,
    pub text: String,
}
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(default)]
pub struct Address {
    pub name: Option<String>,
    pub address: Option<String>,
}

#[derive(Deserialize, Default)]
#[serde(default, rename_all = "camelCase")]
struct RawMeeting {
    id: String,
    observed_by_user_principal_name: String,
    calendar_event: RawEvent,
    attendance: RawAttendance,
    transcript: RawTranscript,
}
#[derive(Deserialize, Default)]
#[serde(default, rename_all = "camelCase")]
struct RawEvent {
    attendees: Vec<RawInvitee>,
    end: RawDateTime,
    is_organizer: bool,
    organizer: RawOrganizer,
    start: RawDateTime,
    subject: String,
}
#[derive(Deserialize, Default)]
#[serde(default, rename_all = "camelCase")]
struct RawDateTime {
    date_time: String,
}
#[derive(Deserialize, Default)]
#[serde(default, rename_all = "camelCase")]
struct RawInvitee {
    email_address: RawAddress,
    status: RawStatus,
}
#[derive(Deserialize, Default)]
#[serde(default)]
struct RawOrganizer {
    #[serde(rename = "emailAddress")]
    email_address: RawAddress,
}
#[derive(Deserialize, Default)]
#[serde(default)]
struct RawAddress {
    name: String,
    address: String,
}
#[derive(Deserialize, Default)]
#[serde(default)]
struct RawStatus {
    response: Option<String>,
}
#[derive(Deserialize, Default)]
#[serde(default)]
struct RawAttendance {
    outcome: String,
    material: Vec<RawAttendanceReport>,
}
#[derive(Deserialize, Default)]
#[serde(default)]
struct RawAttendanceReport {
    records: Vec<RawAttendanceRecord>,
}
#[derive(Deserialize, Default)]
#[serde(default, rename_all = "camelCase")]
struct RawAttendanceRecord {
    email_address: String,
    identity: RawIdentity,
    total_attendance_in_seconds: Option<u64>,
}
#[derive(Deserialize, Default)]
#[serde(default, rename_all = "camelCase")]
struct RawIdentity {
    display_name: String,
}
#[derive(Deserialize, Default)]
#[serde(default)]
struct RawTranscript {
    outcome: String,
    material: Vec<RawTranscriptArtifact>,
}
#[derive(Deserialize, Default)]
#[serde(default)]
struct RawTranscriptArtifact {
    content: String,
}
#[derive(Deserialize, Default)]
#[serde(default, rename_all = "camelCase")]
struct RawMail {
    id: String,
    subject: Option<String>,
    from: Address,
    to: Vec<Address>,
    cc: Vec<Address>,
    body_preview: Option<String>,
    body: Option<String>,
}

pub fn decode<T: for<'de> Deserialize<'de>>(text: &str) -> Result<T, String> {
    ron::from_str(text).map_err(|error| error.to_string())
}
pub fn encode<T: Serialize>(value: &T) -> Result<String, String> {
    ron::ser::to_string_pretty(value, ron::ser::PrettyConfig::default())
        .map_err(|error| error.to_string())
}
pub fn quoted(value: &str) -> Result<String, String> {
    encode(&value)
}
pub fn complete_evidence<F>(mut first: Evidence, mut read: F) -> Result<Evidence, String>
where
    F: FnMut(EvidenceReadRequest) -> Result<Evidence, String>,
{
    if first.byte_start != 0 || !first.hash_verified {
        return Err("primary evidence did not begin at zero or was not verified".into());
    }
    if first.total_len > MAX_PRIMARY_BYTES {
        return Err(format!(
            "primary evidence exceeds {MAX_PRIMARY_BYTES} bytes"
        ));
    }
    while first.content.len() < first.total_len {
        let part = read(EvidenceReadRequest {
            item: first.key.clone(),
            file: None,
            cursor: Some(first.content.len()),
            max_bytes: Some(262_144),
        })?;
        if part.key != first.key
            || !part.hash_verified
            || part.byte_start != first.content.len()
            || part.content.is_empty()
        {
            return Err(
                "continued evidence was reordered, unverified, non-contiguous, or empty".into(),
            );
        }
        first.content.push_str(&part.content);
    }
    Ok(first)
}
pub fn occurrence_id(item: &str) -> String {
    item.rsplit_once('@')
        .map_or(item, |(identity, _)| identity)
        .to_string()
}

pub fn parse_meeting(
    item: &str,
    content: &str,
    retain_transcript: bool,
) -> Result<Meeting, String> {
    let raw: RawMeeting =
        serde_json::from_str(content).map_err(|error| format!("meeting JSON: {error}"))?;
    if raw.id.is_empty() || !item.starts_with("org-meeting:") {
        return Err("item is not current graph-org-meetings occurrence evidence".into());
    }
    let invitees = raw
        .calendar_event
        .attendees
        .into_iter()
        .map(|person| Person {
            name: person.email_address.name,
            address: person.email_address.address,
            response: person.status.response,
            minutes: None,
        })
        .collect();
    let attendance_observed = raw.attendance.outcome == "observed";
    let mut attendance = BTreeMap::<String, Person>::new();
    for record in raw
        .attendance
        .material
        .into_iter()
        .flat_map(|report| report.records)
    {
        let key = if record.email_address.is_empty() {
            format!("name:{}", record.identity.display_name.to_ascii_lowercase())
        } else {
            record.email_address.to_ascii_lowercase()
        };
        let person = Person {
            name: record.identity.display_name,
            address: record.email_address,
            response: None,
            minutes: record
                .total_attendance_in_seconds
                .map(|seconds| (seconds + 30) / 60),
        };
        attendance
            .entry(key)
            .and_modify(|old| old.minutes = old.minutes.max(person.minutes))
            .or_insert(person);
    }
    let transcript_observed = raw.transcript.outcome == "observed";
    let transcript = retain_transcript
        .then(|| {
            raw.transcript
                .material
                .into_iter()
                .map(|part| part.content)
                .max_by_key(String::len)
        })
        .flatten();
    Ok(Meeting {
        item: item.into(),
        occurrence_id: occurrence_id(item),
        subject: raw.calendar_event.subject,
        start: raw.calendar_event.start.date_time,
        end: raw.calendar_event.end.date_time,
        organizer_name: raw.calendar_event.organizer.email_address.name,
        organizer_address: raw.calendar_event.organizer.email_address.address,
        observed_by: raw.observed_by_user_principal_name,
        is_organizer: raw.calendar_event.is_organizer,
        invitees,
        attendance: attendance.into_values().collect(),
        attendance_observed,
        transcript_observed,
        transcript,
    })
}

pub fn group(meetings: Vec<Meeting>) -> BTreeMap<String, Vec<Meeting>> {
    let mut groups = BTreeMap::new();
    for meeting in meetings {
        groups
            .entry(meeting.occurrence_id.clone())
            .or_insert_with(Vec::new)
            .push(meeting);
    }
    groups
}
fn person_key(person: &Person) -> String {
    if person.address.is_empty() {
        format!("name:{}", person.name.to_ascii_lowercase())
    } else {
        person.address.to_ascii_lowercase()
    }
}
fn canonical(meetings: &[Meeting]) -> &Meeting {
    meetings
        .iter()
        .max_by_key(|m| {
            (
                m.transcript.as_ref().map_or(0, String::len),
                m.attendance.len(),
                m.is_organizer,
            )
        })
        .expect("non-empty occurrence")
}

pub fn occurrence_view(id: &str, meetings: &[Meeting]) -> OccurrenceView {
    let selected = canonical(meetings);
    let invitees = meetings
        .iter()
        .flat_map(|m| &m.invitees)
        .map(person_key)
        .collect::<BTreeSet<_>>();
    let attendance = meetings
        .iter()
        .flat_map(|m| &m.attendance)
        .map(person_key)
        .collect::<BTreeSet<_>>();
    OccurrenceView {
        occurrence_id: id.into(),
        subject: selected.subject.clone(),
        start: selected.start.clone(),
        end: selected.end.clone(),
        organizer_name: selected.organizer_name.clone(),
        organizer_address: selected.organizer_address.clone(),
        invitee_count: invitees.len(),
        attendance_count: attendance.len(),
        transcript_available: meetings.iter().any(|m| m.transcript_observed),
        subjects: meetings.iter().map(|m| m.item.clone()).collect(),
    }
}
pub fn detail_view(id: &str, meetings: &[Meeting]) -> DetailView {
    let mut invitees = BTreeMap::new();
    let mut attendance = BTreeMap::new();
    for meeting in meetings {
        for person in &meeting.invitees {
            invitees
                .entry(person_key(person))
                .or_insert_with(|| person.clone());
        }
        for person in &meeting.attendance {
            attendance
                .entry(person_key(person))
                .and_modify(|old: &mut Person| old.minutes = old.minutes.max(person.minutes))
                .or_insert_with(|| person.clone());
        }
    }
    DetailView {
        occurrence: occurrence_view(id, meetings),
        observations: meetings
            .iter()
            .map(|m| ObservationView {
                source_item: m.item.clone(),
                observed_by: m.observed_by.clone(),
                organizer_copy: m.is_organizer,
                attendance_observed: m.attendance_observed,
                transcript_observed: m.transcript_observed,
            })
            .collect(),
        invitees: invitees.into_values().collect(),
        attendance: attendance.into_values().collect(),
    }
}
pub fn attendance_view(id: &str, meetings: &[Meeting]) -> AttendanceView {
    let detail = detail_view(id, meetings);
    AttendanceView {
        occurrence_id: id.into(),
        observed: meetings.iter().any(|m| m.attendance_observed),
        people: detail.attendance,
        subjects: meetings.iter().map(|m| m.item.clone()).collect(),
    }
}

pub fn transcript_view(
    meeting: &Meeting,
    cursor: usize,
    max_bytes: usize,
) -> Result<TranscriptView, String> {
    let text = meeting
        .transcript
        .as_deref()
        .ok_or("meeting has no retained transcript")?;
    if cursor > text.len() {
        return Err("cursor exceeds transcript length".into());
    }
    let mut start = cursor;
    while start < text.len() && !text.is_char_boundary(start) {
        start += 1;
    }
    let mut end = (start + max_bytes).min(text.len());
    while end > start && !text.is_char_boundary(end) {
        end -= 1;
    }
    let mut cue = end == text.len();
    if end < text.len() {
        let page = &text[start..end];
        let boundary = page
            .rfind("\r\n\r\n")
            .map(|at| start + at + 4)
            .into_iter()
            .chain(page.rfind("\n\n").map(|at| start + at + 2))
            .max();
        if let Some(boundary) = boundary.filter(|boundary| boundary.saturating_sub(start) >= 1024) {
            end = boundary;
            cue = true;
        }
    }
    Ok(TranscriptView {
        occurrence_id: meeting.occurrence_id.clone(),
        source_item: meeting.item.clone(),
        byte_start: start,
        byte_end: end,
        total_bytes: text.len(),
        ended_at_cue_boundary: cue,
        next_cursor: (end < text.len()).then_some(end),
        content: text[start..end].into(),
    })
}

pub fn mail_text(content: &str, cursor: usize, max_bytes: usize) -> Result<MailTextView, String> {
    let mail: RawMail =
        serde_json::from_str(content).map_err(|error| format!("mail JSON: {error}"))?;
    if mail.id.is_empty() {
        return Err("item is not current graph-mail evidence".into());
    }
    let raw = mail.body.or(mail.body_preview).unwrap_or_default();
    let text = html_text(&raw);
    if cursor > text.len() {
        return Err("cursor exceeds message text length".into());
    }
    let mut start = cursor;
    while start < text.len() && !text.is_char_boundary(start) {
        start += 1;
    }
    let mut end = (start + max_bytes).min(text.len());
    while end > start && !text.is_char_boundary(end) {
        end -= 1;
    }
    Ok(MailTextView {
        message_id: mail.id,
        subject: mail.subject,
        from: mail.from,
        to: mail.to,
        cc: mail.cc,
        byte_start: start,
        byte_end: end,
        total_bytes: text.len(),
        next_cursor: (end < text.len()).then_some(end),
        text: text[start..end].into(),
    })
}

fn html_text(input: &str) -> String {
    let mut out = String::new();
    let mut tag = false;
    for ch in input.chars() {
        match ch {
            '<' => tag = true,
            '>' => {
                tag = false;
                out.push(' ');
            }
            _ if !tag => out.push(ch),
            _ => {}
        }
    }
    for (from, to) in [
        ("&nbsp;", " "),
        ("&lt;", "<"),
        ("&gt;", ">"),
        ("&quot;", "\""),
        ("&#39;", "'"),
        ("&amp;", "&"),
    ] {
        out = out.replace(from, to);
    }
    out.split_whitespace().collect::<Vec<_>>().join(" ")
}

#[cfg(test)]
mod tests {
    use super::*;
    use graph_population::{
        ArtifactOutcome, AttendanceArtifact, PopulationMeeting, TranscriptArtifact,
    };
    use serde_json::json;
    fn meeting(id: &str, start: &str) -> String {
        format!(
            r#"{{"id":"{id}","observedByUserPrincipalName":"a@example.test","calendarEvent":{{"subject":"Weekly","start":{{"dateTime":"{start}"}},"end":{{"dateTime":"{start}"}},"isOrganizer":true,"organizer":{{"emailAddress":{{"name":"A","address":"a@example.test"}}}},"attendees":[]}},"attendance":{{"outcome":"unavailable"}},"transcript":{{"outcome":"unavailable"}}}}"#
        )
    }
    #[test]
    fn recurrence_dates_stay_distinct() {
        let a = parse_meeting(
            "org-meeting:occurrence:v1:first@a",
            &meeting("first", "2026-08-25"),
            false,
        )
        .unwrap();
        let b = parse_meeting(
            "org-meeting:occurrence:v1:second@a",
            &meeting("second", "2026-08-27"),
            false,
        )
        .unwrap();
        assert_eq!(group(vec![a, b]).len(), 2);
    }
    #[test]
    fn observer_copies_of_one_occurrence_consolidate() {
        let first = parse_meeting(
            "org-meeting:occurrence:v1:first@version-a",
            &meeting("first", "2026-08-25"),
            false,
        )
        .unwrap();
        let second = parse_meeting(
            "org-meeting:occurrence:v1:first@version-b",
            &meeting("first", "2026-08-25"),
            false,
        )
        .unwrap();
        let groups = group(vec![first, second]);
        let view = occurrence_view(
            "org-meeting:occurrence:v1:first",
            &groups["org-meeting:occurrence:v1:first"],
        );
        assert_eq!(view.subjects.len(), 2);
    }
    #[test]
    fn transcript_pages_end_at_a_complete_cue() {
        let mut parsed = parse_meeting(
            "org-meeting:occurrence:v1:first@version-a",
            &meeting("first", "2026-08-25"),
            false,
        )
        .unwrap();
        parsed.transcript = Some(format!(
            "WEBVTT\n\n00:00.000 --> 00:01.000\n{}\n\n00:01.000 --> 00:02.000\nsecond cue",
            "a".repeat(1_100)
        ));
        let page = transcript_view(&parsed, 0, 1_150).unwrap();
        assert!(page.ended_at_cue_boundary);
        assert!(page.content.ends_with("\n\n"));
        assert_eq!(page.next_cursor, Some(page.byte_end));
    }
    #[test]
    fn population_producer_round_trips_into_the_meeting_view() {
        let produced = PopulationMeeting {
            id: "occurrence:v1:producer-proof".into(),
            observed_by_member_id: "member-1".into(),
            observed_by_user_principal_name: "observer@example.test".into(),
            provider_event_id: "event-1".into(),
            calendar_event: json!({
                "subject": "Architecture handover",
                "start": {"dateTime": "2026-08-25T08:00:00Z"},
                "end": {"dateTime": "2026-08-25T09:00:00Z"},
                "isOrganizer": true,
                "organizer": {"emailAddress": {"name": "Ada", "address": "ada@example.test"}},
                "attendees": [{
                    "emailAddress": {"name": "Grace", "address": "grace@example.test"},
                    "status": {"response": "accepted"}
                }]
            }),
            online_meeting: None,
            transcript: ArtifactOutcome::Observed {
                material: vec![TranscriptArtifact {
                    id: "transcript-1".into(),
                    created_date_time: "2026-08-25T09:00:00Z".into(),
                    end_date_time: "2026-08-25T09:01:00Z".into(),
                    media_type: "text/vtt".into(),
                    content: "WEBVTT\n\n00:00.000 --> 00:01.000\nWelcome".into(),
                }],
            },
            attendance: ArtifactOutcome::Observed {
                material: vec![AttendanceArtifact {
                    report_id: "report-1".into(),
                    meeting_start_date_time: "2026-08-25T08:00:00Z".into(),
                    meeting_end_date_time: "2026-08-25T09:00:00Z".into(),
                    records: vec![json!({
                        "emailAddress": "grace@example.test",
                        "identity": {"displayName": "Grace"},
                        "totalAttendanceInSeconds": 3570
                    })],
                }],
            },
        };
        let encoded = serde_json::to_string(&produced).unwrap();
        let parsed = parse_meeting(
            "org-meeting:occurrence:v1:producer-proof@version",
            &encoded,
            true,
        )
        .unwrap();
        assert_eq!(parsed.subject, "Architecture handover");
        assert_eq!(parsed.organizer_name, "Ada");
        assert_eq!(parsed.organizer_address, "ada@example.test");
        assert_eq!(parsed.invitees[0].response.as_deref(), Some("accepted"));
        assert_eq!(parsed.attendance[0].minutes, Some(60));
        assert!(parsed.transcript.unwrap().contains("Welcome"));
    }
    #[test]
    fn html_entities_decode_once() {
        assert_eq!(
            html_text("<p>&amp;lt; hello&nbsp;world</p>"),
            "&lt; hello world"
        );
    }
    #[test]
    fn mail_cursor_advances_to_a_character_boundary() {
        let view = mail_text(r#"{"id":"mail-1","body":"éx"}"#, 1, 16).unwrap();
        assert_eq!(view.byte_start, 2);
        assert_eq!(view.text, "x");
    }
}
