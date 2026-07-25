#[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
mod guest {
    mod bindings {
        wit_bindgen::generate!({
            path: "../../wit",
            world: "tap",
        });
    }

    use bindings::exports::kyyn::tap::api::{
        AuthChallenge, AuthPollResult, AuthStatus, FetchRequest, FetchResult, FetchStyle, Guest,
        Item, PluginDescribe, RunSpec,
    };
    use bindings::kyyn::tap::http::{self, Method, Request, Response};
    use bindings::kyyn::tap::{control, evidence, secrets};
    use serde::{Deserialize, Serialize};
    use sha2::Digest as _;

    const ACCESS_TOKEN: &str = "ms-access-token";
    const REFRESH_TOKEN: &str = "ms-refresh-token";
    const DEFAULT_CLIENT_ID: &str = "53ddb21b-849f-45a3-8168-8a0e555f386f";
    const SCOPES: &str = "Mail.Read Calendars.Read User.Read Chat.Read \
        OnlineMeetings.Read OnlineMeetingTranscript.Read.All \
        OnlineMeetingArtifact.Read.All Files.Read.All Sites.Read.All offline_access";
    const RESPONSE_CAP: u64 = 64 * 1024 * 1024;
    const MAX_PAGES: u32 = 500;

    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Config {
        #[serde(default = "default_client_id")]
        client_id: String,
        #[serde(default = "default_tenant")]
        tenant: String,
        #[serde(default)]
        owner_addresses: Vec<String>,
        #[serde(default, deserialize_with = "opt_string_lenient")]
        mail_filter: Option<String>,
        #[serde(default, deserialize_with = "opt_string_lenient")]
        url: Option<String>,
        #[serde(default = "default_patterns")]
        patterns: Vec<String>,
        #[serde(default = "default_kind")]
        kind: String,
        #[serde(default = "default_max_file_bytes")]
        max_file_bytes: u64,
    }

    fn default_client_id() -> String {
        DEFAULT_CLIENT_ID.into()
    }

    fn default_tenant() -> String {
        "organizations".into()
    }

    fn opt_string_lenient<'de, D>(deserializer: D) -> Result<Option<String>, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum Lenient {
            Optional(Option<String>),
            Bare(String),
        }
        Ok(match Lenient::deserialize(deserializer)? {
            Lenient::Optional(value) => value,
            Lenient::Bare(value) => Some(value),
        })
    }

    fn parse_config(text: &str) -> Result<Config, String> {
        let value: ron::Value =
            ron::from_str(text).map_err(|error| format!("graph config: {error}"))?;
        if matches!(value, ron::Value::Unit) {
            return Ok(Config {
                client_id: default_client_id(),
                tenant: default_tenant(),
                owner_addresses: Vec::new(),
                mail_filter: None,
                url: None,
                patterns: default_patterns(),
                kind: default_kind(),
                max_file_bytes: default_max_file_bytes(),
            });
        }
        value.into_rust().map_err(|error| {
            format!(
                "graph config shape (optional client_id, tenant, owner_addresses; \
                 mail_filter is mail-only): {error}"
            )
        })
    }

    fn default_patterns() -> Vec<String> {
        vec!["**/*".into()]
    }

    fn default_kind() -> String {
        "file".into()
    }

    fn default_max_file_bytes() -> u64 {
        64 * 1024 * 1024
    }

    fn validate(config: &Config) -> Result<(), String> {
        if config.client_id.trim().is_empty() {
            return Err("client_id must not be empty".into());
        }
        if config.tenant.trim().is_empty()
            || !config
                .tenant
                .chars()
                .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '-' | '.'))
        {
            return Err("tenant must be a tenant id or organizations".into());
        }
        if super::PLUGIN_KIND != "mail" && config.mail_filter.is_some() {
            return Err(format!(
                "mail_filter applies to graph-mail, not {}",
                super::PLUGIN_NAME
            ));
        }
        if super::PLUGIN_KIND == "sharepoint" {
            let url = config.url.as_deref().ok_or("sharepoint url is required")?;
            if !url.starts_with("https://") {
                return Err("sharepoint url must be an https:// URL".into());
            }
            for pattern in &config.patterns {
                glob::Pattern::new(pattern)
                    .map_err(|error| format!("pattern '{pattern}': {error}"))?;
            }
            if config.kind.is_empty()
                || !config
                    .kind
                    .chars()
                    .all(|ch| ch.is_ascii_alphanumeric() || ch == '-')
            {
                return Err(format!("kind '{}' must be a bare token", config.kind));
            }
        } else if config.url.is_some()
            || config.patterns != default_patterns()
            || config.kind != default_kind()
            || config.max_file_bytes != default_max_file_bytes()
        {
            return Err(format!(
                "url, patterns, kind and max_file_bytes apply to sharepoint-file, not {}",
                super::PLUGIN_NAME
            ));
        }
        Ok(())
    }

    fn percent_encode(value: &str) -> String {
        let mut encoded = String::with_capacity(value.len() * 3);
        for byte in value.bytes() {
            match byte {
                b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                    encoded.push(byte as char)
                }
                _ => encoded.push_str(&format!("%{byte:02X}")),
            }
        }
        encoded
    }

    fn form(fields: &[(&str, &str)]) -> Vec<u8> {
        fields
            .iter()
            .map(|(name, value)| format!("{}={}", percent_encode(name), percent_encode(value)))
            .collect::<Vec<_>>()
            .join("&")
            .into_bytes()
    }

    fn identity_url(config: &Config, endpoint: &str) -> String {
        format!(
            "https://login.microsoftonline.com/{}/oauth2/v2.0/{endpoint}",
            config.tenant
        )
    }

    fn request(
        method: Method,
        url: String,
        body: Option<Vec<u8>>,
        authorization: Option<&str>,
    ) -> Request {
        Request {
            method,
            url,
            headers: vec![
                ("accept".into(), "application/json".into()),
                (
                    "content-type".into(),
                    "application/x-www-form-urlencoded".into(),
                ),
                ("prefer".into(), "outlook.body-content-type=\"text\"".into()),
            ],
            body,
            secret_authorization: authorization.map(str::to_string),
            max_response_bytes: RESPONSE_CAP,
            timeout_ms: 120_000,
        }
    }

    fn json(response: &Response) -> Result<serde_json::Value, String> {
        serde_json::from_slice(&response.body)
            .map_err(|error| format!("invalid Graph JSON (HTTP {}): {error}", response.status))
    }

    fn refresh(config: &Config) -> Result<(), String> {
        let refresh = secrets::get(REFRESH_TOKEN)
            .ok_or("token expired and no refresh token — sign in again")?;
        let refresh =
            std::str::from_utf8(&refresh).map_err(|_| "stored refresh token is not UTF-8")?;
        let response = http::fetch(&request(
            Method::Post,
            identity_url(config, "token"),
            Some(form(&[
                ("grant_type", "refresh_token"),
                ("client_id", &config.client_id),
                ("refresh_token", refresh),
                ("scope", SCOPES),
            ])),
            None,
        ))
        .map_err(|error| error.message)?;
        let body = json(&response)?;
        let token = body["access_token"]
            .as_str()
            .ok_or_else(|| format!("token refresh failed — sign in again ({body})"))?;
        secrets::put(ACCESS_TOKEN, token.as_bytes())?;
        if let Some(rotated) = body["refresh_token"].as_str() {
            secrets::put(REFRESH_TOKEN, rotated.as_bytes())?;
        }
        Ok(())
    }

    fn graph_response(
        config: &Config,
        url: &str,
        refreshed: &mut bool,
    ) -> Result<Response, String> {
        for attempt in 1..=5u64 {
            let response = http::fetch(&request(Method::Get, url.into(), None, Some(ACCESS_TOKEN)))
                .map_err(|error| error.message)?;
            if response.status == 401 && !*refreshed {
                refresh(config)?;
                *refreshed = true;
                continue;
            }
            if response.status == 429 && attempt < 5 {
                let retry_after = response
                    .headers
                    .iter()
                    .find(|(name, _)| name.eq_ignore_ascii_case("retry-after"))
                    .and_then(|(_, value)| value.parse::<u64>().ok())
                    .unwrap_or(5)
                    .min(60);
                control::progress(&format!(
                    "Graph rate limit; retrying after {retry_after}s ({attempt}/5)"
                ));
                control::sleep_ms(retry_after * 1_000);
                continue;
            }
            if response.status >= 500 && attempt < 5 {
                let delay = (1u64 << attempt).min(30);
                control::progress(&format!(
                    "Graph HTTP {}; retrying after {delay}s ({attempt}/5)",
                    response.status
                ));
                control::sleep_ms(delay * 1_000);
                continue;
            }
            return Ok(response);
        }
        Err(format!("Graph GET exhausted retries for {url}"))
    }

    fn graph_get(config: &Config, url: &str, refreshed: &mut bool) -> Result<Response, String> {
        let response = graph_response(config, url, refreshed)?;
        if !(200..300).contains(&response.status) {
            return Err(format!(
                "Graph GET failed (HTTP {}) for {url}",
                response.status
            ));
        }
        Ok(response)
    }

    fn graph_pages(config: &Config, first_url: String) -> Result<Vec<serde_json::Value>, String> {
        if secrets::get(ACCESS_TOKEN).is_none() {
            return Err("no token — sign the realm in first".into());
        }
        let mut records = Vec::new();
        let mut next = Some(first_url);
        let mut refreshed = false;
        let mut pages = 0u32;
        while let Some(url) = next.take() {
            let body = json(&graph_get(config, &url, &mut refreshed)?)?;
            let values = body["value"]
                .as_array()
                .ok_or_else(|| "Graph collection has no value array".to_string())?;
            records.extend(values.iter().cloned());
            next = body["@odata.nextLink"].as_str().map(str::to_string);
            pages += 1;
            if next.is_some() {
                control::progress(&format!("{} records ({pages} pages)…", records.len()));
            }
            if pages >= MAX_PAGES {
                return Err("Graph paging exceeded 500 pages — aborting".into());
            }
        }
        Ok(records)
    }

    #[derive(Deserialize, Serialize)]
    #[serde(rename_all = "camelCase")]
    struct DateTimeTimeZone {
        date_time: String,
        time_zone: String,
    }

    #[derive(Deserialize, Serialize)]
    struct EmailAddress {
        name: Option<String>,
        address: Option<String>,
    }

    #[derive(Deserialize, Serialize)]
    #[serde(rename_all = "camelCase")]
    struct Recipient {
        email_address: EmailAddress,
    }

    #[derive(Deserialize, Serialize)]
    #[serde(rename_all = "camelCase")]
    struct Attendee {
        email_address: EmailAddress,
    }

    #[derive(Deserialize, Serialize)]
    #[serde(rename_all = "camelCase")]
    struct Location {
        display_name: Option<String>,
    }

    #[derive(Deserialize, Serialize)]
    #[serde(rename_all = "camelCase")]
    struct OnlineMeetingInfo {
        join_url: Option<String>,
    }

    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct GraphEvent {
        id: String,
        subject: Option<String>,
        start: DateTimeTimeZone,
        end: DateTimeTimeZone,
        organizer: Option<Recipient>,
        #[serde(default)]
        attendees: Vec<Attendee>,
        is_online_meeting: Option<bool>,
        location: Option<Location>,
        online_meeting: Option<OnlineMeetingInfo>,
    }

    #[derive(Serialize)]
    #[serde(rename_all = "camelCase")]
    struct Event {
        id: String,
        subject: Option<String>,
        start: String,
        end: String,
        organizer: Option<EmailAddress>,
        attendees: Vec<EmailAddress>,
        teams: bool,
        location: Option<String>,
        transcript_file: Option<String>,
        attendance_file: Option<String>,
    }

    fn calendar_url(start: &str, until: &str) -> String {
        format!(
            "https://graph.microsoft.com/v1.0/me/calendarView\
             ?startDateTime={}&endDateTime={}\
             &$select=id,subject,start,end,organizer,attendees,isOnlineMeeting,location,onlineMeeting\
             &$top=50",
            percent_encode(start),
            percent_encode(until)
        )
    }

    fn fetch_calendar(config: &Config, start: &str, until: &str) -> Result<FetchResult, String> {
        let raw = graph_pages(config, calendar_url(start, until))?;
        let mut events = raw
            .into_iter()
            .map(serde_json::from_value::<GraphEvent>)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|error| format!("calendar event shape: {error}"))?;
        events.sort_by(|left, right| left.start.date_time.cmp(&right.start.date_time));
        events.dedup_by(|left, right| left.id == right.id);
        let events: Vec<Event> = events
            .into_iter()
            .map(|event| Event {
                id: event.id,
                subject: event.subject,
                start: event.start.date_time,
                end: event.end.date_time,
                organizer: event.organizer.map(|value| value.email_address),
                attendees: event
                    .attendees
                    .into_iter()
                    .map(|value| value.email_address)
                    .collect(),
                teams: event.is_online_meeting.unwrap_or(false),
                location: event.location.and_then(|value| value.display_name),
                transcript_file: None,
                attendance_file: None,
            })
            .collect();
        let bundle = serde_json::to_vec_pretty(&events).map_err(|error| error.to_string())?;
        let file = evidence::open("events.json")?;
        file.write(&bundle)?;
        let _stored = file.finish()?;
        let items = events
            .iter()
            .map(|event| {
                Ok(Item {
                    id: event.id.clone(),
                    kind: "event".into(),
                    version: None,
                    content_hash: kyyn_plugin_bundle::canonical_record_sha256(event)
                        .map_err(|error| error.to_string())?,
                    files: vec!["events.json".into()],
                    file_hashes: Vec::new(),
                    locator: Some(event.id.clone()),
                    meta: event.subject.clone().unwrap_or_default(),
                })
            })
            .collect::<Result<Vec<_>, String>>()?;
        control::progress(&format!("{} events in window", items.len()));
        Ok(FetchResult {
            notes: format!("{} events", items.len()),
            items,
            next_checkpoint: None,
        })
    }

    #[derive(Deserialize, Serialize)]
    #[serde(rename_all = "camelCase")]
    struct MessageBody {
        #[allow(dead_code)]
        content_type: String,
        content: String,
    }

    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct GraphMessage {
        id: String,
        conversation_id: Option<String>,
        received_date_time: String,
        subject: Option<String>,
        body_preview: Option<String>,
        body: Option<MessageBody>,
        from: Option<Recipient>,
        #[serde(default)]
        to_recipients: Vec<Recipient>,
        #[serde(default)]
        cc_recipients: Vec<Recipient>,
        has_attachments: Option<bool>,
    }

    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct GraphAttachment {
        id: String,
        #[serde(rename = "@odata.type")]
        odata_type: Option<String>,
        name: Option<String>,
        content_type: Option<String>,
        size: Option<u64>,
        is_inline: Option<bool>,
    }

    #[derive(Serialize)]
    enum Direction {
        Sent,
        Received,
    }

    #[derive(Serialize)]
    #[serde(rename_all = "camelCase")]
    struct Attachment {
        name: String,
        content_type: Option<String>,
        size: Option<u64>,
        #[serde(skip_serializing_if = "Option::is_none")]
        file: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        sha256: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        skipped: Option<String>,
    }

    #[derive(Serialize)]
    #[serde(rename_all = "camelCase")]
    struct Email {
        id: String,
        thread_id: Option<String>,
        received_date_time: String,
        direction: Direction,
        from: EmailAddress,
        to: Vec<EmailAddress>,
        cc: Vec<EmailAddress>,
        subject: Option<String>,
        body_preview: Option<String>,
        body: Option<String>,
        #[serde(skip_serializing_if = "Vec::is_empty")]
        attachments: Vec<Attachment>,
    }

    fn messages_url(config: &Config, start: &str, until: &str) -> String {
        let narrowing = config
            .mail_filter
            .as_deref()
            .map(|value| format!("%20and%20({})", percent_encode(value)))
            .unwrap_or_default();
        format!(
            "https://graph.microsoft.com/v1.0/me/messages\
             ?$select=id,conversationId,receivedDateTime,subject,bodyPreview,body,from,toRecipients,ccRecipients,hasAttachments\
             &$orderby=receivedDateTime%20desc&$top=50\
             &$filter=receivedDateTime%20ge%20{}%20and%20receivedDateTime%20lt%20{}{narrowing}",
            percent_encode(start),
            percent_encode(until)
        )
    }

    fn attachments_url(message_id: &str) -> String {
        format!(
            "https://graph.microsoft.com/v1.0/me/messages/{message_id}/attachments\
             ?$select=id,name,contentType,size,isInline"
        )
    }

    fn attachment_value_url(message_id: &str, attachment_id: &str) -> String {
        format!(
            "https://graph.microsoft.com/v1.0/me/messages/{message_id}/attachments/{attachment_id}/$value"
        )
    }

    fn is_own_address(config: &Config, address: Option<&str>) -> bool {
        address.is_some_and(|address| {
            config
                .owner_addresses
                .iter()
                .any(|own| own.eq_ignore_ascii_case(address))
        })
    }

    fn safe_attachment_name(id: &str, name: &str) -> String {
        let basename = name.rsplit(['/', '\\']).next().unwrap_or("attachment");
        let basename: String = basename
            .chars()
            .map(|ch| if ch.is_control() { '_' } else { ch })
            .collect();
        let digest = format!("{:x}", sha2::Sha256::digest(id.as_bytes()));
        format!("{}-{basename}", &digest[..8])
    }

    fn fetch_attachments(
        config: &Config,
        message_id: &str,
    ) -> Result<Vec<Attachment>, String> {
        const MAX_ATTACHMENT_BYTES: u64 = 32 * 1024 * 1024;
        let raw = graph_pages(config, attachments_url(message_id))?;
        let metas = raw
            .into_iter()
            .map(serde_json::from_value::<GraphAttachment>)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|error| format!("attachment shape: {error}"))?;
        let mut attachments = Vec::new();
        for meta in metas {
            if meta.is_inline.unwrap_or(false) {
                continue;
            }
            let name = meta.name.unwrap_or_else(|| meta.id.clone());
            let mut attachment = Attachment {
                name: name.clone(),
                content_type: meta.content_type,
                size: meta.size,
                file: None,
                sha256: None,
                skipped: None,
            };
            if meta.odata_type.as_deref() != Some("#microsoft.graph.fileAttachment") {
                attachment.skipped = Some(format!(
                    "not a file attachment ({})",
                    meta.odata_type.as_deref().unwrap_or("unknown type")
                ));
            } else if meta.size.unwrap_or(0) > MAX_ATTACHMENT_BYTES {
                attachment.skipped = Some("over the 32MB cap".into());
            } else {
                let relative =
                    format!("attachments/{}", safe_attachment_name(&meta.id, &name));
                let url = attachment_value_url(message_id, &meta.id);
                let mut attachment_request =
                    request(Method::Get, url.clone(), None, Some(ACCESS_TOKEN));
                attachment_request.max_response_bytes = MAX_ATTACHMENT_BYTES;
                let mut response =
                    http::fetch(&attachment_request).map_err(|error| error.message)?;
                if response.status == 401 {
                    refresh(config)?;
                    response = http::fetch(&attachment_request).map_err(|error| error.message)?;
                }
                match response.status {
                    200..=299 => {
                        let file = evidence::open(&relative)?;
                        file.write(&response.body)?;
                        let stored = file.finish()?;
                        attachment.file = Some(relative);
                        attachment.sha256 = Some(stored.sha256);
                        attachment.size = Some(stored.bytes);
                    }
                    403 => attachment.skipped = Some("access denied".into()),
                    404 => attachment.skipped = Some("gone at fetch time".into()),
                    status => {
                        return Err(format!(
                            "attachment fetch failed (HTTP {status}) for message {message_id}"
                        ));
                    }
                }
            }
            attachments.push(attachment);
        }
        Ok(attachments)
    }

    fn fetch_mail(config: &Config, start: &str, until: &str) -> Result<FetchResult, String> {
        let raw = graph_pages(config, messages_url(config, start, until))?;
        let mut messages = raw
            .into_iter()
            .map(serde_json::from_value::<GraphMessage>)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|error| format!("mail message shape: {error}"))?;
        messages.sort_by(|left, right| {
            right
                .received_date_time
                .cmp(&left.received_date_time)
                .then_with(|| left.id.cmp(&right.id))
        });
        messages.dedup_by(|left, right| left.id == right.id);
        let with_attachments = messages
            .iter()
            .filter(|message| message.has_attachments.unwrap_or(false))
            .count();
        let mut attachment_number = 0usize;
        let mut emails = Vec::with_capacity(messages.len());
        for message in messages {
            let sender = message
                .from
                .as_ref()
                .and_then(|recipient| recipient.email_address.address.as_deref());
            let direction = if is_own_address(config, sender) {
                Direction::Sent
            } else {
                Direction::Received
            };
            let attachments = if message.has_attachments.unwrap_or(false) {
                attachment_number += 1;
                control::progress(&format!(
                    "attachments {attachment_number} of {with_attachments}: {}",
                    message.subject.as_deref().unwrap_or("(no subject)")
                ));
                fetch_attachments(config, &message.id)?
            } else {
                Vec::new()
            };
            emails.push(Email {
                id: message.id,
                thread_id: message.conversation_id,
                received_date_time: message.received_date_time,
                direction,
                from: message
                    .from
                    .map(|recipient| recipient.email_address)
                    .unwrap_or(EmailAddress {
                        name: None,
                        address: None,
                    }),
                to: message
                    .to_recipients
                    .into_iter()
                    .map(|recipient| recipient.email_address)
                    .collect(),
                cc: message
                    .cc_recipients
                    .into_iter()
                    .map(|recipient| recipient.email_address)
                    .collect(),
                subject: message.subject,
                body_preview: message.body_preview,
                body: message.body.map(|body| body.content),
                attachments,
            });
        }
        let bundle = serde_json::to_vec_pretty(&emails).map_err(|error| error.to_string())?;
        let file = evidence::open("emails.json")?;
        file.write(&bundle)?;
        let _stored = file.finish()?;
        let items = emails
            .iter()
            .map(|email| {
                Ok(Item {
                    id: email.id.clone(),
                    kind: "email".into(),
                    version: None,
                    content_hash: kyyn_plugin_bundle::canonical_record_sha256(email)
                        .map_err(|error| error.to_string())?,
                    files: std::iter::once("emails.json".into())
                        .chain(
                            email
                                .attachments
                                .iter()
                                .filter_map(|attachment| attachment.file.clone()),
                        )
                        .collect(),
                    file_hashes: email
                        .attachments
                        .iter()
                        .filter_map(|attachment| {
                            Some((attachment.file.clone()?, attachment.sha256.clone()?))
                        })
                        .collect(),
                    locator: Some(email.id.clone()),
                    meta: email.subject.clone().unwrap_or_default(),
                })
            })
            .collect::<Result<Vec<_>, String>>()?;
        control::progress(&format!("{} messages in window", items.len()));
        Ok(FetchResult {
            notes: format!("{} emails", items.len()),
            items,
            next_checkpoint: None,
        })
    }

    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct ChatUser {
        display_name: Option<String>,
    }

    #[derive(Deserialize)]
    struct ChatMessageFrom {
        user: Option<ChatUser>,
    }

    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct GraphChatMessage {
        id: String,
        message_type: Option<String>,
        created_date_time: String,
        from: Option<ChatMessageFrom>,
        body: Option<MessageBody>,
    }

    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct ChatMember {
        display_name: Option<String>,
        email: Option<String>,
    }

    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct GraphChat {
        id: String,
        topic: Option<String>,
        chat_type: Option<String>,
        #[serde(default)]
        members: Vec<ChatMember>,
    }

    #[derive(Serialize)]
    #[serde(rename_all = "camelCase")]
    struct ChatMessage {
        id: String,
        created_date_time: String,
        from: Option<String>,
        body: Option<String>,
    }

    #[derive(Serialize)]
    #[serde(rename_all = "camelCase")]
    struct Chat {
        id: String,
        topic: Option<String>,
        chat_type: Option<String>,
        members: Vec<EmailAddress>,
        messages: Vec<ChatMessage>,
    }

    fn chats_url(start: &str) -> String {
        format!(
            "https://graph.microsoft.com/v1.0/me/chats\
             ?$filter=lastUpdatedDateTime%20ge%20{}&$expand=members&$top=50",
            percent_encode(start)
        )
    }

    fn chat_messages_url(chat_id: &str) -> String {
        format!(
            "https://graph.microsoft.com/v1.0/chats/{chat_id}/messages\
             ?$top=50&$orderby=createdDateTime%20desc"
        )
    }

    fn chat_messages(
        config: &Config,
        chat_id: &str,
        start: &str,
        until: &str,
    ) -> Result<Vec<ChatMessage>, String> {
        let mut next = Some(chat_messages_url(chat_id));
        let mut refreshed = false;
        let mut pages = 0u32;
        let mut messages = Vec::new();
        while let Some(url) = next.take() {
            let response = graph_response(config, &url, &mut refreshed)?;
            match response.status {
                403 | 404 if pages == 0 => return Ok(Vec::new()),
                403 | 404 => {
                    return Err(format!(
                        "chat collection disappeared mid-pagination for {url}"
                    ));
                }
                200..=299 => {}
                status => {
                    return Err(format!("Graph GET failed (HTTP {status}) for {url}"));
                }
            }
            let body = json(&response)?;
            let values = body["value"]
                .as_array()
                .ok_or_else(|| "Graph chat page has no value array".to_string())?;
            let page = values
                .iter()
                .cloned()
                .map(serde_json::from_value::<GraphChatMessage>)
                .collect::<Result<Vec<_>, _>>()
                .map_err(|error| format!("chat message shape: {error}"))?;
            let reached_start = page
                .iter()
                .any(|message| message.created_date_time.as_str() < start);
            messages.extend(
                page.into_iter()
                    .filter(|message| {
                        matches!(message.message_type.as_deref(), Some("message") | None)
                            && message.created_date_time.as_str() >= start
                            && message.created_date_time.as_str() < until
                    })
                    .map(|message| ChatMessage {
                        id: message.id,
                        created_date_time: message.created_date_time,
                        from: message
                            .from
                            .and_then(|from| from.user)
                            .and_then(|user| user.display_name),
                        body: message.body.map(|body| body.content),
                    }),
            );
            next = (!reached_start)
                .then(|| body["@odata.nextLink"].as_str().map(str::to_string))
                .flatten();
            pages += 1;
            if pages >= MAX_PAGES {
                return Err("Graph chat paging exceeded 500 pages — aborting".into());
            }
        }
        messages.sort_by(|left, right| {
            left.created_date_time
                .cmp(&right.created_date_time)
                .then_with(|| left.id.cmp(&right.id))
        });
        messages.dedup_by(|left, right| left.id == right.id);
        Ok(messages)
    }

    fn fetch_chats(config: &Config, start: &str, until: &str) -> Result<FetchResult, String> {
        let raw = graph_pages(config, chats_url(start))?;
        let mut graph_chats = raw
            .into_iter()
            .map(serde_json::from_value::<GraphChat>)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|error| format!("chat shape: {error}"))?;
        graph_chats.sort_by(|left, right| left.id.cmp(&right.id));
        graph_chats.dedup_by(|left, right| left.id == right.id);
        control::progress(&format!(
            "{} chats active in window; fetching messages…",
            graph_chats.len()
        ));
        let mut chats = Vec::new();
        for chat in graph_chats {
            let messages = chat_messages(config, &chat.id, start, until)?;
            if !messages.is_empty() {
                chats.push(Chat {
                    id: chat.id,
                    topic: chat.topic,
                    chat_type: chat.chat_type,
                    members: chat
                        .members
                        .into_iter()
                        .map(|member| EmailAddress {
                            name: member.display_name,
                            address: member.email,
                        })
                        .collect(),
                    messages,
                });
            }
        }
        let bundle = serde_json::to_vec_pretty(&chats).map_err(|error| error.to_string())?;
        let file = evidence::open("chats.json")?;
        file.write(&bundle)?;
        let _stored = file.finish()?;
        let mut items = Vec::new();
        for chat in &chats {
            for message in &chat.messages {
                items.push(Item {
                    id: message.id.clone(),
                    kind: "chat-message".into(),
                    version: None,
                    content_hash: kyyn_plugin_bundle::canonical_record_sha256(message)
                        .map_err(|error| error.to_string())?,
                    files: vec!["chats.json".into()],
                    file_hashes: Vec::new(),
                    locator: Some(message.id.clone()),
                    meta: chat.topic.clone().unwrap_or_else(|| "chat".into()),
                });
            }
        }
        Ok(FetchResult {
            notes: format!("{} chat messages in window", items.len()),
            items,
            next_checkpoint: None,
        })
    }

    fn graph_item_pages(
        config: &Config,
        first_url: String,
    ) -> Result<Option<Vec<serde_json::Value>>, String> {
        let mut records = Vec::new();
        let mut next = Some(first_url);
        let mut refreshed = false;
        let mut pages = 0u32;
        while let Some(url) = next.take() {
            let response = graph_response(config, &url, &mut refreshed)?;
            match response.status {
                403 | 404 if pages == 0 => return Ok(None),
                403 | 404 => {
                    return Err(format!(
                        "Graph collection disappeared mid-pagination for {url}"
                    ));
                }
                200..=299 => {}
                status => return Err(format!("Graph GET failed (HTTP {status}) for {url}")),
            }
            let body = json(&response)?;
            records.extend(
                body["value"]
                    .as_array()
                    .ok_or_else(|| "Graph collection has no value array".to_string())?
                    .iter()
                    .cloned(),
            );
            next = body["@odata.nextLink"].as_str().map(str::to_string);
            pages += 1;
            if pages >= MAX_PAGES {
                return Err("Graph item paging exceeded 500 pages — aborting".into());
            }
        }
        Ok(Some(records))
    }

    #[derive(Deserialize)]
    struct OnlineMeeting {
        id: String,
    }

    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct Transcript {
        id: String,
        created_date_time: Option<String>,
    }

    #[derive(Deserialize)]
    struct AttendanceReport {
        id: String,
        #[serde(rename = "meetingStartDateTime")]
        meeting_start: Option<String>,
        #[serde(rename = "meetingEndDateTime")]
        meeting_end: Option<String>,
        #[serde(rename = "totalParticipantCount")]
        total_participant_count: Option<u32>,
    }

    fn graph_time(value: &str) -> Option<chrono::DateTime<chrono::Utc>> {
        let value = if value.ends_with(['Z', 'z']) {
            value.to_string()
        } else {
            format!("{value}Z")
        };
        chrono::DateTime::parse_from_rfc3339(&value)
            .ok()
            .map(|time| time.with_timezone(&chrono::Utc))
    }

    fn slugify(value: &str) -> String {
        let mut output = String::new();
        let mut previous_dash = false;
        for ch in value.chars() {
            if ch.is_alphanumeric() {
                output.extend(ch.to_lowercase());
                previous_dash = false;
            } else if !previous_dash {
                output.push('-');
                previous_dash = true;
            }
        }
        output.trim_matches('-').chars().take(60).collect()
    }

    fn meeting_file_name(event: &GraphEvent) -> String {
        let date: String = event.start.date_time.chars().take(10).collect();
        let subject = event
            .subject
            .as_deref()
            .map(slugify)
            .filter(|value| !value.is_empty())
            .unwrap_or_else(|| "untitled".into());
        let id = slugify(&event.id);
        let count = id.chars().count();
        let suffix: String = id.chars().skip(count.saturating_sub(8)).collect();
        format!("{date}-{subject}-{suffix}")
    }

    fn online_meeting_lookup_url(join_url: &str) -> String {
        format!(
            "https://graph.microsoft.com/v1.0/me/onlineMeetings\
             ?$filter=JoinWebUrl%20eq%20'{}'",
            percent_encode(join_url)
        )
    }

    fn transcript_urls(meeting_id: &str) -> (String, impl Fn(&str) -> String + '_) {
        (
            format!(
                "https://graph.microsoft.com/v1.0/me/onlineMeetings/{meeting_id}/transcripts"
            ),
            move |transcript_id| {
                format!(
                    "https://graph.microsoft.com/v1.0/me/onlineMeetings/{meeting_id}/\
                     transcripts/{transcript_id}/content?$format=text/vtt"
                )
            },
        )
    }

    fn attendance_urls(meeting_id: &str) -> (String, impl Fn(&str) -> String + '_) {
        (
            format!(
                "https://graph.microsoft.com/v1.0/me/onlineMeetings/{meeting_id}/attendanceReports"
            ),
            move |report_id| {
                format!(
                    "https://graph.microsoft.com/v1.0/me/onlineMeetings/{meeting_id}/\
                     attendanceReports/{report_id}/attendanceRecords"
                )
            },
        )
    }

    struct MeetingArtifacts {
        transcript: Option<(String, String)>,
        attendance: Option<(String, String)>,
    }

    fn fetch_meeting_artifacts(
        config: &Config,
        event: &GraphEvent,
    ) -> Result<MeetingArtifacts, String> {
        let Some(join_url) = event
            .online_meeting
            .as_ref()
            .and_then(|meeting| meeting.join_url.as_deref())
        else {
            return Ok(MeetingArtifacts {
                transcript: None,
                attendance: None,
            });
        };
        let meetings = graph_item_pages(config, online_meeting_lookup_url(join_url))?
            .unwrap_or_default()
            .into_iter()
            .map(serde_json::from_value::<OnlineMeeting>)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|error| format!("online meeting shape: {error}"))?;
        let Some(meeting) = meetings.into_iter().next() else {
            return Ok(MeetingArtifacts {
                transcript: None,
                attendance: None,
            });
        };
        let start = graph_time(&event.start.date_time);
        let end = graph_time(&event.end.date_time);
        let Some((start, end)) = start.zip(end) else {
            return Ok(MeetingArtifacts {
                transcript: None,
                attendance: None,
            });
        };
        let base_name = meeting_file_name(event);
        let (transcript_list_url, transcript_content_url) = transcript_urls(&meeting.id);
        let transcripts = graph_item_pages(config, transcript_list_url)?
            .unwrap_or_default()
            .into_iter()
            .map(serde_json::from_value::<Transcript>)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|error| format!("transcript shape: {error}"))?;
        let chosen_transcript = transcripts
            .into_iter()
            .filter_map(|transcript| {
                let created = graph_time(transcript.created_date_time.as_deref()?)?;
                (created >= start && created <= end + chrono::Duration::hours(6))
                    .then_some((created, transcript))
            })
            .max_by_key(|(created, _)| *created)
            .map(|(_, transcript)| transcript);
        let transcript = if let Some(transcript) = chosen_transcript {
            let mut refreshed = false;
            let response = graph_response(
                config,
                &transcript_content_url(&transcript.id),
                &mut refreshed,
            )?;
            match response.status {
                200..=299 => {
                    let path = format!("transcripts/{base_name}.vtt");
                    let file = evidence::open(&path)?;
                    file.write(&response.body)?;
                    let stored = file.finish()?;
                    Some((path, stored.sha256))
                }
                403 | 404 => None,
                status => return Err(format!("transcript fetch failed (HTTP {status})")),
            }
        } else {
            None
        };

        let (report_list_url, report_records_url) = attendance_urls(&meeting.id);
        let reports = graph_item_pages(config, report_list_url)?
            .unwrap_or_default()
            .into_iter()
            .map(serde_json::from_value::<AttendanceReport>)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|error| format!("attendance report shape: {error}"))?;
        let chosen_report = reports
            .into_iter()
            .filter_map(|report| {
                let report_start = graph_time(report.meeting_start.as_deref()?)?;
                (report_start >= start - chrono::Duration::hours(1)
                    && report_start <= end + chrono::Duration::hours(6))
                .then_some((report_start, report))
            })
            .max_by_key(|(report_start, _)| *report_start)
            .map(|(_, report)| report);
        let attendance = if let Some(report) = chosen_report {
            let Some(records) = graph_item_pages(config, report_records_url(&report.id))? else {
                return Ok(MeetingArtifacts {
                    transcript,
                    attendance: None,
                });
            };
            let envelope = serde_json::json!({
                "reportId": report.id,
                "meetingStartDateTime": report.meeting_start,
                "meetingEndDateTime": report.meeting_end,
                "totalParticipantCount": report.total_participant_count,
                "records": records,
            });
            let path = format!("attendance/{base_name}.json");
            let bytes =
                serde_json::to_vec_pretty(&envelope).map_err(|error| error.to_string())?;
            let file = evidence::open(&path)?;
            file.write(&bytes)?;
            let stored = file.finish()?;
            Some((path, stored.sha256))
        } else {
            None
        };
        Ok(MeetingArtifacts {
            transcript,
            attendance,
        })
    }

    fn fetch_meetings(config: &Config, start: &str, until: &str) -> Result<FetchResult, String> {
        let raw = graph_pages(config, calendar_url(start, until))?;
        let mut events = raw
            .into_iter()
            .map(serde_json::from_value::<GraphEvent>)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|error| format!("calendar event shape: {error}"))?;
        events.sort_by(|left, right| left.start.date_time.cmp(&right.start.date_time));
        events.dedup_by(|left, right| left.id == right.id);
        control::progress(&format!(
            "{} events in window; checking for transcripts and attendance…",
            events.len()
        ));
        let mut meetings = Vec::new();
        let mut hashes: Vec<Vec<(String, String)>> = Vec::new();
        for event in events {
            if event.attendees.is_empty() && !event.is_online_meeting.unwrap_or(false) {
                continue;
            }
            let artifacts = fetch_meeting_artifacts(config, &event)?;
            let event_hashes: Vec<(String, String)> = artifacts
                .transcript
                .iter()
                .chain(artifacts.attendance.iter())
                .cloned()
                .collect();
            let normalized = Event {
                id: event.id,
                subject: event.subject,
                start: event.start.date_time,
                end: event.end.date_time,
                organizer: event.organizer.map(|value| value.email_address),
                attendees: event
                    .attendees
                    .into_iter()
                    .map(|value| value.email_address)
                    .collect(),
                teams: event.is_online_meeting.unwrap_or(false),
                location: event.location.and_then(|value| value.display_name),
                transcript_file: artifacts.transcript.map(|(path, _)| path),
                attendance_file: artifacts.attendance.map(|(path, _)| path),
            };
            meetings.push(normalized);
            hashes.push(event_hashes);
        }
        let bundle = serde_json::to_vec_pretty(&meetings).map_err(|error| error.to_string())?;
        let file = evidence::open("meetings.json")?;
        file.write(&bundle)?;
        let _stored = file.finish()?;
        let items = meetings
            .iter()
            .zip(hashes)
            .map(|(meeting, hashes)| {
                Ok(Item {
                    id: meeting.id.clone(),
                    kind: "meeting".into(),
                    version: None,
                    content_hash: kyyn_plugin_bundle::canonical_record_sha256(meeting)
                        .map_err(|error| error.to_string())?,
                    files: std::iter::once("meetings.json".into())
                        .chain(hashes.iter().map(|(path, _)| path.clone()))
                        .collect(),
                    file_hashes: hashes,
                    locator: Some(meeting.id.clone()),
                    meta: meeting.subject.clone().unwrap_or_default(),
                })
            })
            .collect::<Result<Vec<_>, String>>()?;
        Ok(FetchResult {
            notes: format!("{} meetings (artifacts where organizer)", items.len()),
            items,
            next_checkpoint: None,
        })
    }

    #[derive(Deserialize)]
    struct FolderFacet {}

    #[derive(Deserialize)]
    struct ParentReference {
        #[serde(rename = "driveId")]
        drive_id: Option<String>,
    }

    #[derive(Deserialize)]
    struct DriveItem {
        id: Option<String>,
        name: String,
        #[serde(rename = "@microsoft.graph.downloadUrl")]
        download_url: Option<String>,
        #[serde(rename = "eTag")]
        etag: Option<String>,
        #[serde(rename = "lastModifiedDateTime")]
        last_modified: Option<String>,
        size: Option<u64>,
        folder: Option<FolderFacet>,
        #[serde(rename = "parentReference")]
        parent_reference: Option<ParentReference>,
    }

    fn share_token(url: &str) -> String {
        use base64::Engine as _;
        format!(
            "u!{}",
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(url)
        )
    }

    fn relative_matches(patterns: &[glob::Pattern], relative: &str) -> bool {
        let options = glob::MatchOptions {
            require_literal_separator: true,
            require_literal_leading_dot: true,
            ..Default::default()
        };
        patterns
            .iter()
            .any(|pattern| pattern.matches_with(relative, options))
    }

    fn download(
        url: &str,
        path: &str,
        max_bytes: u64,
    ) -> Result<evidence::StoredFile, String> {
        let response = http::fetch(&Request {
            method: Method::Get,
            url: url.into(),
            headers: Vec::new(),
            body: None,
            secret_authorization: None,
            max_response_bytes: max_bytes,
            timeout_ms: 120_000,
        })
        .map_err(|error| error.message)?;
        if !(200..300).contains(&response.status) {
            return Err(format!("download failed (HTTP {}) for '{path}'", response.status));
        }
        let file = evidence::open(path)?;
        file.write(&response.body)?;
        file.finish()
    }

    fn fetch_sharepoint(config: &Config, checkpoint: Option<String>) -> Result<FetchResult, String> {
        use std::collections::BTreeMap;
        let sharing_url = config.url.as_deref().ok_or("sharepoint url is required")?;
        if secrets::get(ACCESS_TOKEN).is_none() {
            return Err("no token — sign the realm in first".into());
        }
        let metadata_url = format!(
            "https://graph.microsoft.com/v1.0/shares/{}/driveItem",
            share_token(sharing_url)
        );
        let mut refreshed = false;
        let response = graph_response(config, &metadata_url, &mut refreshed)?;
        match response.status {
            403 => return Err("share link access denied (Graph 403)".into()),
            404 => return Err("share link not found (Graph 404)".into()),
            200..=299 => {}
            status => return Err(format!("share lookup failed (HTTP {status})")),
        }
        let root: DriveItem = serde_json::from_slice(&response.body)
            .map_err(|error| format!("drive item shape: {error}"))?;
        if root.folder.is_none() {
            let provider_version = root.etag.clone().or(root.last_modified.clone());
            if provider_version.as_deref().zip(checkpoint.as_deref()).is_some_and(
                |(version, previous)| version == previous,
            ) {
                return Ok(FetchResult {
                    items: Vec::new(),
                    notes: format!("'{}' unchanged", root.name),
                    next_checkpoint: checkpoint,
                });
            }
            if root.size.is_some_and(|size| size > config.max_file_bytes) {
                return Ok(FetchResult {
                    items: Vec::new(),
                    notes: format!("skipped '{}' (over size cap)", root.name),
                    next_checkpoint: checkpoint,
                });
            }
            let url = root.download_url.as_deref().ok_or("file has no download URL")?;
            let name = root
                .name
                .rsplit(['/', '\\'])
                .next()
                .unwrap_or("download")
                .to_string();
            let stored = download(url, &name, config.max_file_bytes)?;
            if provider_version.is_none()
                && checkpoint.as_deref() == Some(stored.sha256.as_str())
            {
                return Ok(FetchResult {
                    items: Vec::new(),
                    notes: format!("'{name}' unchanged (content hash match)"),
                    next_checkpoint: Some(stored.sha256),
                });
            }
            let next = provider_version
                .clone()
                .unwrap_or_else(|| stored.sha256.clone());
            return Ok(FetchResult {
                items: vec![Item {
                    id: sharing_url.into(),
                    kind: config.kind.clone(),
                    version: provider_version,
                    content_hash: stored.sha256,
                    files: vec![name.clone()],
                    file_hashes: Vec::new(),
                    locator: None,
                    meta: format!(
                        "{name} · {} bytes · modified {}",
                        stored.bytes,
                        root.last_modified.as_deref().unwrap_or("?")
                    ),
                }],
                notes: format!("'{name}' new version snapshotted"),
                next_checkpoint: Some(next),
            });
        }

        let drive_id = root
            .parent_reference
            .and_then(|reference| reference.drive_id)
            .ok_or("folder share carries no driveId")?;
        let root_id = root.id.ok_or("folder share carries no item id")?;
        let patterns = config
            .patterns
            .iter()
            .map(|pattern| {
                glob::Pattern::new(pattern)
                    .map_err(|error| format!("pattern '{pattern}': {error}"))
            })
            .collect::<Result<Vec<_>, _>>()?;
        let previous: BTreeMap<String, String> = checkpoint
            .as_deref()
            .and_then(|value| ron::from_str(value).ok())
            .unwrap_or_default();
        let mut stack = vec![(root_id, String::new())];
        let mut found = Vec::new();
        while let Some((id, prefix)) = stack.pop() {
            let children_url = format!(
                "https://graph.microsoft.com/v1.0/drives/{drive_id}/items/{id}/children"
            );
            let children = graph_pages(config, children_url)?
                .into_iter()
                .map(serde_json::from_value::<DriveItem>)
                .collect::<Result<Vec<_>, _>>()
                .map_err(|error| format!("drive child shape: {error}"))?;
            for child in children {
                let relative = if prefix.is_empty() {
                    child.name.clone()
                } else {
                    format!("{prefix}/{}", child.name)
                };
                if child.folder.is_some() {
                    stack.push((
                        child.id.clone().ok_or("folder child has no id")?,
                        relative,
                    ));
                } else {
                    found.push((child, relative));
                }
            }
        }
        found.sort_by(|left, right| left.1.cmp(&right.1));
        let mut next = BTreeMap::new();
        let mut items = Vec::new();
        let mut unchanged = 0usize;
        let mut notes = Vec::new();
        for (child, relative) in found {
            if !relative_matches(&patterns, &relative) {
                continue;
            }
            let id = child.id.clone().ok_or("file child has no id")?;
            if child.size.is_some_and(|size| size > config.max_file_bytes) {
                notes.push(format!("skipped {relative} (over size cap)"));
                continue;
            }
            if child
                .etag
                .as_deref()
                .zip(previous.get(&id).map(String::as_str))
                .is_some_and(|(version, old)| version == old)
            {
                next.insert(id, child.etag.unwrap());
                unchanged += 1;
                continue;
            }
            let url = child
                .download_url
                .as_deref()
                .ok_or_else(|| format!("no download URL on '{relative}'"))?;
            let stored = download(url, &relative, config.max_file_bytes)?;
            if child.etag.is_none() && previous.get(&id) == Some(&stored.sha256) {
                next.insert(id, stored.sha256);
                unchanged += 1;
                continue;
            }
            next.insert(
                id.clone(),
                child
                    .etag
                    .clone()
                    .unwrap_or_else(|| stored.sha256.clone()),
            );
            items.push(Item {
                id,
                kind: config.kind.clone(),
                version: child.etag,
                content_hash: stored.sha256,
                files: vec![relative.clone()],
                file_hashes: Vec::new(),
                locator: None,
                meta: format!(
                    "{relative} · {} bytes · modified {}",
                    stored.bytes,
                    child.last_modified.as_deref().unwrap_or("?")
                ),
            });
        }
        notes.insert(
            0,
            format!("{} new/changed, {unchanged} unchanged", items.len()),
        );
        Ok(FetchResult {
            items,
            notes: notes.join("; "),
            next_checkpoint: Some(ron::to_string(&next).map_err(|error| error.to_string())?),
        })
    }

    struct GraphComponent;

    impl Guest for GraphComponent {
        fn describe() -> PluginDescribe {
            PluginDescribe {
                name: super::PLUGIN_NAME.into(),
                link_namespace: if super::PLUGIN_KIND == "sharepoint" {
                    "sharepoint"
                } else {
                    "graph"
                }
                .into(),
                fetch_style: if super::PLUGIN_KIND == "sharepoint" {
                    FetchStyle::Snapshot
                } else {
                    FetchStyle::Windowed
                },
                auth_realm: Some("ms-graph".into()),
            }
        }

        fn validate_config(config: String) -> Result<(), String> {
            validate(&parse_config(&config)?)
        }

        fn config_auth_realm(config: String) -> Result<Option<String>, String> {
            let config = parse_config(&config)?;
            validate(&config)?;
            Ok(Some(format!(
                "ms-graph:{}:{}",
                config.tenant, config.client_id
            )))
        }

        fn status(_config: String) -> Result<AuthStatus, String> {
            if secrets::get(ACCESS_TOKEN).is_some() {
                Ok(AuthStatus::Authenticated(
                    "token cached (verified on fetch)".into(),
                ))
            } else {
                Ok(AuthStatus::NotAuthenticated(
                    "no token — sign the realm in first".into(),
                ))
            }
        }

        fn auth_begin(config: String) -> Result<AuthChallenge, String> {
            let config = parse_config(&config)?;
            validate(&config)?;
            let response = http::fetch(&request(
                Method::Post,
                identity_url(&config, "devicecode"),
                Some(form(&[("client_id", &config.client_id), ("scope", SCOPES)])),
                None,
            ))
            .map_err(|error| error.message)?;
            let body = json(&response)?;
            let field = |name: &str| body[name].as_str().map(str::to_string);
            Ok(AuthChallenge {
                verification_url: field("verification_uri")
                    .ok_or_else(|| format!("device flow refused: {body}"))?,
                user_code: field("user_code").ok_or("no user_code")?,
                expires_in_secs: body["expires_in"].as_u64().unwrap_or(900),
                handle: field("device_code").ok_or("no device_code")?,
            })
        }

        fn auth_poll(config: String, handle: String) -> Result<AuthPollResult, String> {
            let config = parse_config(&config)?;
            validate(&config)?;
            let response = http::fetch(&request(
                Method::Post,
                identity_url(&config, "token"),
                Some(form(&[
                    ("grant_type", "urn:ietf:params:oauth:grant-type:device_code"),
                    ("client_id", &config.client_id),
                    ("device_code", &handle),
                ])),
                None,
            ))
            .map_err(|error| error.message)?;
            let body = json(&response)?;
            if let Some(token) = body["access_token"].as_str() {
                secrets::put(ACCESS_TOKEN, token.as_bytes())?;
                let refresh = body["refresh_token"]
                    .as_str()
                    .ok_or("no refresh_token returned — offline_access is required")?;
                secrets::put(REFRESH_TOKEN, refresh.as_bytes())?;
                return Ok(AuthPollResult::Done("signed in".into()));
            }
            match body["error"].as_str() {
                Some("authorization_pending") | Some("slow_down") => Ok(AuthPollResult::Pending),
                Some(error) => Ok(AuthPollResult::Failed(format!(
                    "{error}: {}",
                    body["error_description"].as_str().unwrap_or("")
                ))),
                None => Ok(AuthPollResult::Failed(format!(
                    "unexpected reply (HTTP {}): {body}",
                    response.status
                ))),
            }
        }

        fn fetch(request: FetchRequest) -> Result<FetchResult, String> {
            let config = parse_config(&request.config)?;
            validate(&config)?;
            if super::PLUGIN_KIND == "sharepoint" {
                if !matches!(request.spec, RunSpec::Snapshot) {
                    return Err("sharepoint-file is a snapshot source".into());
                }
                return fetch_sharepoint(&config, request.checkpoint);
            }
            let RunSpec::Window(window) = request.spec else {
                return Err(format!("{} is a windowed source", super::PLUGIN_NAME));
            };
            match super::PLUGIN_KIND {
                "calendar" => fetch_calendar(&config, &window.start, &window.until),
                "mail" => fetch_mail(&config, &window.start, &window.until),
                "chats" => fetch_chats(&config, &window.start, &window.until),
                "meetings" => fetch_meetings(&config, &window.start, &window.until),
                kind => Err(format!("unsupported Graph component kind {kind}")),
            }
        }
    }

    bindings::export!(GraphComponent with_types_in bindings);
}
