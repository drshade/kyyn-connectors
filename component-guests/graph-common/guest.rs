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
            });
        }
        value.into_rust().map_err(|error| {
            format!(
                "graph config shape (optional client_id, tenant, owner_addresses; \
                 mail_filter is mail-only): {error}"
            )
        })
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

    fn graph_get(config: &Config, url: &str, refreshed: &mut bool) -> Result<Response, String> {
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
            if !(200..300).contains(&response.status) {
                return Err(format!(
                    "Graph GET failed (HTTP {}) for {url}",
                    response.status
                ));
            }
            return Ok(response);
        }
        Err(format!("Graph GET exhausted retries for {url}"))
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
        #[allow(dead_code)]
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
                let canonical = serde_json::to_vec(event).map_err(|error| error.to_string())?;
                Ok(Item {
                    id: event.id.clone(),
                    kind: "event".into(),
                    version: None,
                    content_hash: format!("{:x}", sha2::Sha256::digest(&canonical)),
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
                let (status, stored) = http::fetch_to_evidence(
                    &request(
                        Method::Get,
                        attachment_value_url(message_id, &meta.id),
                        None,
                        Some(ACCESS_TOKEN),
                    ),
                    &relative,
                )
                .map_err(|error| error.message)?;
                match status {
                    200..=299 => {
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
                let canonical = serde_json::to_vec(email).map_err(|error| error.to_string())?;
                Ok(Item {
                    id: email.id.clone(),
                    kind: "email".into(),
                    version: None,
                    content_hash: format!("{:x}", sha2::Sha256::digest(&canonical)),
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

    struct GraphComponent;

    impl Guest for GraphComponent {
        fn describe() -> PluginDescribe {
            PluginDescribe {
                name: super::PLUGIN_NAME.into(),
                link_namespace: "graph".into(),
                fetch_style: FetchStyle::Windowed,
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
            let RunSpec::Window(window) = request.spec else {
                return Err(format!("{} is a windowed source", super::PLUGIN_NAME));
            };
            match super::PLUGIN_KIND {
                "calendar" => fetch_calendar(&config, &window.start, &window.until),
                "mail" => fetch_mail(&config, &window.start, &window.until),
                kind => Err(format!("unsupported Graph component kind {kind}")),
            }
        }
    }

    bindings::export!(GraphComponent with_types_in bindings);
}
