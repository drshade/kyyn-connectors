#![cfg_attr(
    not(all(target_arch = "wasm32", target_os = "unknown")),
    allow(dead_code)
)]

use base64::Engine as _;
use serde::{Deserialize, Serialize};
use url::Url;

const GRAPH_ORIGIN: &str = "https://graph.microsoft.com";
const RESPONSE_CAP: u64 = 1024 * 1024;
const MAX_GRAPH_ID_BYTES: usize = 512;
const MAX_DISPLAY_BYTES: usize = 512;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum LinkFamily {
    SharePoint,
    OneDriveBusiness,
    OneDrivePersonal,
}

impl LinkFamily {
    fn label(self) -> &'static str {
        match self {
            Self::SharePoint => "SharePoint",
            Self::OneDriveBusiness => "OneDrive for Business",
            Self::OneDrivePersonal => "OneDrive",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ResolutionMode {
    ReadOnly,
    MetadataReadWrite,
}

/// The submitted browser URL is owner-ephemeral. This type deliberately has
/// no `Clone`, `Debug`, serialization implementation or public URL accessor.
struct RawLink {
    url: Url,
    family: LinkFamily,
    mode: ResolutionMode,
}

impl RawLink {
    fn parse(submitted: &str) -> Result<Self, String> {
        if submitted.len() > 16 * 1024 {
            return Err("Microsoft link exceeds the input ceiling".into());
        }
        let mut url =
            Url::parse(submitted).map_err(|_| "Microsoft link is not a valid URL".to_string())?;
        if url.scheme() != "https"
            || (url.port().is_some() && url.port() != Some(443))
            || !url.username().is_empty()
            || url.password().is_some()
        {
            return Err("Microsoft link must be a credential-free HTTPS URL".into());
        }
        url.set_fragment(None);
        let host = url
            .host_str()
            .ok_or_else(|| "Microsoft link has no hostname".to_string())?
            .to_ascii_lowercase();
        let (family, mode) = classify(&url, &host)?;
        Ok(Self { url, family, mode })
    }

    fn resolution(&self) -> ResolutionRequest {
        if self.mode == ResolutionMode::ReadOnly
            && let Some(request) = transparent_provider_path(&self.url)
        {
            request
        } else {
            let encoded =
                base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(self.url.as_str());
            ResolutionRequest::OpaqueShare(format!("u!{encoded}"))
        }
    }
}

enum ResolutionRequest {
    CanonicalPath {
        site_host: String,
        site_path: String,
        library_path: String,
        item_path: String,
        folder_view: bool,
    },
    OpaqueShare(String),
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct EphemeralConfig {
    resource_link: String,
}

#[derive(Serialize)]
struct DurableConfig {
    drive_id: String,
    item_id: String,
    item_kind: String,
    display_name: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct GraphDriveItem {
    id: String,
    name: String,
    parent_reference: Option<GraphParentReference>,
    file: Option<serde_json::Value>,
    folder: Option<serde_json::Value>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct GraphParentReference {
    drive_id: Option<String>,
}

#[derive(Deserialize)]
struct GraphSite {
    id: String,
}

#[derive(Deserialize)]
struct GraphDriveList {
    value: Vec<GraphDrive>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct GraphDrive {
    id: String,
    web_url: String,
}

fn parse_ephemeral(text: &str) -> Result<EphemeralConfig, String> {
    let value: ron::Value =
        ron::from_str(text).map_err(|_| "Microsoft setup input is not valid RON".to_string())?;
    value
        .into_rust()
        .map_err(|_| "Microsoft setup requires one resource link".to_string())
}

fn classify(url: &Url, host: &str) -> Result<(LinkFamily, ResolutionMode), String> {
    if matches!(host, "onedrive.live.com" | "1drv.ms") {
        return Ok((
            LinkFamily::OneDrivePersonal,
            ResolutionMode::MetadataReadWrite,
        ));
    }
    if !host.ends_with(".sharepoint.com") {
        return Err("URL is not a supported Microsoft file link".into());
    }
    if host.ends_with("-my.sharepoint.com") {
        let mode = if transparent_shared_wrapper(url, host) {
            ResolutionMode::ReadOnly
        } else {
            ResolutionMode::MetadataReadWrite
        };
        return Ok((LinkFamily::OneDriveBusiness, mode));
    }
    let path = url.path();
    let transparent = (path.starts_with("/sites/") || path.starts_with("/teams/"))
        && path.split('/').filter(|part| !part.is_empty()).count() >= 2;
    Ok((
        LinkFamily::SharePoint,
        if transparent {
            ResolutionMode::ReadOnly
        } else {
            ResolutionMode::MetadataReadWrite
        },
    ))
}

fn transparent_shared_wrapper(url: &Url, outer_host: &str) -> bool {
    if url.path() != "/shared" {
        return false;
    }
    let mut list_url = None;
    let mut item_path = None;
    for (name, value) in url.query_pairs() {
        match name.as_ref() {
            "listurl" => list_url = Some(value.into_owned()),
            "id" => item_path = Some(value.into_owned()),
            _ => {}
        }
    }
    let (Some(list_url), Some(item_path)) = (list_url, item_path) else {
        return false;
    };
    let Ok(list_url) = Url::parse(&list_url) else {
        return false;
    };
    let Some(list_host) = list_url.host_str().map(str::to_ascii_lowercase) else {
        return false;
    };
    let Some(tenant) = outer_host.strip_suffix("-my.sharepoint.com") else {
        return false;
    };
    if list_url.scheme() != "https"
        || !list_url.username().is_empty()
        || list_url.password().is_some()
        || list_host != format!("{tenant}.sharepoint.com")
        || list_url.query().is_some()
        || list_url.fragment().is_some()
    {
        return false;
    }
    let Some(decoded) = decode_percent_path(list_url.path()) else {
        return false;
    };
    let list_path = decoded.trim_end_matches('/');
    let segments = list_path
        .split('/')
        .filter(|segment| !segment.is_empty())
        .collect::<Vec<_>>();
    if segments.len() < 3 || !matches!(segments[0], "sites" | "teams") {
        return false;
    }
    item_path == list_path
        || item_path
            .strip_prefix(list_path)
            .is_some_and(|rest| rest.starts_with('/'))
}

fn transparent_provider_path(url: &Url) -> Option<ResolutionRequest> {
    if url.path() == "/shared" {
        let mut list_url = None;
        let mut item_path = None;
        for (name, value) in url.query_pairs() {
            match name.as_ref() {
                "listurl" => list_url = Url::parse(&value).ok(),
                "id" => item_path = Some(value.into_owned()),
                _ => {}
            }
        }
        let list_url = list_url?;
        let site_host = list_url.host_str()?.to_ascii_lowercase();
        let library_path = decode_percent_path(list_url.path())?;
        let item_path = item_path?
            .strip_prefix(library_path.trim_end_matches('/'))?
            .trim_start_matches('/')
            .to_string();
        let segments = library_path
            .split('/')
            .filter(|segment| !segment.is_empty())
            .collect::<Vec<_>>();
        if segments.len() < 3 || !matches!(segments[0], "sites" | "teams") {
            return None;
        }
        return Some(ResolutionRequest::CanonicalPath {
            site_host,
            site_path: format!("/{}/{}", segments[0], segments[1]),
            library_path,
            item_path,
            folder_view: false,
        });
    }

    let site_host = url.host_str()?.to_ascii_lowercase();
    let decoded = decode_percent_path(url.path())?;
    let segments = decoded
        .split('/')
        .filter(|segment| !segment.is_empty())
        .collect::<Vec<_>>();
    if segments.len() < 3 || !matches!(segments[0], "sites" | "teams") {
        return None;
    }
    let library_path = format!("/{}/{}/{}", segments[0], segments[1], segments[2]);
    let folder_view = segments.len() == 5
        && segments[3].eq_ignore_ascii_case("forms")
        && segments[4].eq_ignore_ascii_case("allitems.aspx");
    let item_path = if folder_view {
        let selected = url.query_pairs().find_map(|(name, value)| {
            matches!(name.as_ref(), "id" | "RootFolder").then(|| value.into_owned())
        })?;
        let remainder = selected.strip_prefix(library_path.trim_end_matches('/'))?;
        remainder.strip_prefix('/').unwrap_or(remainder).to_string()
    } else {
        segments[3..].join("/")
    };
    Some(ResolutionRequest::CanonicalPath {
        site_host,
        site_path: format!("/{}/{}", segments[0], segments[1]),
        library_path,
        item_path,
        folder_view,
    })
}

fn decode_percent_path(path: &str) -> Option<String> {
    let bytes = path.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' {
            decoded.push((hex(*bytes.get(index + 1)?)? << 4) | hex(*bytes.get(index + 2)?)?);
            index += 3;
        } else {
            decoded.push(bytes[index]);
            index += 1;
        }
    }
    let value = String::from_utf8(decoded).ok()?;
    (!value.chars().any(char::is_control)).then_some(value)
}

fn hex(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn encode_graph_segment(value: &str) -> String {
    let mut url = Url::parse("https://graph.invalid/").expect("constant URL");
    url.path_segments_mut()
        .expect("constant URL has path segments")
        .pop_if_empty()
        .push(value);
    url.path().trim_start_matches('/').to_string()
}

fn encode_graph_path(value: &str) -> String {
    value
        .split('/')
        .filter(|segment| !segment.is_empty())
        .map(encode_graph_segment)
        .collect::<Vec<_>>()
        .join("/")
}

fn normalize_provider_path(value: &str) -> Result<String, String> {
    let decoded = decode_percent_path(value)
        .ok_or_else(|| "Microsoft returned an invalid document library path".to_string())?;
    Ok(format!("/{}", decoded.trim_matches('/')))
}

fn safe_graph_id(value: &str, label: &str) -> Result<(), String> {
    if value.is_empty()
        || value.len() > MAX_GRAPH_ID_BYTES
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_graphic() && !matches!(byte, b'/' | b'\\'))
    {
        return Err(format!("Microsoft returned an invalid {label} identity"));
    }
    Ok(())
}

fn safe_display(value: &str) -> Result<(), String> {
    if value.trim().is_empty()
        || value.len() > MAX_DISPLAY_BYTES
        || value.chars().any(char::is_control)
        || Url::parse(value).is_ok()
    {
        return Err("Microsoft returned an invalid display name".into());
    }
    Ok(())
}

fn locator(
    item: GraphDriveItem,
    fallback_drive_id: Option<String>,
) -> Result<DurableConfig, String> {
    let drive_id = item
        .parent_reference
        .and_then(|reference| reference.drive_id)
        .or(fallback_drive_id)
        .ok_or_else(|| "Microsoft did not return a canonical drive identity".to_string())?;
    let item_kind = match (item.file.is_some(), item.folder.is_some()) {
        (true, false) => "file",
        (false, true) => "folder",
        _ => return Err("Microsoft returned an unsupported item kind".into()),
    };
    safe_graph_id(&drive_id, "drive")?;
    safe_graph_id(&item.id, "item")?;
    safe_display(&item.name)?;
    Ok(DurableConfig {
        drive_id,
        item_id: item.id,
        item_kind: item_kind.into(),
        display_name: item.name,
    })
}

#[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
mod guest {
    mod bindings {
        wit_bindgen::generate!({
            path: "../../../wit/configurator.wit",
            world: "configurator",
        });
    }

    use super::*;
    use bindings::exports::kyyn::configurator::api::{
        ConfigureOutput, ConfigureRequest, Diagnostic, DiagnosticClass, Guest,
    };
    use bindings::kyyn::configurator::http::{self, Method, Request, Response};

    fn fetch(url: String, operation: &str, folder_view: bool) -> Result<Response, String> {
        let response = http::fetch(&Request {
            method: Method::Get,
            url,
            headers: vec![("accept".into(), "application/json".into())],
            body: None,
            max_response_bytes: RESPONSE_CAP,
            timeout_ms: 120_000,
        })
        .map_err(|_| format!("Microsoft {operation} could not connect"))?;
        if !(200..300).contains(&response.status) {
            if response.status == 404 && folder_view {
                return Err("Microsoft could not access the selected folder. SharePoint can show individually shared files inside a folder that was not itself shared; share the folder with this account or add the files separately".into());
            }
            return Err(format!(
                "Microsoft {operation} failed (HTTP {})",
                response.status
            ));
        }
        Ok(response)
    }

    fn json<T: for<'de> Deserialize<'de>>(
        response: Response,
        operation: &str,
    ) -> Result<T, String> {
        serde_json::from_slice(&response.body)
            .map_err(|_| format!("Microsoft returned an invalid {operation} response"))
    }

    fn resolve(request: ResolutionRequest) -> Result<DurableConfig, String> {
        match request {
            ResolutionRequest::OpaqueShare(token) => {
                let item = json::<GraphDriveItem>(
                    fetch(
                        format!("{GRAPH_ORIGIN}/v1.0/shares/{token}/driveItem"),
                        "file identity request",
                        false,
                    )?,
                    "file identity request",
                )?;
                locator(item, None)
            }
            ResolutionRequest::CanonicalPath {
                site_host,
                site_path,
                library_path,
                item_path,
                folder_view,
            } => {
                let site = json::<GraphSite>(
                    fetch(
                        format!(
                            "{GRAPH_ORIGIN}/v1.0/sites/{site_host}:/{}",
                            encode_graph_path(&site_path)
                        ),
                        "site identity request",
                        false,
                    )?,
                    "site identity request",
                )?;
                let drives = json::<GraphDriveList>(
                    fetch(
                        format!(
                            "{GRAPH_ORIGIN}/v1.0/sites/{}/drives",
                            encode_graph_segment(&site.id)
                        ),
                        "document library request",
                        false,
                    )?,
                    "document library request",
                )?;
                if drives.value.len() > 256 {
                    return Err("Microsoft returned too many document libraries".into());
                }
                let expected = normalize_provider_path(&library_path)?;
                let mut matching = drives.value.into_iter().filter(|drive| {
                    Url::parse(&drive.web_url).is_ok_and(|url| {
                        url.scheme() == "https"
                            && url.host_str() == Some(site_host.as_str())
                            && url.query().is_none()
                            && url.fragment().is_none()
                            && normalize_provider_path(url.path())
                                .is_ok_and(|path| path == expected)
                    })
                });
                let drive = matching
                    .next()
                    .ok_or_else(|| "Microsoft could not match the document library".to_string())?;
                if matching.next().is_some() {
                    return Err("Microsoft returned an ambiguous document library".into());
                }
                let endpoint = if item_path.is_empty() {
                    format!(
                        "{GRAPH_ORIGIN}/v1.0/drives/{}/root",
                        encode_graph_segment(&drive.id)
                    )
                } else {
                    format!(
                        "{GRAPH_ORIGIN}/v1.0/drives/{}/root:/{}",
                        encode_graph_segment(&drive.id),
                        encode_graph_path(&item_path)
                    )
                };
                let item = json::<GraphDriveItem>(
                    fetch(endpoint, "file identity request", folder_view)?,
                    "file identity request",
                )?;
                locator(item, Some(drive.id))
            }
        }
    }

    struct MicrosoftFiles;

    impl Guest for MicrosoftFiles {
        fn configure(request: ConfigureRequest) -> Result<ConfigureOutput, String> {
            let input = parse_ephemeral(&request.ephemeral_config)?;
            let raw = RawLink::parse(&input.resource_link)?;
            let family = raw.family;
            let durable = resolve(raw.resolution())?;
            let summary = format!(
                "Resolved {} item '{}'",
                family.label(),
                durable.display_name
            );
            Ok(ConfigureOutput {
                durable_config: ron::ser::to_string(&durable)
                    .map_err(|_| "could not encode resolved Microsoft identity".to_string())?,
                display_summary: summary,
                diagnostics: vec![Diagnostic {
                    class: DiagnosticClass::Info,
                    message: "Microsoft file identity resolved".into(),
                    detail: None,
                }],
            })
        }
    }

    bindings::export!(MicrosoftFiles with_types_in bindings);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn browser_link_families_choose_the_expected_resolution() {
        let opaque = RawLink::parse(
            "https://tenant-my.sharepoint.com/:w:/r/personal/user/doc.aspx?authKey=never-persist",
        )
        .unwrap();
        assert_eq!(opaque.family, LinkFamily::OneDriveBusiness);
        assert!(matches!(
            opaque.resolution(),
            ResolutionRequest::OpaqueShare(_)
        ));

        let site =
            RawLink::parse("https://tenant.sharepoint.com/sites/Finance/Shared%20Documents/a.xlsx")
                .unwrap();
        assert_eq!(site.family, LinkFamily::SharePoint);
        assert!(matches!(
            site.resolution(),
            ResolutionRequest::CanonicalPath { .. }
        ));
    }

    #[test]
    fn folder_view_uses_the_selected_folder_not_the_forms_path() {
        let link = RawLink::parse("https://tenant.sharepoint.com/sites/CFD/Shared%20Documents/Forms/AllItems.aspx?id=%2Fsites%2FCFD%2FShared%20Documents%2FFY2027%20Packs%2FProduct").unwrap();
        match link.resolution() {
            ResolutionRequest::CanonicalPath {
                item_path,
                folder_view,
                ..
            } => {
                assert!(folder_view);
                assert_eq!(item_path, "FY2027 Packs/Product");
            }
            ResolutionRequest::OpaqueShare(_) => panic!("folder view must stay read-only"),
        }
    }

    #[test]
    fn cross_tenant_shared_wrapper_stays_opaque() {
        let link = RawLink::parse("https://tenant-my.sharepoint.com/shared?listurl=https%3A%2F%2Fevil.sharepoint.com%2Fsites%2FOrg%2FDocs&id=%2Fsites%2FOrg%2FDocs%2Fa.pdf").unwrap();
        assert!(matches!(
            link.resolution(),
            ResolutionRequest::OpaqueShare(_)
        ));
    }

    #[test]
    fn invalid_urls_are_refused_without_replaying_them() {
        for value in [
            "not a url",
            "http://tenant.sharepoint.com/x",
            "https://user:pass@tenant.sharepoint.com/x",
            "https://example.com/x",
        ] {
            let error = match RawLink::parse(value) {
                Ok(_) => panic!("invalid URL was accepted"),
                Err(error) => error,
            };
            assert!(!error.contains(value));
        }
    }
}
