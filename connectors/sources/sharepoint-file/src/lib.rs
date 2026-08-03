#[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
const CONNECTOR_NAME: &str = "sharepoint-file";
#[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
const CONNECTOR_KIND: &str = "sharepoint";

include!("../../graph-common/guest.rs");
