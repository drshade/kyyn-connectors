#[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
const PLUGIN_NAME: &str = "sharepoint-file";
#[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
const PLUGIN_KIND: &str = "sharepoint";

include!("../../graph-common/guest.rs");
