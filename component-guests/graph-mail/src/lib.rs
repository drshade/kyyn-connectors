#[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
const PLUGIN_NAME: &str = "graph-mail";
#[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
const PLUGIN_KIND: &str = "mail";

include!("../../graph-common/guest.rs");
