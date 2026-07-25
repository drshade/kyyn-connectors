#[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
const PLUGIN_NAME: &str = "graph-meetings";
#[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
const PLUGIN_KIND: &str = "meetings";

include!("../../graph-common/guest.rs");
