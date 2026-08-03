#[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
const CONNECTOR_NAME: &str = "graph-meetings";
#[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
const CONNECTOR_KIND: &str = "meetings";

include!("../../graph-common/guest.rs");
