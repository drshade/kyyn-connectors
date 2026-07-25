#[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
const PLUGIN_NAME: &str = "graph-calendar";
#[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
const PLUGIN_KIND: &str = "calendar";

// One source of truth for Graph auth, HTTP bounds, paging, normalization, and
// evidence construction. Each Graph-family component includes this runtime
// with a compile-time plugin identity and only its mode-specific fetch path.
include!("../../graph-common/guest.rs");
