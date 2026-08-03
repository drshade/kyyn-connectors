use anyhow::{Context, Result, bail};
use std::path::PathBuf;
use wit_component::ComponentEncoder;

/// Rust emits informational core-module custom sections (`producers`,
/// `target_features`, names) whose bytes can vary across build hosts even
/// when executable code is identical. The component contract metadata is the
/// one custom section componentization needs; discard the rest before it can
/// make a committed artifact host-specific.
fn normalized_core(core: &[u8]) -> Result<Vec<u8>> {
    let mut module = wasm_encoder::Module::new();
    for payload in wasmparser::Parser::new(0).parse_all(core) {
        let payload = payload.context("parsing core WebAssembly")?;
        if matches!(
            &payload,
            wasmparser::Payload::CustomSection(section)
                if !section.name().starts_with("component-type")
        ) {
            continue;
        }
        if let Some((id, range)) = payload.as_section() {
            module.section(&wasm_encoder::RawSection {
                id,
                data: &core[range],
            });
        }
    }
    Ok(module.finish())
}

fn main() -> Result<()> {
    let mut args = std::env::args_os().skip(1);
    let input = args.next().map(PathBuf::from);
    let output = args.next().map(PathBuf::from);
    if input.is_none() || output.is_none() || args.next().is_some() {
        bail!("usage: kyyn-connector-componentize <core.wasm> <component.wasm>");
    }
    let input = input.expect("checked");
    let output = output.expect("checked");
    let core = std::fs::read(&input).with_context(|| format!("reading {}", input.display()))?;
    let core = normalized_core(&core)?;
    let component = ComponentEncoder::default()
        .module(&core)
        .with_context(|| format!("decoding component metadata in {}", input.display()))?
        .validate(true)
        .encode()
        .context("encoding WebAssembly component")?;
    std::fs::write(&output, component).with_context(|| format!("writing {}", output.display()))
}
