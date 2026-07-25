use anyhow::{Context, Result, bail};
use std::path::PathBuf;
use wit_component::ComponentEncoder;

fn main() -> Result<()> {
    let mut args = std::env::args_os().skip(1);
    let input = args.next().map(PathBuf::from);
    let output = args.next().map(PathBuf::from);
    if input.is_none() || output.is_none() || args.next().is_some() {
        bail!("usage: kyyn-plugin-componentize <core.wasm> <component.wasm>");
    }
    let input = input.expect("checked");
    let output = output.expect("checked");
    let core = std::fs::read(&input).with_context(|| format!("reading {}", input.display()))?;
    let component = ComponentEncoder::default()
        .module(&core)
        .with_context(|| format!("decoding component metadata in {}", input.display()))?
        .validate(true)
        .encode()
        .context("encoding WebAssembly component")?;
    std::fs::write(&output, component).with_context(|| format!("writing {}", output.display()))
}
