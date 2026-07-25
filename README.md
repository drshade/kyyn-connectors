# kyyn-plugins

The first-party [kyyn](https://github.com/drshade/kyyn) tap: the
`sweep`, `kb`, and Microsoft Graph family plugins.

A tap is a plugin repository a KB pins at an immutable commit in its
`sources.ron`; kyyn clones and builds it on first use. This repo is
what a fresh `kyyn init` pins — and the reference example for writing
your own tap.

Every advertised plugin is served by a committed, digest-pinned
`kyyn:tap@1` WebAssembly component. The repository keeps four boundaries
explicit:

- `wit/tap.wit` is the vendored, frozen host/guest contract.
- `component-guests/` contains the capability-limited guest implementations.
  The Microsoft family uses one shared Graph runtime for auth, bounded HTTP,
  paging, normalization, and evidence construction, with tiny per-plugin
  entry crates selecting each fetch mode.
- `components/` contains only the executable artifacts consumers pin.
- `crates/` retains the native implementations during the compatibility
  window; it is not an execution bypass for component-declared plugins.

`scripts/check-components.sh` reproducibly rebuilds every guest and compares
its bytes with the committed artifact. Use `--update` only for a deliberate,
reviewed artifact change, then re-pin every changed digest in `kyyn-tap.ron`.
