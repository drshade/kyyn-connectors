# kyyn-plugins

The first-party [kyyn](https://github.com/drshade/kyyn) tap: the
`sweep`, `kb`, and Microsoft Graph family plugins.

A tap is a plugin repository a KB pins at an immutable commit in its
`sources.ron`; Kyyn fetches that exact tree and verifies each declared
component before execution. This repo is what a fresh `kyyn init` pins —
and the reference example for writing your own tap.

Every advertised plugin is served by a committed, digest-pinned
`kyyn:tap@1` WebAssembly component. The repository keeps four boundaries
explicit:

- `wit/tap.wit` is a byte-identical vendoring of Kyyn's documented, frozen
  host/guest contract. The test gate pins its digest so a hand edit cannot
  silently change `kyyn:tap@1`.
- `component-guests/` contains the capability-limited guest implementations.
  The Microsoft family uses one shared Graph runtime for auth, bounded HTTP,
  paging, normalization, and evidence construction, with tiny per-plugin
  entry crates selecting each fetch mode.
- `components/` contains only the executable artifacts consumers pin.
- `crates/` contains reusable provider-domain logic and native unit-test
  seams consumed by the component guest adapters; the repository has no
  native tap executable.

`scripts/check-components.sh` reproducibly rebuilds every guest and compares
its bytes with the committed artifact. Use `--update` only for a deliberate,
reviewed artifact change, then re-pin every changed digest in `kyyn-tap.ron`.

SharePoint downloads use Graph's pre-authorized
`@microsoft.graph.downloadUrl` without a bearer token. The current consent
allows provider download hosts under `*.sharepoint.com`; a personal-OneDrive
download returned from another CDN family is refused rather than widening
network authority implicitly. Add a reviewed suffix only when field evidence
identifies the exact provider-owned host family.
