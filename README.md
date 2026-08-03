# kyyn-connectors

The first-party [kyyn](https://github.com/drshade/kyyn) connector repository:
the `sweep`, repository/pack, Salesforce, and Microsoft Graph source families.

A connector repository is code a KB pins at an immutable commit in
`connectors.ron`; configured source instances live separately in `sources.ron`.
Kyyn fetches that exact tree and verifies each declared
component before execution. This repo is what a fresh `kyyn init` pins —
and the reference example for writing your own source.

Every advertised connector is served by a committed, digest-pinned
`kyyn:source@1` WebAssembly component. The repository keeps four boundaries
explicit:

- `wit/source.wit` is a byte-identical vendoring of Kyyn's documented, frozen
  host/guest contract. The test gate pins its digest so a hand edit cannot
  silently change `kyyn:source@1`.
- `connectors/sources/` contains the capability-limited guest implementations.
  The Microsoft family uses one shared Graph runtime for auth, bounded HTTP,
  paging, normalization, and evidence construction, with tiny per-connector
  entry crates selecting each fetch mode.
- `components/sources/` contains only source executable artifacts consumers pin;
  `components/sinks/` enters with ADR 0020.
- `crates/` contains reusable, execution-neutral connector logic consumed by
  component guests; the repository has no native source executable.

`scripts/check-components.sh` reproducibly rebuilds every guest and compares
its bytes with the committed artifact. Use `--update` only for a deliberate,
reviewed artifact change, then re-pin every changed digest in `kyyn-connectors.ron`.

`sharepoint-file` remains implemented and reproducibly built but is not
advertised in `kyyn-connectors.ron`: Graph returns a pre-authorized download URL
with a dynamic origin/path, while `kyyn:source@1` intentionally accepts only an
exact HTTPS origin and exact/fixed-depth path grants. It will return only under
an explicitly reviewed authority contract; the old wildcard-host consent is
not carried through the clean break.

There is deliberately no raw Kyyn-KB import connector. KB identity, schema and
accept authority do not cross repositories; a future federation source may
publish an immutable query result bound to the producer truth commit. Until
that contract exists, ordinary `git-repo` evidence remains repository content,
not another KB's ontology.
