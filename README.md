# kyyn-connectors

The first-party [kyyn](https://github.com/drshade/kyyn) connector repository:
the `sweep`, repository/pack, Salesforce, Microsoft Graph, and read-only
SharePoint file/folder source families, plus the authority-distinct
`file-replace`, `git-ref`, and `microsoft-file-replace` sinks.

A connector repository is code a KB pins at an immutable commit in
`connectors.ron`; reusable provider accounts live in `connections.ron`, while
configured source and sink instances select those named connections from
`sources.ron` and `sinks.ron`.
Kyyn fetches that exact tree and verifies each declared
component before execution. This repo is what a fresh `kyyn init` pins —
and the reference example for writing your own connector.

Every advertised connector is served by a committed, digest-pinned,
direction-distinct WebAssembly component. The repository keeps five boundaries
explicit:

- `wit/source.wit` and `wit/connection.wit` are byte-identical vendorings of
  Kyyn's documented contracts. The source guest receives governed non-secret
  connection context when needed, while authorization remains host-only.
  The test gate pins their digests so a hand edit cannot silently change
  `kyyn:source@1` or `kyyn:connection@1`.
- `wit/sink.wit` is the same byte-identical gate for `kyyn:sink@1`; each sink
  component imports exactly its one host-owned write operation
  and has no ambient WASI authority.
- `connectors/sources/` contains the capability-limited guest implementations.
  Mail, calendar, chat and meeting sources share Graph machinery. Every remote
  source declares a least-privilege provider capability and imports no secret
  storage; one named Microsoft or Salesforce connection can therefore serve
  several independently configured sources without broadening any source's
  request authority.
- `components/sources/` and `components/sinks/` contain only direction-explicit
  executable artifacts consumers pin.
- `crates/` contains reusable, execution-neutral connector logic consumed by
  component guests; the repository has no native source executable.

`scripts/check-components.sh` reproducibly rebuilds every guest and compares
its bytes with the committed artifact. Use `--update` only for a deliberate,
reviewed artifact change, then re-pin every changed digest in `kyyn-connectors.ron`.

`microsoft-files` accepts canonical SharePoint/OneDrive drive and item identity
expanded by Kyyn from an owner-resolved browser-link candidate. It observes
that exact file or recursively filters that exact folder through fixed-depth
GET-only Graph grants. File bytes use the exact
`/content` evidence operation with an explicit provider-download continuation:
Kyyn follows the short-lived preauthenticated URL without returning it or the
Graph bearer token to the guest. The same named Microsoft connection can be
selected by this source and by a publication sink, with `files-read` and
`files-write` capabilities reviewed independently.

`microsoft-file-replace` creates or replaces one owner-resolved SharePoint or
OneDrive file. Its guest receives only destination display text, the reviewed
expected state, and exact replacement bytes; canonical identity, Graph
transport, conditional-write headers, and the sink-only write credential stay
inside the Kyyn host.

There is deliberately no raw Kyyn-KB import connector. KB identity, schema and
accept authority do not cross repositories; a future federation source may
publish an immutable query result bound to the producer truth commit. Until
that contract exists, ordinary `git-repo` evidence remains repository content,
not another KB's ontology.
