# kyyn-connectors

The first-party [kyyn](https://github.com/drshade/kyyn) connector repository:
the `sweep`, repository/pack, Salesforce, Microsoft Graph, and read-only
SharePoint file/folder source families, plus the authority-distinct
`file-replace`, `git-ref`, and `microsoft-file-replace` sinks.

A connector repository is code a KB pins at an immutable commit in
`connectors.ron`; configured source instances live separately in `sources.ron`.
Kyyn fetches that exact tree and verifies each declared
component before execution. This repo is what a fresh `kyyn init` pins —
and the reference example for writing your own connector.

Every advertised connector is served by a committed, digest-pinned,
direction-distinct WebAssembly component. The repository keeps four boundaries
explicit:

- `wit/source.wit` is a byte-identical vendoring of Kyyn's documented, frozen
  host/guest contract. The test gate pins its digest so a hand edit cannot
  silently change `kyyn:source@1`.
- `wit/sink.wit` is the same byte-identical gate for `kyyn:sink@1`; each sink
  component imports exactly its one host-owned write operation
  and has no ambient WASI authority.
- `connectors/sources/` contains the capability-limited guest implementations.
  Mail, calendar, chat and meeting sources share Graph machinery. SharePoint
  files use a dedicated read-only OAuth realm and a standalone guest so broad
  communication scopes cannot bleed into file consent.
- `components/sources/` and `components/sinks/` contain only direction-explicit
  executable artifacts consumers pin.
- `crates/` contains reusable, execution-neutral connector logic consumed by
  component guests; the repository has no native source executable.

`scripts/check-components.sh` reproducibly rebuilds every guest and compares
its bytes with the committed artifact. Use `--update` only for a deliberate,
reviewed artifact change, then re-pin every changed digest in `kyyn-connectors.ron`.

`sharepoint-file` accepts a canonical work/school site URL, document library,
and library-relative file or folder path. It searches and exact-matches the
site, walks stable drive/item identities through fixed-depth Graph grants, and
asks only for read-only `Sites.Read.All` consent. File bytes use the exact
`/content` evidence operation with an explicit provider-download continuation:
Kyyn follows the short-lived preauthenticated URL without returning it or the
Graph bearer token to the guest.

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
