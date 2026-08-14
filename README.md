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

- `wit/source.wit`, `wit/connection.wit`, and `wit/configurator.wit` are byte-identical vendorings of
  Kyyn's documented contracts. The source guest receives governed non-secret
  connection context when needed, while authorization remains host-only.
  The test gate pins their digests so a hand edit cannot silently change
  `kyyn:source@1`, `kyyn:connection@1`, or `kyyn:configurator@1`.
- `wit/sink.wit` is the same byte-identical gate for `kyyn:sink@1`; each sink
  component imports exactly its one host-owned write operation
  and has no ambient WASI authority.
- `connectors/sources/` contains the capability-limited guest implementations.
  Mail, calendar, chat and meeting sources share Graph machinery. Every remote
  source declares a least-privilege provider capability and imports no secret
  storage; one named Microsoft or Salesforce connection can therefore serve
  several independently configured sources without broadening any source's
  request authority.
- `connectors/configurators/` contains bounded owner-setup guests. They receive
  only declared transient and durable fields, can make only manifest-reviewed
  requests, and return closed durable configuration; provider URLs and
  diagnostics therefore stay in this repository rather than the Kyyn engine.
- `components/sources/` and `components/sinks/` contain only direction-explicit
  executable artifacts consumers pin. `components/configurators/` contains the
  equally digest-pinned setup guests.
- `crates/` contains reusable, execution-neutral connector logic consumed by
  component guests; the repository has no native source executable.

`scripts/check-components.sh` reproducibly rebuilds every guest and compares
its bytes with the committed artifact. Use `--update` only for a deliberate,
reviewed artifact change, then re-pin every changed digest in `kyyn-connectors.ron`.

`microsoft-files` owns the complete SharePoint/OneDrive setup journey. Its
configurator consumes an owner-ephemeral browser link, resolves it through
exact GET-only Graph grants, and returns only canonical drive/item identity and
a safe display name. Kyyn neither recognizes Microsoft URLs nor stores the
submitted link. The source then observes that exact file or recursively filters
that exact folder. File bytes use the exact
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

The Microsoft provider supports two explicit principal classes. Delegated
human Connections retain the existing device-code journey and local refresh
credential. Workload application Connections use the `client-secret` recipe:
the accepted Connection names an explicit tenant and Entra application id,
while each invocation binds `client-secret` from a named environment variable,
absolute regular file, or bounded stdin. The provider exchanges it through the
tenant token endpoint using the OAuth client-credentials `.default` scope and
returns only the short-lived bearer authorization to Kyyn; it writes no
workload credential or token to durable Connection state.

Only `microsoft-files` and `microsoft-file-replace` advertise workload
compatibility. The mail, calendar, chats, and meetings connectors retain
delegated-only `/me` semantics. The Entra administrator must separately grant
the workload application the real Microsoft Graph application permissions its
selected file consumer needs. Prefer SharePoint resource-scoped selected
permissions where the deployment supports them; otherwise tenant-wide grants
remain visible deployment authority and are not narrowed by Kyyn's exact
`/drives/...` request boundary.

There is deliberately no raw Kyyn-KB import connector. KB identity, schema and
accept authority do not cross repositories; a future federation source may
publish an immutable query result bound to the producer truth commit. Until
that contract exists, ordinary `git-repo` evidence remains repository content,
not another KB's ontology.
