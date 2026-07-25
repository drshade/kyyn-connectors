# kyyn-plugins

The first-party [kyyn](https://github.com/drshade/kyyn) tap: the
`sweep`, `kb`, and Microsoft Graph family plugins.

A tap is a plugin repository a KB pins at an immutable commit in its
`sources.ron`; kyyn clones and builds it on first use. This repo is
what a fresh `kyyn init` pins — and the reference example for writing
your own tap.

Plugins are migrating from the temporary native harness to one committed,
digest-pinned `kyyn:tap@1` WebAssembly component per advertised plugin.
`scripts/check-components.sh` reproducibly rebuilds the migrated guests
against the vendored frozen WIT and checks their bytes; use `--update` only
for a deliberate reviewed artifact change, then re-pin every changed digest
in `kyyn-tap.ron`.
