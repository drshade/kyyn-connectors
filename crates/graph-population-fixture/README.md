# Graph population fixture

This native-only crate freezes ADR 0037's synthetic Microsoft Graph provider
conversations before the workload connector implementations land. Connector
tests consume the same closed corpus rather than carrying per-component mock
interpretations.

The fixtures use reserved `example.test` identities and synthetic provider
coordinates. They contain no tenant or KB material. Each scenario records the
ordered requests, retry responses, invocation boundaries, interruption point
and expected publication outcome. They are provider examples, not claims that
Kyyn controls authority outside its contained connector boundary.

The provider shapes were reconciled on 2026-08-24 against Microsoft's current
Graph documentation for
[calendarView](https://learn.microsoft.com/graph/api/user-list-calendarview),
[call transcript content](https://learn.microsoft.com/graph/api/calltranscript-get),
and [audit query listing](https://learn.microsoft.com/graph/api/security-auditcoreroot-list-auditlogqueries).
The transcript adversary deliberately exercises the documented `Accept`
fallback when speaker attribution is disabled.
