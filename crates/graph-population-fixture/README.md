# Graph population fixture

This native-only crate freezes ADR 0037's synthetic Microsoft Graph provider
conversations for the single resumable workload meeting connector. The closed
corpus independently pins its bounded calendar selection, organizer routing,
occurrence deduplication and artifact outcome distinctions.

The fixtures use reserved `example.test` identities and synthetic provider
coordinates. They contain no tenant or KB material. Each scenario records
bounded requests and provider responses. They are provider examples, not claims
that Kyyn controls authority outside its contained connector boundary.

The provider shapes were reconciled on 2026-08-24 against Microsoft's current
Graph documentation for
[calendarView](https://learn.microsoft.com/graph/api/user-list-calendarview),
[call transcript content](https://learn.microsoft.com/graph/api/calltranscript-get),
and [attendance reports](https://learn.microsoft.com/graph/api/meetingattendancereport-list).
