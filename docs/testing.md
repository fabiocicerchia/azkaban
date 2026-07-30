# Tests

[← README](../README.md)

```bash
make test          # or: CGO_ENABLED=0 go test ./...
```

Every test that starts a real jail runs against a throwaway `$HOME` built under
`/var/tmp` and deleted afterwards, populated with content-tagged decoys
(`PRIVATE-KEY-MUST-NEVER-BE-VISIBLE` and friends) so a test can prove a file was
neither read nor destroyed. `guardReason()` refuses to run if that fake home is,
contains, or sits inside the real one — re-checked on every invocation, and unit
tested itself, because it is the one thing that must never silently break. See
[the incident](../README.md#this-actually-happened) for why.

`/var/tmp` rather than `/tmp` on purpose: azkaban puts `/tmp` on Landlock's
writable list, so a fake home there would inherit write access and mask the
restrictions under test.

Two naming conventions carry meaning:

- `Test<Area>_<Behaviour>` — a guarantee azkaban makes; a failure is a bug.
- `TestKnownGap_<Behaviour>` — a documented weakness, asserted **as it is today**.
  Fixing the gap fails the test on purpose, forcing the assertion and these docs
  to be updated together.

The docker integration test needs a real daemon and is skipped unless
`AZKABAN_DOCKER_IT=1`. Everything else, including the socket filter tests
(served by a fake daemon), runs offline and touches nothing.
