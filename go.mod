module azkaban

go 1.25.0

// Pinned: go1.26.6 carries the fixes for GO-2026-6218 (net/url),
// GO-2026-6090 (crypto/tls), GO-2026-6089 and GO-2026-5026 (net/http) and
// GO-2026-5972 (encoding/asn1) — all five reachable from this code, and the
// earlier GO-2026-5856 / GO-2026-5039 / GO-2026-5037 set that 1.26.4 fixed.
// This is a network-facing sandbox with three listeners of its own, so the
// stdlib pin is part of the guarantee rather than housekeeping. # VERSION-BUMP
toolchain go1.26.6

require (
	github.com/landlock-lsm/go-landlock v0.9.0
	golang.org/x/sys v0.47.0
)

require kernel.org/pub/linux/libs/security/libcap/psx v1.2.77 // indirect
