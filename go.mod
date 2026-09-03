module azkaban

go 1.25.0

// Pinned: the 1.26.6+ line carries the fixes for GO-2026-6218 (net/url),
// GO-2026-6090 (crypto/tls), GO-2026-6089 and GO-2026-5026 (net/http, the
// latter via x/net/idna) and GO-2026-5972 (encoding/asn1), plus the earlier
// GO-2026-5856 / GO-2026-5039 / GO-2026-5037 set that 1.26.4 closed. All of
// them are reachable from this code — govulncheck reaches them through the
// container-filter proxy, and this is a network-facing sandbox with three
// listeners of its own, so the stdlib pin is part of the guarantee rather than
// housekeeping. 1.26.8 is the current patch, so the pin tracks the line rather
// than the single release that closed any one of them. # VERSION-BUMP
toolchain go1.26.8

require (
	github.com/landlock-lsm/go-landlock v0.10.0
	golang.org/x/sys v0.47.0
)

require kernel.org/pub/linux/libs/security/libcap/psx v1.2.77 // indirect
