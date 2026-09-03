module azkaban

go 1.25.0

// Pinned: go1.26.6 carries the fixes for GO-2026-6090 (crypto/tls),
// GO-2026-6089 (net/http), GO-2026-5972 (encoding/asn1) and GO-2026-5026
// (net/http via x/net/idna), which govulncheck reports as reachable from the
// container-filter proxy. 1.26.8 is the current patch of that line, so the pin
// tracks the whole line rather than the single release that closed them.
// # VERSION-BUMP
toolchain go1.26.8

require (
	github.com/landlock-lsm/go-landlock v0.9.0
	golang.org/x/sys v0.47.0
)

require kernel.org/pub/linux/libs/security/libcap/psx v1.2.77 // indirect
