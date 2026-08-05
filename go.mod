module azkaban

go 1.25.0

// Pinned: go1.26.4/1.26.5 carry the fixes for GO-2026-5856 (crypto/tls),
// GO-2026-5039 (net/textproto) and GO-2026-5037 (crypto/x509), which
// govulncheck reports as reachable from this code. # VERSION-BUMP
toolchain go1.26.5

require (
	github.com/landlock-lsm/go-landlock v0.9.0
	golang.org/x/sys v0.47.0
)

require kernel.org/pub/linux/libs/security/libcap/psx v1.2.77 // indirect
