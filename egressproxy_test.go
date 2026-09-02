package main

import (
	"encoding/base64"
	"io"
	"net/http"
	"net/netip"
	"strings"
	"testing"
)

func TestHostAllowlistMatchesExactlyAndByWildcard(t *testing.T) {
	allow := []string{"api.anthropic.com", "*.githubusercontent.com", "REGISTRY.NPMJS.ORG"}
	for _, tc := range []struct {
		host string
		want bool
	}{
		{"api.anthropic.com", true},
		{"api.anthropic.com.", true},        // FQDN form is the same host
		{"API.Anthropic.COM", true},         // DNS is case-insensitive
		{"raw.githubusercontent.com", true}, // wildcard
		{"objects.raw.githubusercontent.com", true},
		{"registry.npmjs.org", true},           // allowlist entry cased oddly
		{"anthropic.com", false},               // not a subdomain of itself
		{"githubusercontent.com", false},       // *.x does not cover bare x
		{"evil-api.anthropic.com", false},      // not a label boundary
		{"api.anthropic.com.evil.test", false}, // suffix, not the host
		{"notgithubusercontent.com", false},
	} {
		if got := hostAllowed(allow, tc.host); got != tc.want {
			t.Errorf("hostAllowed(%q) = %v, want %v", tc.host, got, tc.want)
		}
	}
}

func TestWildcardDoesNotCoverTheBareDomain(t *testing.T) {
	// Conflating `*.example.com` with `example.com` is how an allowlist quietly
	// widens: they are different decisions and someone writing the first has
	// not made the second.
	if hostAllowed([]string{"*.example.com"}, "example.com") {
		t.Error("*.example.com must not allow example.com")
	}
	if !hostAllowed([]string{"*.example.com", "example.com"}, "example.com") {
		t.Error("naming both should allow both")
	}
}

func TestUnroutableRefusesTheAddressesThatDefeatAnAllowlist(t *testing.T) {
	for _, tc := range []struct {
		addr   string
		reason string
	}{
		// The one that matters: an allowlisted name with an A record here hands
		// out instance credentials to anything that asks.
		{"169.254.169.254", "link-local"},
		{"127.0.0.1", "loopback"},
		{"::1", "loopback"},
		{"10.0.0.5", "private"},
		{"192.168.1.1", "private"},
		{"172.16.0.1", "private"},
		{"fe80::1", "link-local"},
		{"0.0.0.0", "not a routable"},
		// 224.0.0.0/24 is the local network control block, so this lands in the
		// link-local arm first. Either way it is refused, which is the point.
		{"224.0.0.1", ""},
		{"239.1.2.3", "not a routable"},
		{"fc00::1", "private"}, // IPv6 unique-local
	} {
		a := netip.MustParseAddr(tc.addr)
		got := unroutable(a)
		if got == "" {
			t.Errorf("%s was accepted; it must not be dialled on the jail's behalf", tc.addr)
			continue
		}
		if tc.reason != "" && !strings.Contains(got, tc.reason) {
			t.Errorf("%s refused as %q, want a %q reason", tc.addr, got, tc.reason)
		}
	}
}

func TestUnroutableAllowsOrdinaryPublicAddresses(t *testing.T) {
	for _, a := range []string{"1.1.1.1", "160.79.104.10", "2606:4700::1111"} {
		if reason := unroutable(netip.MustParseAddr(a)); reason != "" {
			t.Errorf("%s refused: %s", a, reason)
		}
	}
}

func TestProxyTokenIsLongAndDifferentEveryRun(t *testing.T) {
	// The proxy listens on loopback, which every process on the host shares.
	// A guessable token means the allowlist is available to all of them.
	a, err := proxyToken()
	if err != nil {
		t.Fatal(err)
	}
	b, _ := proxyToken()
	if a == b {
		t.Fatal("two runs produced the same token")
	}
	if len(a) != 64 { // 32 bytes, hex
		t.Errorf("token is %d chars, want 64", len(a))
	}
}

func TestProxyAuthParsesBasicAndRejectsAnythingElse(t *testing.T) {
	// "azkaban:tok" base64 == YXprYWJhbjp0b2s=
	user, pass, ok := parseProxyAuth("Basic YXprYWJhbjp0b2s=")
	if !ok || user != "azkaban" || pass != "tok" {
		t.Errorf("parse = %q/%q/%v", user, pass, ok)
	}
	for _, bad := range []string{"", "Bearer tok", "Basic !!!not-base64!!!", "Basic bm9jb2xvbg=="} {
		if _, _, ok := parseProxyAuth(bad); ok {
			t.Errorf("%q was accepted", bad)
		}
	}
}

func TestStartEgressProxyRefusesAnEmptyAllowlist(t *testing.T) {
	// An empty allowlist would be a proxy that denies everything, which reads
	// as the network being broken rather than as a policy nobody wrote.
	if _, err := startEgressProxy(nil); err == nil {
		t.Fatal("want an error for an empty allowlist")
	}
}

func TestEgressProxyListensOnLoopbackOnly(t *testing.T) {
	p, err := startEgressProxy([]string{"example.com"})
	if err != nil {
		t.Fatal(err)
	}
	// Bound to 127.0.0.1 rather than 0.0.0.0: the LAN does not get to use this
	// jail's egress allowlist.
	if !strings.HasPrefix(p.Addr, "127.0.0.1:") {
		t.Errorf("listening on %s, want loopback", p.Addr)
	}
	if p.Port == 0 {
		t.Error("no port allocated")
	}
}

// A real request through the real proxy: the filter has to work as a filter,
// not just as a set of pure functions that agree with their tests.
func TestEgressProxyEndToEnd(t *testing.T) {
	p, err := startEgressProxy([]string{"allowed.example"})
	if err != nil {
		t.Fatal(err)
	}
	auth := "Basic " + base64.StdEncoding.EncodeToString([]byte("azkaban:"+p.Token))

	do := func(target, authHeader string) (int, string) {
		req, _ := http.NewRequest(http.MethodConnect, "http://"+p.Addr, nil)
		req.Host = target
		req.URL.Host = p.Addr
		if authHeader != "" {
			req.Header.Set("Proxy-Authorization", authHeader)
		}
		resp, err := (&http.Client{}).Do(req)
		if err != nil {
			t.Fatalf("%s: %v", target, err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, string(b)
	}

	if code, _ := do("allowed.example:443", ""); code != http.StatusProxyAuthRequired {
		t.Errorf("no token = %d, want 407", code)
	}
	if code, _ := do("allowed.example:443", "Basic "+base64.StdEncoding.EncodeToString([]byte("azkaban:wrong"))); code != http.StatusProxyAuthRequired {
		t.Errorf("wrong token = %d, want 407", code)
	}
	code, body := do("blocked.example:443", auth)
	if code != http.StatusForbidden || !strings.Contains(body, "not on the egress allowlist") {
		t.Errorf("blocked host = %d %q", code, body)
	}
	// Allowed, but unresolvable here — the point is that it got past the
	// allowlist and failed at DNS, not at the filter.
	code, body = do("allowed.example:443", auth)
	if code != http.StatusForbidden || !strings.Contains(body, "cannot resolve") {
		t.Errorf("allowed host = %d %q, want it to reach the resolver", code, body)
	}
}
