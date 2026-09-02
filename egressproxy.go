// egressproxy.go — CONNECT-tunnel proxy in front of the jail's outbound TCP.
//
// WHY THIS EXISTS: `--net-ports` restricts outbound TCP *ports* at the kernel
// via Landlock's ConnectTCP. That closes localhost services and LAN scanning
// and cannot express "only api.anthropic.com" — which is the shape of the rule
// people actually want, and the reason credential masking is weaker than it
// reads. Masking stops a token being destroyed; it does nothing to stop one
// being read and sent somewhere.
//
// It runs in the OUTER (host) process. The jail is handed HTTP_PROXY /
// HTTPS_PROXY pointing at it, and Landlock's ConnectTCP allowlist is narrowed
// to the proxy's port, so a client that ignores the proxy variables cannot
// route around it — the kernel refuses the connect.
//
// Three deliberate choices, each of which is the difference between a filter
// and the appearance of one:
//
//  1. NO TLS INTERCEPTION. A CONNECT target is checked against the allowlist and
//     then raw bytes are relayed. Shipping a CA into the jail would buy L7
//     visibility at the cost of a much larger security surface, and this tool's
//     threat model is accidental destruction, not a determined attacker.
//  2. DNS IS RESOLVED HERE, and the resolved addresses are checked before the
//     dial. An allowed hostname whose A record points at 169.254.169.254 or
//     127.0.0.1 is exactly how an allowlist gets walked past.
//  3. THE DIAL GOES TO THE RESOLVED IP, not to the hostname again. Resolving
//     twice is a TOCTOU window a rebinding record is designed to fit through.
//
// What this is NOT: a boundary against a determined attacker inside the jail.
// UDP is untouched, so DNS itself is a covert channel, and a client that speaks
// raw TCP on the proxy port to something else is bounded only by the port
// number. See the KNOWN ESCAPE VECTORS block in main.go.
package main

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"strings"
	"time"
)

// egressProxy is a running filter, and what the caller needs to wire it up.
type egressProxy struct {
	Addr  string // 127.0.0.1:port, for HTTP_PROXY
	Port  int    // for the Landlock ConnectTCP allowlist
	Token string // per-run credential; see proxyToken
	hosts []string
}

// proxyToken is a per-run bearer credential.
//
// The proxy listens on loopback, which every process on the host shares — so
// without this, any other local process could use the jail's egress allowlist,
// and more importantly a jailed process could not be distinguished from one.
// 256 bits from crypto/rand, handed to the child in HTTP_PROXY's userinfo and
// never written to the audit log.
func proxyToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// startEgressProxy - Listens on loopback and filters CONNECT by host.
func startEgressProxy(hosts []string) (*egressProxy, error) {
	if len(hosts) == 0 {
		return nil, errors.New("no hosts allowed; --net-host or `net <host>` in the config")
	}
	token, err := proxyToken()
	if err != nil {
		return nil, err
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	port := ln.Addr().(*net.TCPAddr).Port
	p := &egressProxy{
		Addr:  fmt.Sprintf("127.0.0.1:%d", port),
		Port:  port,
		Token: token,
		hosts: hosts,
	}
	srv := &http.Server{
		Handler: http.HandlerFunc(p.serve),
		// No WriteTimeout: a tunnel legitimately stays open for the length of a
		// download or a streaming API response, and a deadline there would cut
		// it off mid-transfer.
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       2 * time.Minute,
	}
	go srv.Serve(ln)
	return p, nil
}

func (p *egressProxy) serve(w http.ResponseWriter, r *http.Request) {
	if !p.authorized(r) {
		// 407 rather than 403: this is the proxy refusing the client, not the
		// origin refusing the request, and the distinction is what tells a
		// human it is azkaban talking.
		w.Header().Set("Proxy-Authenticate", `Basic realm="azkaban"`)
		http.Error(w, "azkaban egress proxy: not authorized", http.StatusProxyAuthRequired)
		auditLog.event("egress", map[string]any{"decision": "denied", "reason": "bad or missing proxy token"})
		return
	}
	if r.Method != http.MethodConnect {
		// Plain HTTP through a proxy is an absolute-URI request. Refused rather
		// than forwarded: it would mean this process reading and relaying
		// cleartext bodies on the jail's behalf, which is a much larger thing
		// to get right than a tunnel, and everything worth allowing speaks TLS.
		p.deny(w, r.Host, "plain HTTP through the proxy is not supported; use https://")
		return
	}
	p.tunnel(w, r)
}

// authorized checks the per-run token, in constant time on length at least.
func (p *egressProxy) authorized(r *http.Request) bool {
	_, pass, ok := parseProxyAuth(r.Header.Get("Proxy-Authorization"))
	return ok && subtleEqual(pass, p.Token)
}

func (p *egressProxy) tunnel(w http.ResponseWriter, r *http.Request) {
	host, port, err := net.SplitHostPort(r.Host)
	if err != nil {
		p.deny(w, r.Host, "malformed CONNECT target")
		return
	}
	if !hostAllowed(p.hosts, host) {
		p.deny(w, r.Host, "host is not on the egress allowlist")
		return
	}

	// Resolve here, and check what came back. An allowed name that resolves to
	// a link-local or loopback address is the rebinding case: the allowlist
	// says yes and the connection goes somewhere the jail was never meant to
	// reach — the cloud metadata service being the one that matters.
	addrs, err := net.DefaultResolver.LookupNetIP(r.Context(), "ip", host)
	if err != nil || len(addrs) == 0 {
		p.deny(w, r.Host, "cannot resolve "+host)
		return
	}
	target := addrs[0]
	for _, a := range addrs {
		if reason := unroutable(a); reason != "" {
			p.deny(w, r.Host, host+" resolves to "+a.String()+" ("+reason+")")
			return
		}
	}

	// Dial the ADDRESS, not the name. Passing the hostname would resolve a
	// second time, and the window between the two checks is exactly what a
	// short-TTL rebinding record is built to fit through.
	upstream, err := (&net.Dialer{Timeout: 15 * time.Second}).DialContext(
		r.Context(), "tcp", net.JoinHostPort(target.String(), port))
	if err != nil {
		p.deny(w, r.Host, "upstream unreachable: "+err.Error())
		return
	}
	defer upstream.Close()

	hj, ok := w.(http.Hijacker)
	if !ok {
		p.deny(w, r.Host, "cannot hijack the connection")
		return
	}
	client, _, err := hj.Hijack()
	if err != nil {
		return
	}
	defer client.Close()

	if _, err := client.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n")); err != nil {
		return
	}
	auditLog.event("egress", map[string]any{
		"decision": "allowed", "host": host, "port": port, "addr": target.String(),
	})

	// Raw bytes both ways, and nothing looks at them. This is the whole of the
	// "no TLS interception" promise.
	done := make(chan struct{}, 2)
	go func() { _, _ = io.Copy(upstream, client); done <- struct{}{} }()
	go func() { _, _ = io.Copy(client, upstream); done <- struct{}{} }()
	<-done
}

// deny refuses one request, loudly.
//
// Loudly because a silently filtered connection looks like the network being
// down, which is the misdiagnosis this whole layer exists to avoid — the same
// reasoning as the docker filter's JSON-shaped 403.
func (p *egressProxy) deny(w http.ResponseWriter, target, reason string) {
	fmt.Fprintln(os.Stderr, "azkaban: egress DENIED "+target+": "+reason)
	auditLog.event("egress", map[string]any{
		"decision": "denied", "host": target, "reason": reason,
	})
	http.Error(w, "azkaban egress proxy: "+reason, http.StatusForbidden)
}

// hostAllowed matches a CONNECT host against the allowlist.
//
// Exact match, or a single leading `*.` wildcard covering subdomains but not
// the bare domain — `*.example.com` allows `api.example.com` and not
// `example.com`, because those are different decisions and conflating them is
// how an allowlist quietly widens. Case-insensitive; a trailing dot on the
// fully-qualified form is stripped, since `example.com.` and `example.com` are
// the same host and only one of them would otherwise match.
func hostAllowed(allow []string, host string) bool {
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	for _, a := range allow {
		a = strings.ToLower(strings.TrimSuffix(a, "."))
		if a == host {
			return true
		}
		if suffix, ok := strings.CutPrefix(a, "*."); ok {
			if strings.HasSuffix(host, "."+suffix) {
				return true
			}
		}
	}
	return false
}

// unroutable reports why an address must not be dialled on the jail's behalf,
// or "" when it is fine.
//
// The metadata service is the one that matters: 169.254.169.254 hands out
// instance credentials to anything that asks, and an allowlisted hostname with
// an A record pointing at it is a complete bypass of everything above.
func unroutable(a netip.Addr) string {
	switch {
	case a.IsLoopback():
		return "loopback — the point of the port allowlist is that the jail cannot reach local services"
	case a.IsLinkLocalUnicast(), a.IsLinkLocalMulticast():
		return "link-local — this is where cloud metadata services live"
	case a.IsPrivate():
		return "private — a name resolving into your LAN is not egress"
	case a.IsUnspecified(), a.IsMulticast():
		return "not a routable unicast address"
	}
	return ""
}

// parseProxyAuth reads a Basic Proxy-Authorization header.
func parseProxyAuth(header string) (user, pass string, ok bool) {
	const prefix = "Basic "
	if !strings.HasPrefix(header, prefix) {
		return "", "", false
	}
	raw, err := base64Decode(header[len(prefix):])
	if err != nil {
		return "", "", false
	}
	user, pass, ok = strings.Cut(raw, ":")
	return user, pass, ok
}

func base64Decode(s string) (string, error) {
	b, err := base64.StdEncoding.DecodeString(s)
	return string(b), err
}

// subtleEqual compares in constant time, so a wrong token cannot be found one
// byte at a time from the outside.
func subtleEqual(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}
