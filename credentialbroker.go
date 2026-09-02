// credentialbroker.go — hand the jail a signing oracle instead of a secret.
//
// WHY THIS EXISTS: azkaban's credential model is hide or hand over. A secret is
// either masked (maskPaths) or given to the jail in full, where anything inside
// can read it for the life of the run. docs/configuration.md concedes the
// consequence directly: for `gh pr create` you would have to hand the jail a
// token via `env GH_TOKEN`, which *is* stealable.
//
// The broker moves the credential out. The jail is pointed at a loopback
// endpoint over PLAIN HTTP; the broker attaches the real credential and makes
// the TLS connection upstream itself. The token never exists inside the jail —
// not in the environment, not on the filesystem, not in argv.
//
// This is deliberately NOT the egress proxy's job, and the difference matters:
// that one relays a CONNECT tunnel without looking inside, which is what keeps
// it out of the TLS-interception business. A broker has to see the request to
// attach a header, so the jail must not be speaking TLS to it in the first
// place. Plain HTTP to loopback is what makes both properties true at once —
// no CA is ever shipped into the jail.
//
// Scoped per route, because that is the entire point of doing it here rather
// than with an environment variable: a token in the jail can do everything the
// token can do, and a token behind a broker can do only what the route policy
// allows. Clone and fetch are permitted; push is not, unless asked for.
package main

import (
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"
)

// credentialProvider is one brokered upstream.
type credentialProvider struct {
	Name string
	// Upstream is where requests are forwarded, over TLS.
	Upstream string
	// EnvNames are the host variables searched for the secret, in order.
	EnvNames []string
	// Header builds the upstream authorization header value from the secret.
	Header func(secret string) (name, value string)
	// Allow is the route policy: a request matching none of these is refused.
	Allow []route
	// WriteAllow is added to Allow only when the caller opts into writes.
	WriteAllow []route
	// Env is what the jail is given so its tooling uses the broker.
	Env func(base string) map[string]string
}

// route is one permitted request shape.
type route struct {
	Methods []string
	Path    *regexp.Regexp
	What    string // for the refusal message and the audit record
}

func (r route) matches(req *http.Request) bool {
	if !r.Path.MatchString(req.URL.Path) {
		return false
	}
	for _, m := range r.Methods {
		if m == req.Method {
			return true
		}
	}
	return false
}

// providers is the set azkaban knows how to broker.
//
// One entry, on purpose. The issue this implements says to start narrow with
// the case the docs currently tell you to avoid, and a second provider added
// without someone actually using it is a route policy nobody has checked.
var providers = map[string]*credentialProvider{
	"github": {
		Name:     "github",
		Upstream: "https://github.com",
		// GH_TOKEN first: it is the one `gh` sets and the more specific of the
		// two, so a shell with both set gets the one the user meant.
		EnvNames: []string{"GH_TOKEN", "GITHUB_TOKEN"},
		Header: func(secret string) (string, string) {
			// git over HTTPS wants Basic with the token as the password. The
			// username is ignored by GitHub but must be present.
			return "Authorization", "Basic " + base64.StdEncoding.EncodeToString(
				[]byte("x-access-token:"+secret))
		},
		Allow: []route{
			{
				Methods: []string{http.MethodGet},
				Path:    regexp.MustCompile(`/info/refs$`),
				What:    "ref discovery",
			},
			{
				Methods: []string{http.MethodPost},
				Path:    regexp.MustCompile(`/git-upload-pack$`),
				What:    "clone and fetch",
			},
		},
		WriteAllow: []route{
			{
				Methods: []string{http.MethodPost},
				Path:    regexp.MustCompile(`/git-receive-pack$`),
				What:    "push",
			},
		},
		Env: func(base string) map[string]string {
			// git's environment-only config: no file to write, which matters
			// because ~/.gitconfig is bound read-only.
			return map[string]string{
				"GIT_CONFIG_COUNT":   "1",
				"GIT_CONFIG_KEY_0":   "url." + base + "/.insteadOf",
				"GIT_CONFIG_VALUE_0": "https://github.com/",
			}
		},
	},
}

// credentialBroker is a running broker.
type credentialBroker struct {
	Addr     string
	Port     int
	Token    string
	provider *credentialProvider
	secret   string
	allow    []route
}

// startCredentialBroker resolves the secret on the host and starts listening.
//
// Resolving here — in the outer process, before the jail exists — is the whole
// mechanism. Nothing later has to be trusted with it.
func startCredentialBroker(name string, allowWrites bool) (*credentialBroker, error) {
	p, ok := providers[name]
	if !ok {
		known := make([]string, 0, len(providers))
		for k := range providers {
			known = append(known, k)
		}
		return nil, fmt.Errorf("unknown credential provider %q; known: %s", name, strings.Join(known, ", "))
	}
	secret := ""
	for _, env := range p.EnvNames {
		if v := os.Getenv(env); v != "" {
			secret = v
			break
		}
	}
	if secret == "" {
		return nil, fmt.Errorf("no %s credential on the host: set one of %s",
			name, strings.Join(p.EnvNames, ", "))
	}
	token, err := proxyToken()
	if err != nil {
		return nil, err
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	b := &credentialBroker{
		Addr: fmt.Sprintf("127.0.0.1:%d", ln.Addr().(*net.TCPAddr).Port),
		Port: ln.Addr().(*net.TCPAddr).Port, Token: token,
		provider: p, secret: secret, allow: p.Allow,
	}
	if allowWrites {
		b.allow = append(append([]route{}, p.Allow...), p.WriteAllow...)
	}
	srv := &http.Server{
		Handler:           http.HandlerFunc(b.serve),
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       2 * time.Minute,
	}
	go srv.Serve(ln)
	return b, nil
}

// BaseURL is what the jail is pointed at, including the session credential.
func (b *credentialBroker) BaseURL() string {
	return "http://azkaban:" + b.Token + "@" + b.Addr
}

// JailEnv is the environment the child needs to use the broker.
func (b *credentialBroker) JailEnv() map[string]string {
	return b.provider.Env(b.BaseURL())
}

func (b *credentialBroker) serve(w http.ResponseWriter, r *http.Request) {
	// The broker listens on loopback, which every process on the host shares.
	// Without this, any of them could spend this run's credential.
	_, pass, ok := parseProxyAuth(basicHeader(r))
	if !ok || !subtleEqual(pass, b.Token) {
		w.Header().Set("WWW-Authenticate", `Basic realm="azkaban"`)
		http.Error(w, "azkaban credential broker: not authorized", http.StatusUnauthorized)
		auditLog.event("credential", map[string]any{
			"provider": b.provider.Name, "decision": "denied", "reason": "bad or missing session token",
		})
		return
	}

	matched := ""
	for _, rt := range b.allow {
		if rt.matches(r) {
			matched = rt.What
			break
		}
	}
	if matched == "" {
		reason := r.Method + " " + r.URL.Path + " is not on the broker's route policy"
		// Push is the one people will hit, so name it rather than leaving them
		// to work out which route was missing.
		for _, rt := range b.provider.WriteAllow {
			if rt.matches(r) {
				reason = rt.What + " needs `credential " + b.provider.Name +
					" write` — the default policy is read-only on purpose"
			}
		}
		fmt.Fprintln(os.Stderr, "azkaban: credential broker DENIED "+reason)
		auditLog.event("credential", map[string]any{
			"provider": b.provider.Name, "decision": "denied",
			"method": r.Method, "path": r.URL.Path, "reason": reason,
		})
		http.Error(w, "azkaban credential broker: "+reason, http.StatusForbidden)
		return
	}

	upstream, err := url.Parse(b.provider.Upstream)
	if err != nil {
		http.Error(w, "azkaban credential broker: bad upstream", http.StatusInternalServerError)
		return
	}
	out, err := http.NewRequestWithContext(r.Context(), r.Method,
		upstream.String()+r.URL.RequestURI(), r.Body)
	if err != nil {
		http.Error(w, "azkaban credential broker: "+err.Error(), http.StatusBadGateway)
		return
	}
	// Copy the client's headers, minus anything that carries its credentials or
	// describes a hop that is ending here.
	for k, vs := range r.Header {
		if hopByHop(k) {
			continue
		}
		for _, v := range vs {
			out.Header.Add(k, v)
		}
	}
	out.Host = upstream.Host
	// The substitution. Set rather than added, so a client that sent its own
	// Authorization cannot stack one.
	name, value := b.provider.Header(b.secret)
	out.Header.Set(name, value)

	resp, err := http.DefaultClient.Do(out)
	if err != nil {
		auditLog.event("credential", map[string]any{
			"provider": b.provider.Name, "decision": "upstream-error", "error": err.Error(),
		})
		http.Error(w, "azkaban credential broker: upstream: "+err.Error(), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	auditLog.event("credential", map[string]any{
		"provider": b.provider.Name, "decision": "allowed", "route": matched,
		"method": r.Method, "path": r.URL.Path, "status": resp.StatusCode,
	})
	for k, vs := range resp.Header {
		if hopByHop(k) {
			continue
		}
		for _, v := range vs {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(resp.StatusCode)
	// Streamed: a clone is a long response and buffering it would hold it whole
	// in the outer process's memory.
	_, _ = io.Copy(flushWriter{w}, resp.Body)
}

// basicHeader reads the client's credential from either header git might use.
func basicHeader(r *http.Request) string {
	if h := r.Header.Get("Authorization"); h != "" {
		return h
	}
	return r.Header.Get("Proxy-Authorization")
}

// hopByHop reports headers that must not be forwarded.
//
// Authorization is in here for a reason of its own: the client's is replaced,
// never passed through, so a jail cannot smuggle a second credential upstream.
func hopByHop(name string) bool {
	switch strings.ToLower(name) {
	case "authorization", "proxy-authorization", "connection", "keep-alive",
		"proxy-authenticate", "te", "trailer", "transfer-encoding", "upgrade":
		return true
	}
	return false
}

// flushWriter pushes each chunk out as it arrives. git's pack protocol is
// interactive; buffering it stalls the client waiting for bytes the server has
// already sent.
type flushWriter struct{ w http.ResponseWriter }

func (f flushWriter) Write(p []byte) (int, error) {
	n, err := f.w.Write(p)
	if fl, ok := f.w.(http.Flusher); ok {
		fl.Flush()
	}
	return n, err
}

// parseCredentialDirective reads a `credential <provider> [write]` line.
func parseCredentialDirective(val string) (name string, write bool, err error) {
	fields := strings.Fields(val)
	if len(fields) == 0 {
		return "", false, errors.New("credential needs a provider name")
	}
	name = fields[0]
	for _, f := range fields[1:] {
		if f != "write" {
			return "", false, fmt.Errorf("unknown credential option %q; only `write` is understood", f)
		}
		write = true
	}
	return name, write, nil
}
