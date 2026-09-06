package main

import (
	"encoding/base64"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// brokerReply is one round trip through the broker, already read: the status,
// the headers the jail would see, and the body.
type brokerReply struct {
	Status int
	Header http.Header
	Body   string
}

// brokerAgainst points a broker at a fake upstream and returns a function that
// makes one request through it, already read.
func brokerAgainst(t *testing.T, write bool) (*credentialBroker, func(method, path, token string) brokerReply) {
	t.Helper()
	// The upstream only has to answer: the test that asserts on what it saw
	// builds its own server, because that is the only one that needs it.
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("upstream ok"))
	}))
	t.Cleanup(upstream.Close)

	t.Setenv("GH_TOKEN", "ghp_the_real_secret")
	b, err := startCredentialBroker("github", write)
	if err != nil {
		t.Fatal(err)
	}
	b.provider = &credentialProvider{
		Name: b.provider.Name, Upstream: upstream.URL,
		EnvNames: b.provider.EnvNames, Header: b.provider.Header,
		Allow: b.provider.Allow, WriteAllow: b.provider.WriteAllow, Env: b.provider.Env,
	}

	// The reply is read and closed here rather than handed back: six tests
	// were each closing a body they did not open.
	do := func(method, path, token string) brokerReply {
		t.Helper()
		req, err := http.NewRequestWithContext(t.Context(), method, "http://"+b.Addr+path, nil)
		if err != nil {
			t.Fatal(err)
		}
		if token != "" {
			req.Header.Set("Authorization", "Basic "+
				base64.StdEncoding.EncodeToString([]byte("azkaban:"+token)))
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close() //nolint:errcheck // the body is read on the line below
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatal(err)
		}
		return brokerReply{Status: resp.StatusCode, Header: resp.Header, Body: string(body)}
	}
	return b, do
}

func TestBrokerAttachesTheCredentialUpstreamAndNeverDownstream(t *testing.T) {
	b, do := brokerAgainst(t, false)

	resp := do(http.MethodGet, "/o/r.git/info/refs?service=git-upload-pack", b.Token)
	if resp.Status != http.StatusOK {
		t.Fatalf("status = %d: %s", resp.Status, resp.Body)
	}

	// The whole point: the secret is on the wire to GitHub and nowhere the jail
	// can see it.
	if strings.Contains(resp.Body, "ghp_the_real_secret") {
		t.Fatal("the credential came back to the client")
	}
	for k, vs := range resp.Header {
		for _, v := range vs {
			if strings.Contains(v, "ghp_the_real_secret") {
				t.Fatalf("the credential leaked in header %s", k)
			}
		}
	}
}

func TestBrokerSendsTheSecretToTheUpstream(t *testing.T) {
	// Asserted against a real round trip rather than by reading the code: the
	// substitution is the feature, and a broker that forwards without it looks
	// identical until GitHub returns 401.
	var seen *http.Request
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = r.Clone(r.Context())
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	t.Setenv("GH_TOKEN", "ghp_the_real_secret")
	b, err := startCredentialBroker("github", false)
	if err != nil {
		t.Fatal(err)
	}
	b.provider.Upstream = upstream.URL
	defer func() { b.provider.Upstream = "https://github.com" }()

	req, _ := http.NewRequestWithContext(t.Context(), http.MethodGet, "http://"+b.Addr+"/o/r.git/info/refs", nil)
	req.Header.Set("Authorization", "Basic "+
		base64.StdEncoding.EncodeToString([]byte("azkaban:"+b.Token)))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()

	if seen == nil {
		t.Fatal("upstream saw nothing")
	}
	want := "Basic " + base64.StdEncoding.EncodeToString([]byte("x-access-token:ghp_the_real_secret"))
	if got := seen.Header.Get("Authorization"); got != want {
		t.Errorf("upstream Authorization = %q, want the brokered credential", got)
	}
}

func TestBrokerRefusesPushUnlessAskedFor(t *testing.T) {
	b, do := brokerAgainst(t, false)

	// Clone and fetch are the default policy; push is the thing that changes
	// someone else's repository, and a token in the jail could do it freely.
	for _, ok := range []struct {
		method, path string
	}{
		{http.MethodGet, "/o/r.git/info/refs?service=git-upload-pack"},
		{http.MethodPost, "/o/r.git/git-upload-pack"},
	} {
		resp := do(ok.method, ok.path, b.Token)
		if resp.Status == http.StatusForbidden {
			t.Errorf("%s %s was refused; it is on the read policy", ok.method, ok.path)
		}
	}

	resp := do(http.MethodPost, "/o/r.git/git-receive-pack", b.Token)
	if resp.Status != http.StatusForbidden {
		t.Fatalf("push = %d, want 403", resp.Status)
	}
	// The refusal has to name the fix, or someone will conclude the broker is
	// broken rather than that it is doing its job.
	if !strings.Contains(resp.Body, "credential github write") {
		t.Errorf("refusal = %q, want it to name the opt-in", resp.Body)
	}
}

func TestBrokerAllowsPushWhenAskedFor(t *testing.T) {
	b, do := brokerAgainst(t, true)
	resp := do(http.MethodPost, "/o/r.git/git-receive-pack", b.Token)
	if resp.Status == http.StatusForbidden {
		t.Errorf("push refused despite `write`: %s", resp.Body)
	}
}

func TestBrokerRefusesAnythingOffTheRoutePolicy(t *testing.T) {
	b, do := brokerAgainst(t, true)
	// Scoping per route is the entire reason for brokering rather than setting
	// GH_TOKEN: a token in the jail can do everything the token can do.
	for _, path := range []string{
		"/api/v3/user", "/settings/tokens", "/o/r.git/git-upload-pack/../../etc",
	} {
		resp := do(http.MethodGet, path, b.Token)
		if resp.Status != http.StatusForbidden {
			t.Errorf("GET %s = %d, want 403", path, resp.Status)
		}
	}
}

func TestBrokerRequiresTheSessionToken(t *testing.T) {
	b, do := brokerAgainst(t, false)
	// Loopback is shared with every process on the host; without this any of
	// them could spend this run's credential.
	for _, tok := range []string{"", "wrong", b.Token + "x"} {
		resp := do(http.MethodGet, "/o/r.git/info/refs", tok)
		if resp.Status != http.StatusUnauthorized {
			t.Errorf("token %q = %d, want 401", tok, resp.Status)
		}
	}
}

func TestBrokerDoesNotForwardTheClientsOwnAuthorization(t *testing.T) {
	// A jail that sets its own Authorization must not be able to stack a second
	// credential onto the brokered request.
	if !hopByHop("Authorization") || !hopByHop("proxy-authorization") {
		t.Error("Authorization must not be forwarded upstream")
	}
}

func TestBrokerRefusesToStartWithNoCredentialOnTheHost(t *testing.T) {
	t.Setenv("GH_TOKEN", "")
	t.Setenv("GITHUB_TOKEN", "")
	// Starting anyway would produce a broker that forwards unauthenticated
	// requests and a jail that reports a mysterious 401 from GitHub.
	if _, err := startCredentialBroker("github", false); err == nil {
		t.Fatal("want an error when there is nothing to broker")
	}
}

func TestBrokerRejectsAnUnknownProvider(t *testing.T) {
	if _, err := startCredentialBroker("gitlab", false); err == nil {
		t.Fatal("want an error for a provider with no route policy")
	}
}

func TestCredentialDirectiveParsing(t *testing.T) {
	for _, tc := range []struct {
		in    string
		name  string
		write bool
		bad   bool
	}{
		{in: "github", name: "github"},
		{in: "github write", name: "github", write: true},
		{in: "  github   write  ", name: "github", write: true},
		{in: "", bad: true},
		{in: "github readwrite", bad: true},
	} {
		name, write, err := parseCredentialDirective(tc.in)
		if tc.bad {
			if err == nil {
				t.Errorf("%q was accepted", tc.in)
			}
			continue
		}
		if err != nil || name != tc.name || write != tc.write {
			t.Errorf("%q = %q/%v/%v", tc.in, name, write, err)
		}
	}
}

func TestBrokerJailEnvPointsGitAtItWithoutAFile(t *testing.T) {
	t.Setenv("GH_TOKEN", "x")
	b, err := startCredentialBroker("github", false)
	if err != nil {
		t.Fatal(err)
	}
	env := b.JailEnv()
	// ~/.gitconfig is bound read-only, so this has to work without writing a
	// file anywhere.
	if env["GIT_CONFIG_COUNT"] != "1" {
		t.Errorf("GIT_CONFIG_COUNT = %q", env["GIT_CONFIG_COUNT"])
	}
	if env["GIT_CONFIG_VALUE_0"] != "https://github.com/" {
		t.Errorf("rewrite source = %q", env["GIT_CONFIG_VALUE_0"])
	}
	if !strings.Contains(env["GIT_CONFIG_KEY_0"], b.Addr) {
		t.Errorf("rewrite target %q does not point at the broker", env["GIT_CONFIG_KEY_0"])
	}
}
