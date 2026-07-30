package main

// Docker filter tests that need a daemon — served here by a FAKE one, so these
// never reach the operator's real docker and never create or delete anything.
//
// The create-body filter is covered in main_test.go. What this file covers is the
// other half of the threat model: azkaban's stated purpose is stopping a
// hallucinating agent from destroying things, and `docker volume rm` is
// unrecoverable in a way `rm -rf` on a git repo is not.

import (
	"encoding/json"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// fakeDaemon records every request that gets past the filter.
type fakeDaemon struct {
	reached   []string
	proxySock string
}

func newFakeDaemon(t *testing.T, projectDir string) *fakeDaemon {
	t.Helper()
	d := &fakeDaemon{}
	sock := filepath.Join(t.TempDir(), "real.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })

	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		d.reached = append(d.reached, r.Method+" "+r.URL.Path)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{}`))
	})}
	go srv.Serve(ln)

	ps, err := startDockerFilterProxy(sock, projectDir)
	if err != nil {
		t.Fatal(err)
	}
	// startDockerFilterProxy registers its dir with tempTrack, which only the real
	// binary drains — the test process must clean up after itself.
	t.Cleanup(func() { os.RemoveAll(filepath.Dir(ps)) })
	d.proxySock = ps
	return d
}

func (d *fakeDaemon) do(t *testing.T, method, path, body string) int {
	t.Helper()
	c := &http.Client{Transport: &http.Transport{
		Dial: func(_, _ string) (net.Conn, error) { return net.Dial("unix", d.proxySock) },
	}}
	req, err := http.NewRequest(method, "http://docker"+path, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	resp, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	return resp.StatusCode
}

// The endpoint allowlist must stop whole API areas whose bodies the create-filter
// never inspects — swarm services take a host Source in ContainerSpec.Mounts, and
// plugins can be granted host mounts at install time.
func TestDockerFilter_UnmodelledEndpointsAreRefused(t *testing.T) {
	d := newFakeDaemon(t, t.TempDir())

	for _, c := range []struct{ method, path string }{
		{"POST", "/v1.45/swarm/init"},
		{"POST", "/v1.45/services/create"},
		{"POST", "/v1.45/plugins/pull"},
		{"POST", "/v1.45/secrets/create"},
		{"POST", "/v1.45/configs/create"},
		{"GET", "/v1.45/nodes"},
	} {
		if got := d.do(t, c.method, c.path, "{}"); got != http.StatusForbidden {
			t.Errorf("%s %s: status %d, want 403", c.method, c.path, got)
		}
	}
	if len(d.reached) != 0 {
		t.Errorf("requests reached the daemon that should have been refused: %v", d.reached)
	}
}

// SECURITY-CRITICAL. Podman is reached through its Docker-COMPATIBLE API, never
// its native libpod API, because the two use different create schemas: libpod
// puts mounts at the top level, so a libpod body deserialises into our struct
// with HostConfig == nil and containerReason returns "allowed" for a request
// that mounts /. The endpoint allowlist is the only thing standing in front of
// that, and it holds because "libpod" is not an allowed root.
//
// If anyone ever adds "libpod" to allowedRoots to "support podman properly",
// this test fails — and it must, because doing so opens a total bypass.
func TestDockerFilter_LibpodAPIIsRefused(t *testing.T) {
	d := newFakeDaemon(t, t.TempDir())

	// First, prove the body filter really is blind to the libpod schema.
	libpodBody := `{"image":"alpine","privileged":true,` +
		`"mounts":[{"source":"/","destination":"/host","type":"bind"}]}`
	if reason := filterReason("/containers/create", []byte(libpodBody), t.TempDir()); reason != "" {
		t.Logf("body filter now understands libpod bodies (%q) — good, but the "+
			"endpoint allowlist is still the guarantee", reason)
	}

	for _, path := range []string{
		"/libpod/volumes/create",
		"/v4.0.0/libpod/containers/create",
		"/v4.0.0/libpod/play/kube",
		"/v5.0.0/libpod/containers/prune",
	} {
		if got := d.do(t, "POST", path, libpodBody); got != http.StatusForbidden {
			t.Errorf("%s: status %d, want 403 — the libpod schema bypasses the body filter", path, got)
		}
	}
	if len(d.reached) != 0 {
		t.Errorf("libpod requests reached the daemon: %v", d.reached)
	}
}

func TestDockerFilter_EverydayEndpointsStillWork(t *testing.T) {
	d := newFakeDaemon(t, t.TempDir())

	for _, c := range []struct{ method, path string }{
		{"GET", "/_ping"},
		{"GET", "/v1.45/version"},
		{"GET", "/v1.45/containers/json"},
		{"POST", "/v1.45/images/create?fromImage=alpine"},
		{"POST", "/v1.45/build"},
	} {
		if got := d.do(t, c.method, c.path, ""); got != http.StatusOK {
			t.Errorf("%s %s: status %d, want 200 (legitimate use must not break)", c.method, c.path, got)
		}
	}
}

// The rest of the filter blocks ESCAPE; this blocks LOSS. A named volume has no
// git history and no trash behind it, and prune deletes in bulk. Deliberately
// narrow: `docker rm`/`rmi` stay allowed, because containers and images are
// rebuildable and denying them would break --rm cleanup and ordinary workflows.
func TestDockerFilter_DestructiveCallsAreRefused(t *testing.T) {
	d := newFakeDaemon(t, t.TempDir())

	for _, c := range []struct{ method, path string }{
		{"DELETE", "/v1.45/volumes/postgres-data"},
		{"POST", "/v1.45/volumes/prune"},
		{"POST", "/v1.45/containers/prune"},
		{"POST", "/v1.45/images/prune"},
		{"POST", "/v1.45/networks/prune"},
		{"POST", "/v1.45/build/prune"},
	} {
		if got := d.do(t, c.method, c.path, ""); got != http.StatusForbidden {
			t.Errorf("%s %s: status %d, want 403", c.method, c.path, got)
		}
	}
	if len(d.reached) != 0 {
		t.Errorf("destructive calls reached the daemon: %v", d.reached)
	}
}

// …but everyday cleanup must still work, or people turn the filter off.
func TestDockerFilter_OrdinaryCleanupStillWorks(t *testing.T) {
	d := newFakeDaemon(t, t.TempDir())

	for _, c := range []struct{ method, path string }{
		{"DELETE", "/v1.45/containers/abc123?force=1&v=1"},
		{"DELETE", "/v1.45/images/ubuntu:22.04?force=1"},
		{"POST", "/v1.45/containers/abc123/stop"},
	} {
		if got := d.do(t, c.method, c.path, ""); got != http.StatusOK {
			t.Errorf("%s %s: status %d, want 200", c.method, c.path, got)
		}
	}
}

// A denial must be a well-formed docker error, or the CLI prints something
// unhelpful instead of the reason.
func TestDockerFilter_DenialIsAWellFormedDockerError(t *testing.T) {
	d := newFakeDaemon(t, t.TempDir())
	c := &http.Client{Transport: &http.Transport{
		Dial: func(_, _ string) (net.Conn, error) { return net.Dial("unix", d.proxySock) },
	}}
	resp, err := c.Post("http://docker/v1.45/containers/create", "application/json",
		strings.NewReader(`{"HostConfig":{"Binds":["/:/host"]}}`))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status %d, want 403", resp.StatusCode)
	}
	var body struct {
		Message string `json:"message"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("denial body is not JSON: %v", err)
	}
	if !strings.Contains(body.Message, "azkaban") {
		t.Errorf("denial message does not identify azkaban: %q", body.Message)
	}
}

// The proxy must not buffer a hostile client's unbounded body before forwarding.
func TestDockerFilter_CreateBodyIsSizeCapped(t *testing.T) {
	d := newFakeDaemon(t, t.TempDir())
	huge := `{"HostConfig":{"Binds":["/:/host"]},"pad":"` + strings.Repeat("A", 8<<20) + `"}`
	if got := d.do(t, "POST", "/v1.45/containers/create", huge); got != http.StatusForbidden {
		t.Errorf("oversized create body: status %d, want 403", got)
	}
}
