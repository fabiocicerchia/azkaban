package main

import (
	"os"
	"os/exec"
	"strings"
	"testing"
)

// Run with: AZKABAN_DOCKER_IT=1 go test -run TestDockerProxyIntegration -v
// Needs a reachable docker daemon and the alpine image. Creates only `--rm true`
// containers, so it is non-destructive.
func TestDockerProxyIntegration(t *testing.T) {
	if os.Getenv("AZKABAN_DOCKER_IT") != "1" {
		t.Skip("set AZKABAN_DOCKER_IT=1 to run (needs docker daemon + alpine)")
	}
	realSock := strings.TrimPrefix(os.Getenv("DOCKER_HOST"), "unix://")
	if realSock == "" {
		t.Skip("no DOCKER_HOST unix socket")
	}
	cwd, _ := os.Getwd()
	proxySock, err := startDockerFilterProxy(realSock, cwd)
	if err != nil {
		t.Fatal(err)
	}
	host := "unix://" + proxySock

	run := func(args ...string) (string, error) {
		c := exec.Command("docker", append([]string{"-H", host}, args...)...)
		out, err := c.CombinedOutput()
		return string(out), err
	}

	// Only the cases a FAKE daemon cannot answer belong here. Which bodies the
	// filter rejects is asserted — and actually run — by the fake-daemon tests in
	// dockerproxy_destructive_test.go. What those cannot prove is that a real
	// docker CLI still works end to end through the proxy, and that one real
	// rejection surfaces as our error rather than a confusing CLI failure.
	cases := []struct {
		name      string
		args      []string
		wantAllow bool
	}{
		{"plain run", []string{"run", "--rm", "alpine", "true"}, true},
		{"bind project dir", []string{"run", "--rm", "-v", cwd + ":/app", "alpine", "true"}, true},
		{"bind root", []string{"run", "--rm", "-v", "/:/host", "alpine", "true"}, false},
	}
	for _, c := range cases {
		out, err := run(c.args...)
		allowed := err == nil
		if allowed != c.wantAllow {
			t.Errorf("%s: allowed=%v want=%v\n  out: %s", c.name, allowed, c.wantAllow, strings.TrimSpace(out))
			continue
		}
		if !allowed && !strings.Contains(out, "azkaban docker filter") {
			t.Errorf("%s: denied but not by our filter:\n  %s", c.name, strings.TrimSpace(out))
		}
	}
}
