package main

// Ephemeral test environment for the jail tests.
//
// EVERY test that starts a real jail runs against a THROWAWAY $HOME, built fresh
// under /var/tmp and deleted afterwards. No test may touch the operator's real
// home, and guard() refuses to run if one ever tries.
//
// This is not defensive decoration; it is the whole point of the file. During a
// review of this tool, `rm -rf ~/.claude` was run inside the jail against the
// REAL home to "prove" containment held. `rm -rf` deletes a directory's contents
// BEFORE it fails with EBUSY on the bind-mount root, so it exited non-zero — read
// as "blocked" — having already destroyed five months of data. Two forced
// re-logins (the deleted credentials file) were explained away as unrelated.
//
// The lesson encoded here: verifying a containment tool is the WORST place to
// use real data, because the mechanism you are trusting for safety is the exact
// mechanism under test. A non-zero exit code is not evidence that nothing
// happened — see TestPersist_ExitCodeIsNotEvidence, which pins that trap.
//
// The tmp-overlay default now makes that specific loss impossible; the tests
// still run against a fake home, because the next bug will not be this one.

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

const bwrapPath = "/usr/bin/bwrap"

// ephemeralRoot holds the fake homes. Deliberately NOT /tmp: azkaban puts /tmp on
// Landlock's writable list, so a fake $HOME under /tmp would inherit write access
// and silently mask the restrictions these tests exist to check. /var/tmp is
// outside every mount and Landlock allowlist — which is what a real $HOME looks
// like from inside the jail.
const ephemeralRoot = "/var/tmp"

var (
	azkabanBin string // built once by TestMain
	realHome   string // captured before any test overrides $HOME
)

func TestMain(m *testing.M) {
	realHome = os.Getenv("HOME")
	if realHome == "" {
		realHome, _ = os.UserHomeDir()
	}
	realHome = filepath.Clean(realHome)

	dir, err := os.MkdirTemp("", "azkaban-build-")
	if err != nil {
		panic(err)
	}
	azkabanBin = filepath.Join(dir, "azkaban")
	build := exec.Command("go", "build", "-o", azkabanBin, ".")
	build.Env = append(os.Environ(), "CGO_ENABLED=0")
	if out, err := build.CombinedOutput(); err != nil {
		os.RemoveAll(dir)
		panic("building azkaban for tests: " + err.Error() + "\n" + string(out))
	}

	code := m.Run()
	os.RemoveAll(dir)
	tempCleanup() // backstop: anything the tests registered but did not drain
	os.Exit(code)
}

func requireJail(t *testing.T) {
	t.Helper()
	// These tests spawn jails; running them INSIDE one is not a stricter test, it
	// is a misleading one. Landlock rulesets stack, so the outer jail denies what
	// an inner test asserts is denied even if the inner rule were deleted — every
	// "must not be writable" case would pass vacuously. On top of that /var/tmp
	// (where guard insists the fake homes live) is not bound into a jail, and
	// nesting needs --allow-userns on the outside plus a kernel that permits
	// nested unprivileged user namespaces. Skip, loudly: run on the host.
	if h, _ := os.Hostname(); h == jailHostname {
		t.Skip("running inside azkaban — the jail-spawning tests only mean something on the host")
	}
	if _, err := os.Stat(bwrapPath); err != nil {
		t.Skip("bwrap not installed at " + bwrapPath)
	}
}

// --------------------------------------------------------------------------- //
// The ephemeral $HOME
// --------------------------------------------------------------------------- //

type env struct {
	root string // /var/tmp/azkaban-test-XXXX
	home string // <root>/home   — the fake $HOME
	proj string // <root>/home/proj — the fake project dir (cwd)
}

// decoys mimic a lived-in home. Secrets carry recognisable content so a test can
// prove a file was neither read nor destroyed, rather than merely absent.
var decoys = map[string]string{
	".ssh/id_rsa":                 "PRIVATE-KEY-MUST-NEVER-BE-VISIBLE",
	".ssh/known_hosts":            "github.com ssh-ed25519 AAAA-decoy",
	".aws/credentials":            "aws_secret_access_key=MUST-NEVER-BE-VISIBLE",
	".gnupg/secring.gpg":          "GPG-SECRET-MUST-NEVER-BE-VISIBLE",
	"Documents/taxes.txt":         "not on any allowlist",
	"sibling-project/main.go":     "another project, must stay hidden",
	".gitconfig":                  "[user]\n\tname = Test\n",
	".cache/tool/blob":            "cache data",
	".config/app/settings.json":   "{}",
	".claude/projects/p1/s.jsonl": "CONVERSATION-HISTORY",
	".claude/settings.json":       `{"theme":"dark"}`,
	".local/share/thing/data":     "share data",
	"proj/src.txt":                "project source",
	"proj/.git/HEAD":              "ref: refs/heads/main\n",
}

func newEnv(t *testing.T) *env {
	t.Helper()
	requireJail(t) // before MkdirTemp: inside a jail there is no /var/tmp to fail on
	root, err := os.MkdirTemp(ephemeralRoot, "azkaban-test-")
	if err != nil {
		t.Fatal(err)
	}
	e := &env{root: root, home: filepath.Join(root, "home")}
	e.proj = filepath.Join(e.home, "proj")
	e.guard(t)
	t.Cleanup(func() { os.RemoveAll(root) })

	for rel, content := range decoys {
		p := filepath.Join(e.home, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return e
}

// guard is the tripwire. It refuses to proceed unless the fake home is safely
// ephemeral: under /var/tmp, and neither inside nor an ancestor of the real home.
func (e *env) guard(t *testing.T) {
	t.Helper()
	if bad := guardReason(e.home, realHome); bad != "" {
		t.Fatalf("REFUSING TO RUN: %s (fake=%q real=%q)", bad, e.home, realHome)
	}
}

// guardReason is pure so it can be tested directly — see TestGuardRejectsUnsafeHomes.
// It returns "" when fake is safe to hand to a destructive test, else why not.
func guardReason(fake, real string) string {
	h, r := filepath.Clean(fake), filepath.Clean(real)
	sep := string(os.PathSeparator)
	switch {
	case r == "" || r == "." || r == "/":
		return "real home is unset or /, cannot prove isolation"
	case h == r:
		return "fake home IS the real home"
	case strings.HasPrefix(h, r+sep):
		return "fake home is inside the real home"
	case strings.HasPrefix(r, h+sep):
		return "fake home is an ANCESTOR of the real home"
	case !strings.HasPrefix(h, ephemeralRoot+sep):
		return "fake home is outside " + ephemeralRoot
	}
	return ""
}

// path returns the HOST path of a fake-home-relative entry, for asserting what
// survived after the jail exits.
func (e *env) path(rel string) string { return filepath.Join(e.home, rel) }

func (e *env) mustContain(t *testing.T, rel, want string) {
	t.Helper()
	b, err := os.ReadFile(e.path(rel))
	if err != nil {
		t.Errorf("%s: expected to survive intact, got error: %v", rel, err)
		return
	}
	if string(b) != want {
		t.Errorf("%s: content changed\n  got:  %q\n  want: %q", rel, b, want)
	}
}

func (e *env) mustBeGone(t *testing.T, rel string) {
	t.Helper()
	if _, err := os.Stat(e.path(rel)); err == nil {
		t.Errorf("%s: expected to be destroyed, but it still exists", rel)
	}
}

// --------------------------------------------------------------------------- //
// Running the jail
// --------------------------------------------------------------------------- //

type result struct {
	stdout, stderr string
	code           int
}

func (r result) has(s string) bool { return strings.Contains(r.stdout, s) }

// run starts the jail with cwd = the fake project dir and executes script under
// /bin/sh. No socket flag is injected: azkaban binds no container socket unless
// asked, so no test can reach the operator's real daemon by accident.
func (e *env) run(t *testing.T, flags []string, script string, extraEnv ...string) result {
	t.Helper()
	return e.runIn(t, e.proj, flags, script, extraEnv...)
}

func (e *env) runIn(t *testing.T, cwd string, flags []string, script string, extraEnv ...string) result {
	t.Helper()
	requireJail(t)
	e.guard(t) // re-checked on every single invocation, not just at setup

	args := append([]string{}, flags...)
	if script != "" {
		args = append(args, "--", "/bin/sh", "-c", script)
	}

	cmd := exec.Command(azkabanBin, args...)
	cmd.Dir = cwd
	cmd.Env = append([]string{
		"HOME=" + e.home,
		"PATH=/usr/bin:/bin:/usr/sbin:/sbin",
		"TERM=dumb",
	}, extraEnv...)

	var out, errb strings.Builder
	cmd.Stdout, cmd.Stderr = &out, &errb
	err := cmd.Run()
	r := result{stdout: out.String(), stderr: errb.String()}
	if ee, ok := err.(*exec.ExitError); ok {
		r.code = ee.ExitCode()
	} else if err != nil {
		t.Fatalf("running azkaban: %v\nstderr: %s", err, errb.String())
	}
	return r
}

// probe emits "<label>:yes" or "<label>:no" for a shell condition, so a single
// jail invocation can answer many questions and assertions stay readable.
func probe(label, cond string) string {
	return "if " + cond + "; then echo " + label + ":yes; else echo " + label + ":no; fi; "
}

func (r result) assert(t *testing.T, label string, want bool) {
	t.Helper()
	yes, no := r.has(label+":yes"), r.has(label+":no")
	if !yes && !no {
		t.Errorf("%s: probe produced no result\nstdout: %s\nstderr: %s", label, r.stdout, r.stderr)
		return
	}
	if yes != want {
		t.Errorf("%s = %v, want %v", label, yes, want)
	}
}
