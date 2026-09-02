package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// homeWith - A fake $HOME with the given entries created, so decide() sees the
// same "does the source exist" answers the bind loops would.
func homeWith(t *testing.T, entries ...string) string {
	t.Helper()
	home := t.TempDir()
	for _, e := range entries {
		p := filepath.Join(home, e)
		if strings.HasSuffix(e, "/") {
			if err := os.MkdirAll(p, 0o755); err != nil {
				t.Fatal(err)
			}
			continue
		}
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return home
}

func ask(t *testing.T, home, path, op string, uc userConf, overlay bool) verdict {
	t.Helper()
	// cwd deliberately outside the fake home: the project-dir shortcut is
	// tested on its own.
	return decide(filepath.Join(home, path), op, home, filepath.Join(home, "..", "proj"), uc, overlay)
}

func TestWhyDefaultDenyIsAbsentNotDenied(t *testing.T) {
	home := homeWith(t, ".ssh/id_rsa")
	v := ask(t, home, ".ssh/id_rsa", "read", userConf{}, true)
	// The distinction matters to whoever is reading the error: ~/.ssh was never
	// mounted, so a read is ENOENT. Calling it "denied" would send someone
	// hunting for a permission they cannot grant.
	if v.Decision != "absent" {
		t.Fatalf("decision = %q, want absent (%+v)", v.Decision, v)
	}
	if !strings.Contains(v.Rule, "default deny") {
		t.Fatalf("rule = %q, want the default-deny rule", v.Rule)
	}
}

func TestWhyOverlayIsWritableButDoesNotSurvive(t *testing.T) {
	home := homeWith(t, ".claude/")
	v := ask(t, home, ".claude", "write", userConf{}, true)
	if v.Decision != "allowed" {
		t.Fatalf("decision = %q, want allowed", v.Decision)
	}
	if v.Survives == nil || *v.Survives {
		t.Fatal("an overlaid path must report that writes do not survive")
	}
	if !strings.Contains(v.Rule, "rwPaths .claude") {
		t.Fatalf("rule = %q, want the rwPaths entry that matched", v.Rule)
	}
}

func TestWhyPersistFlipsSurvival(t *testing.T) {
	home := homeWith(t, ".claude/")
	v := ask(t, home, ".claude", "write", userConf{}, false)
	if v.Survives == nil || !*v.Survives {
		t.Fatalf("under --persist writes must survive (%+v)", v)
	}
}

func TestWhyRoFreezeBeatsAWritableParent(t *testing.T) {
	// .config is on rwPaths and .config/azkaban is on roFreeze. The freeze is
	// bound after the rw list precisely so it wins, and `why` has to agree —
	// this is the "nothing in the jail may write what configures the jail" rule.
	home := homeWith(t, ".config/azkaban/config")
	v := ask(t, home, azkabanCfgDir, "write", userConf{}, true)
	if v.Decision != "denied" {
		t.Fatalf("decision = %q, want denied (%+v)", v.Decision, v)
	}
	if !strings.Contains(v.Rule, "roFreeze") {
		t.Fatalf("rule = %q, want roFreeze", v.Rule)
	}
}

func TestWhyMaskBeatsTheWritableParent(t *testing.T) {
	home := homeWith(t, ".config/gh/hosts.yml")
	v := ask(t, home, ".config/gh", "read", userConf{}, true)
	if v.Decision != "denied" || !strings.Contains(v.Mechanism, "masked") {
		t.Fatalf("want a masked denial, got %+v", v)
	}
}

func TestWhyConfigUnmasksACredentialStore(t *testing.T) {
	// Naming a masked path in the trusted config is the documented opt-out, and
	// the answer has to change with it or the escape hatch is invisible.
	home := homeWith(t, ".config/gh/hosts.yml")
	v := ask(t, home, ".config/gh", "read", userConf{ro: []string{".config/gh"}}, true)
	if v.Decision != "allowed" {
		t.Fatalf("decision = %q, want allowed once the config names it (%+v)", v.Decision, v)
	}
}

func TestWhyAParentOfAMaskedPathIsStillWritable(t *testing.T) {
	// ~/.config holds tokens and is bound whole; only the named children are
	// masked. Reporting the parent as denied would be a different policy.
	home := homeWith(t, ".config/gh/hosts.yml")
	v := ask(t, home, ".config", "write", userConf{}, true)
	if v.Decision != "allowed" {
		t.Fatalf("decision = %q, want allowed (%+v)", v.Decision, v)
	}
}

func TestWhySkipsAnEntryWithNoSourceOnTheHost(t *testing.T) {
	// Every bind loop skips an entry whose source is missing. If `why` did not,
	// it would report a mask that was never applied.
	home := homeWith(t, ".config/")
	v := ask(t, home, ".config/gh", "read", userConf{}, true)
	if v.Decision != "allowed" {
		t.Fatalf("decision = %q, want allowed: the mask entry has no source so it is not applied (%+v)",
			v.Decision, v)
	}
	if !strings.Contains(v.Detail, "create it") {
		t.Fatalf("detail = %q, want it to say the jail can create the path", v.Detail)
	}
}

func TestWhyProjectDirIsRealAndNeverOverlaid(t *testing.T) {
	home := t.TempDir()
	cwd := filepath.Join(home, "..", "proj")
	v := decide(filepath.Join(cwd, "src/main.go"), "write", home, cwd, userConf{}, true)
	if v.Decision != "allowed" || v.Survives == nil || !*v.Survives {
		t.Fatalf("the project dir is bound for real, not overlaid: %+v", v)
	}
}

func TestWhySystemPathsFollowTheBaseLayout(t *testing.T) {
	home := t.TempDir()
	for _, tc := range []struct{ path, op, want string }{
		{"/etc/passwd", "read", "allowed"},
		{"/etc/passwd", "write", "denied"},
		{"/usr/bin/ls", "write", "denied"},
		{"/tmp", "write", "allowed"},
		{"/var/lib/whatever", "read", "absent"},
	} {
		v := decide(tc.path, tc.op, home, "/nowhere", userConf{}, true)
		if v.Decision != tc.want {
			t.Errorf("%s (%s) = %q, want %q", tc.path, tc.op, v.Decision, tc.want)
		}
	}
}

func TestWhyNetAnswersPortsAndIsHonestAboutHosts(t *testing.T) {
	if v := decideNet("", 443, false, "443,80", true); v.Decision != "allowed" {
		t.Errorf("port 443 with --net-ports 443,80 = %q", v.Decision)
	}
	if v := decideNet("", 22, false, "443,80", true); v.Decision != "denied" {
		t.Errorf("port 22 with --net-ports 443,80 = %q", v.Decision)
	}
	if v := decideNet("", 443, true, "", true); v.Decision != "denied" {
		t.Errorf("--no-net must deny everything, got %q", v.Decision)
	}
	// --net-ports is enforced by Landlock, so turning Landlock off turns it off.
	if v := decideNet("", 22, false, "443", false); v.Decision != "allowed" {
		t.Errorf("--no-landlock leaves the port list unenforced, got %q", v.Decision)
	}
	// The honest answer: azkaban has no host allowlist, and `why` must not
	// imply one exists.
	v := decideNet("api.anthropic.com", 0, false, "443", true)
	if v.Decision != "allowed" || !strings.Contains(v.Detail, "cannot express a hostname") {
		t.Fatalf("a host question must say hosts are not filtered: %+v", v)
	}
}

func TestWhyCoversMatchesTheEntryAndItsChildrenOnly(t *testing.T) {
	for _, tc := range []struct {
		entry, rel string
		want       bool
	}{
		{".claude", ".claude", true},
		{".claude", ".claude/projects/a.jsonl", true},
		{".claude", ".claude.json", false}, // a sibling, not a child
		{".config", ".config", true},
		{".config/gh", ".config", false}, // a parent is not covered by its child
	} {
		if got := covers(tc.entry, tc.rel); got != tc.want {
			t.Errorf("covers(%q, %q) = %v, want %v", tc.entry, tc.rel, got, tc.want)
		}
	}
}
