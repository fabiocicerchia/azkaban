package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"slices"
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

// --- --self, and the policy the jail carries --------------------------------

func selfPolicy() jailPolicy {
	return jailPolicy{
		Version: 1, Home: "/home/you", Project: "/home/you/proj",
		Writable:  []string{"/home/you/.config", "/home/you/.cache"},
		ReadOnly:  []string{"/home/you/.gitconfig"},
		Persisted: []string{"/home/you/.claude/.credentials.json"},
		Masked:    []string{"/home/you/.config/gh"},
		Overlay:   true, Landlock: true, NetPorts: "443",
	}
}

func TestSelfDistinguishesAbsentFromDenied(t *testing.T) {
	// The distinction the whole file exists for. ~/.ssh was never mounted, so
	// a read is ENOENT — and an agent told "denied" goes looking for a
	// permission nobody can grant.
	v := decideSelf("/home/you/.ssh/id_rsa", "read", selfPolicy())
	if v.Decision != "absent" {
		t.Fatalf("decision = %q, want absent (%+v)", v.Decision, v)
	}
	if !strings.Contains(v.Detail, "creating it will not help") {
		t.Errorf("detail should tell the agent not to work around it: %q", v.Detail)
	}
}

func TestSelfLongestMatchWinsSoAMaskBeatsItsWritableParent(t *testing.T) {
	jp := selfPolicy()
	if v := decideSelf("/home/you/.config/gh", "read", jp); v.Decision != "denied" {
		t.Errorf(".config/gh = %q, want denied — the mask is deeper than the rw parent", v.Decision)
	}
	if v := decideSelf("/home/you/.config/other", "write", jp); v.Decision != "allowed" {
		t.Errorf(".config/other = %q, want allowed", v.Decision)
	}
}

func TestSelfSaysWhenAWriteWillBeDiscarded(t *testing.T) {
	v := decideSelf("/home/you/.cache/thing", "write", selfPolicy())
	if v.Decision != "allowed" {
		t.Fatalf("decision = %q", v.Decision)
	}
	if v.Survives == nil || *v.Survives {
		t.Error("an overlaid write must report that it does not survive")
	}
	// An agent that sees the write succeed and the file vanish will otherwise
	// conclude something is broken and try again.
	if !strings.Contains(v.Detail, "discarded") {
		t.Errorf("detail = %q", v.Detail)
	}
}

func TestSelfNamesTheProjectAsTheOnePlaceWritesPersist(t *testing.T) {
	v := decideSelf("/home/you/proj/src/main.go", "write", selfPolicy())
	if v.Decision != "allowed" || v.Survives == nil || !*v.Survives {
		t.Fatalf("the project dir must be real and persistent: %+v", v)
	}
}

func TestSelfTellsTheAgentChmodWillNotHelp(t *testing.T) {
	v := decideSelf("/home/you/.gitconfig", "write", selfPolicy())
	if v.Decision != "denied" {
		t.Fatalf("decision = %q", v.Decision)
	}
	// sudo is present in the jail and inert under NoNewPrivs; without this the
	// agent tries it.
	if !strings.Contains(v.Detail, "sudo is inert") {
		t.Errorf("detail = %q", v.Detail)
	}
}

func TestSelfOutsideAJailSaysSoRatherThanGuessing(t *testing.T) {
	t.Setenv("AZKABAN_JAIL", "")
	t.Setenv("AZKABAN_POLICY", filepath.Join(t.TempDir(), "nope.json"))
	_, err := loadSelfPolicy()
	if err == nil {
		t.Fatal("want an error outside a jail")
	}
	if !strings.Contains(err.Error(), "this is not one") {
		t.Errorf("error = %q, want it to say this is not a jail", err)
	}
}

func TestSelfInsideAJailWithNoPolicyBlamesNoGuidance(t *testing.T) {
	t.Setenv("AZKABAN_JAIL", "1")
	t.Setenv("AZKABAN_POLICY", filepath.Join(t.TempDir(), "nope.json"))
	_, err := loadSelfPolicy()
	if err == nil || !strings.Contains(err.Error(), "--no-guidance") {
		t.Errorf("error = %v, want it to name --no-guidance", err)
	}
}

func TestSelfPolicyRoundTripsThroughJSON(t *testing.T) {
	// The outer stage writes it and the inner stage reads it; a field that
	// does not survive that is a field the agent is answered wrongly from.
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.json")
	if err := os.WriteFile(path, []byte(selfPolicy().json()), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("AZKABAN_JAIL", "1")
	t.Setenv("AZKABAN_POLICY", path)

	got, err := loadSelfPolicy()
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(got.Writable, selfPolicy().Writable) ||
		!slices.Equal(got.Masked, selfPolicy().Masked) ||
		got.Overlay != true || got.NetPorts != "443" || got.Project != "/home/you/proj" {
		t.Errorf("round trip lost something: %+v", got)
	}
}

func TestGuidanceTextNamesAReachableCommand(t *testing.T) {
	text := guidanceText(selfPolicy())
	// Telling the agent to run `azkaban why` is useless if azkaban is not on
	// its PATH, and whether it is depends on where the user installed it.
	if !strings.Contains(text, guidanceBinPath+" why") {
		t.Error("the README must name the absolute in-jail binary path")
	}
	for _, want := range []string{"not a deleted file", "sudo", "discarded", "/home/you/proj"} {
		if !strings.Contains(text, want) {
			t.Errorf("the README does not mention %q", want)
		}
	}
}

func TestPresentUnderSkipsWhatIsNotOnTheHost(t *testing.T) {
	home := t.TempDir()
	if err := os.MkdirAll(filepath.Join(home, ".config"), 0o755); err != nil {
		t.Fatal(err)
	}
	got := presentUnder(home, []string{".config", ".does-not-exist", ".config"})
	// Naming a path the jail did not get would tell the agent it is available
	// when it is not — the exact confusion this file removes. And the same
	// entry twice must not appear twice.
	if len(got) != 1 || got[0] != filepath.Join(home, ".config") {
		t.Errorf("presentUnder = %v", got)
	}
}

func TestDryRunShowsTheGuidanceBinds(t *testing.T) {
	// A regression test for a real bug: the guidance binds were appended to the
	// argument list *after* the bwrap command line had already been built from
	// it, so they were silently dropped. Nothing failed — the jail just started
	// without the file that tells the agent it is in one. Asserting against
	// --dry-run is what catches that class, because --dry-run is the argument
	// list.
	cmd := exec.Command(azkabanBin, "--dry-run", "/bin/true")
	cmd.Dir = t.TempDir()
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("--dry-run failed: %v\n%s", err, out)
	}
	got := string(out)
	for _, want := range []string{
		guidancePolicyPath, guidanceReadmePath, guidanceBinPath,
		guidanceDir + "/claude-hook.sh", "AZKABAN_JAIL",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("--dry-run does not bind %s", want)
		}
	}
}

func TestNoGuidanceLeavesThemOut(t *testing.T) {
	cmd := exec.Command(azkabanBin, "--dry-run", "--no-guidance", "/bin/true")
	cmd.Dir = t.TempDir()
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("--dry-run failed: %v\n%s", err, out)
	}
	if strings.Contains(string(out), guidanceDir) {
		t.Error("--no-guidance still bound the guidance directory")
	}
}
