package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

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
			"a bare high-entropy value nobody named",
			[]string{"curl", "-H", "ghp_A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8"},
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
