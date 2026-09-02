package main

import (
	"os"
	"path/filepath"
	"testing"
)

func write(t *testing.T, p, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

// The incident this feature exists for: a jail deletes a directory of real
// data, and the operator has to be able to put it back.
func TestRollbackRestoresWhatWasDeleted(t *testing.T) {
	root := t.TempDir()
	store := filepath.Join(t.TempDir(), "objects")
	write(t, filepath.Join(root, "projects/a.jsonl"), "transcript a")
	write(t, filepath.Join(root, "projects/b.jsonl"), "transcript b")
	write(t, filepath.Join(root, "settings.json"), "{}")

	before, err := takeSnapshot([]string{root}, store)
	if err != nil {
		t.Fatal(err)
	}
	if len(before.Entries) != 3 {
		t.Fatalf("snapshotted %d files, want 3", len(before.Entries))
	}

	// rm -rf the transcripts, and change a file.
	if err := os.RemoveAll(filepath.Join(root, "projects")); err != nil {
		t.Fatal(err)
	}
	write(t, filepath.Join(root, "settings.json"), `{"changed":true}`)
	write(t, filepath.Join(root, "new.txt"), "added by the run")

	after, _ := takeSnapshot([]string{root}, store)
	changes := diffSnapshots(before, after)

	kinds := map[string]int{}
	for _, c := range changes {
		kinds[c.Kind]++
	}
	if kinds["deleted"] != 2 || kinds["modified"] != 1 || kinds["added"] != 1 {
		t.Fatalf("diff = %v, want 2 deleted / 1 modified / 1 added", kinds)
	}

	for _, c := range changes {
		if c.Kind == "added" {
			// Putting an addition back means deleting it, which is the
			// operator's call and not this tool's.
			if err := restore(c, store); err == nil {
				t.Error("restoring an addition should refuse")
			}
			continue
		}
		if err := restore(c, store); err != nil {
			t.Fatalf("restore %s: %v", c.Path, err)
		}
	}

	got, err := os.ReadFile(filepath.Join(root, "projects/a.jsonl"))
	if err != nil || string(got) != "transcript a" {
		t.Errorf("deleted file not restored: %q %v", got, err)
	}
	got, _ = os.ReadFile(filepath.Join(root, "settings.json"))
	if string(got) != "{}" {
		t.Errorf("modified file = %q, want the original", got)
	}
}

func TestRollbackStoreIsContentAddressedSoRepeatsAreFree(t *testing.T) {
	root := t.TempDir()
	store := filepath.Join(t.TempDir(), "objects")
	write(t, filepath.Join(root, "a.txt"), "same bytes")
	write(t, filepath.Join(root, "b.txt"), "same bytes")

	if _, err := takeSnapshot([]string{root}, store); err != nil {
		t.Fatal(err)
	}
	// Two files, one object: this is what makes a snapshot before every run
	// affordable, and a feature nobody leaves on protects nothing.
	count := 0
	filepath.Walk(store, func(p string, fi os.FileInfo, err error) error {
		if err == nil && fi != nil && !fi.IsDir() {
			count++
		}
		return nil
	})
	if count != 1 {
		t.Errorf("store holds %d objects, want 1", count)
	}
}

func TestRollbackRefusesCorruptedContent(t *testing.T) {
	root := t.TempDir()
	store := filepath.Join(t.TempDir(), "objects")
	write(t, filepath.Join(root, "x.txt"), "original")
	before, _ := takeSnapshot([]string{root}, store)
	os.Remove(filepath.Join(root, "x.txt"))
	after, _ := takeSnapshot([]string{root}, store)
	c := diffSnapshots(before, after)[0]

	// Corrupt the stored object.
	obj := filepath.Join(store, c.Hash[:2], c.Hash[2:])
	if err := os.WriteFile(obj, []byte("tampered"), 0o600); err != nil {
		t.Fatal(err)
	}
	// Restoring it silently would be the one failure that makes this feature
	// actively harmful.
	if err := restore(c, store); err == nil {
		t.Fatal("restored corrupted content without complaint")
	}
}

func TestRollbackSkipsGitAndBuildOutput(t *testing.T) {
	root := t.TempDir()
	write(t, filepath.Join(root, "src/main.go"), "package main")
	write(t, filepath.Join(root, ".git/objects/ab/cdef"), "git object")
	write(t, filepath.Join(root, "node_modules/pkg/index.js"), "module")

	snap, err := takeSnapshot([]string{root}, "")
	if err != nil {
		t.Fatal(err)
	}
	// git is its own snapshot mechanism, and node_modules is regenerable.
	if len(snap.Entries) != 1 {
		for _, e := range snap.Entries {
			t.Logf("kept %s", e.Path)
		}
		t.Fatalf("snapshotted %d files, want just src/main.go", len(snap.Entries))
	}
}

func TestRollbackDoesNotFollowSymlinksOutOfTheRoot(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	write(t, filepath.Join(outside, "secret.txt"), "not yours")
	if err := os.Symlink(outside, filepath.Join(root, "link")); err != nil {
		t.Skip("symlinks unavailable")
	}
	write(t, filepath.Join(root, "real.txt"), "mine")

	snap, _ := takeSnapshot([]string{root}, "")
	// Following the link would pull an untracked tree into the snapshot, and
	// restoring through one would write outside the root.
	for _, e := range snap.Entries {
		if filepath.Base(e.Path) == "secret.txt" {
			t.Fatal("followed a symlink out of the tracked root")
		}
	}
	if len(snap.Entries) != 1 {
		t.Errorf("snapshotted %d entries, want just the regular file", len(snap.Entries))
	}
}
