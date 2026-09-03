// rollback.go — snapshot the writable roots, then let the operator put back
// what the jail destroyed.
//
// WHY THIS EXISTS: the overlay cannot tell destruction from useful work, so it
// discards both. `--persist` is the only escape and it is all-or-nothing — it
// makes every writable $HOME entry really destroyable again. As docs/design.md
// puts it: there is no way to keep ~/.claude/projects while `rm -rf ~/.claude`
// stays impossible.
//
// The result is that shell history, caches and Claude Code transcripts are lost
// as collateral on every default run, and the workaround costs the protection.
//
// Rollback answers the question the overlay cannot: writes land for real, and
// destruction becomes a diff to review rather than a loss. For the incident in
// docs/design.md — `rm -rf ~/.claude` against a real home — this is strictly
// better than discarding everything.
//
// It is opt-in (`--rollback`) and it is an ALTERNATIVE to the overlay, not a
// layer on top: rollback implies real writes.
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// Directories never walked. .git is the big one: a repository is its own
// snapshot mechanism, and hashing every object doubles the cost of a rollback
// for something git already recovers. The rest are build output — large,
// regenerable, and not what anyone wants restored.
var rollbackSkip = map[string]bool{
	".git": true, "node_modules": true, "target": true, "vendor": true,
	".venv": true, "__pycache__": true, ".mypy_cache": true, ".pytest_cache": true,
	".next": true, ".nuxt": true, "dist": true, "build": true,
}

// rollbackMaxFiles bounds one snapshot. A directory with more entries than this
// is skipped whole and said so — hashing a 200k-file cache before every run
// would make the feature something nobody leaves on, and a feature nobody
// leaves on protects nothing.
const rollbackMaxFiles = 20000

// rollbackMaxFileSize is the largest file stored. Above it the entry is
// recorded (so a deletion is still reported) but the content is not kept:
// rolling back a 2 GiB model file is not what this is for, and silently
// filling the state directory is worse than saying so.
const rollbackMaxFileSize = 64 << 20

// snapEntry is one file at one moment.
type snapEntry struct {
	Path string      `json:"path"` // absolute, on the host
	Hash string      `json:"hash"` // sha256 of the content, "" when not stored
	Size int64       `json:"size"`
	Mode os.FileMode `json:"mode"`
	Mod  time.Time   `json:"mod"`
}

// snapshot is the state of the tracked roots at one moment.
type snapshot struct {
	Version int         `json:"version"`
	Taken   time.Time   `json:"taken"`
	Roots   []string    `json:"roots"`
	Entries []snapEntry `json:"entries"`
	Skipped []string    `json:"skipped,omitempty"`
}

// change is one difference between two snapshots.
type change struct {
	Path string `json:"path"`
	Kind string `json:"kind"` // "deleted", "modified", "added"
	Hash string `json:"hash"` // the BEFORE content, for deleted and modified
	Size int64  `json:"size"`
}

// rollbackDir is where snapshots and content live.
func rollbackDir() string {
	base := os.Getenv("XDG_STATE_HOME")
	if base == "" {
		home, _ := os.UserHomeDir()
		base = filepath.Join(home, ".local", "state")
	}
	return filepath.Join(base, "azkaban", "rollback")
}

func rollbackStore() string { return filepath.Join(rollbackDir(), "objects") }

// takeSnapshot walks the roots and records what is there.
//
// Content is stored as it goes, keyed by hash, so an unchanged file across
// twenty runs costs one copy. That is what makes taking a snapshot before every
// run affordable — and it has to be affordable, or the feature is off.
func takeSnapshot(roots []string, store string) (*snapshot, error) {
	snap := &snapshot{Version: 1, Taken: time.Now().UTC(), Roots: roots}
	if store != "" {
		if err := os.MkdirAll(store, 0o700); err != nil {
			return nil, err
		}
	}
	for _, root := range roots {
		info, err := os.Stat(root)
		if err != nil || !info.IsDir() {
			continue
		}
		count := 0
		err = filepath.WalkDir(root, func(p string, d os.DirEntry, err error) error {
			if err != nil {
				return nil // an unreadable subtree is not a reason to abandon the rest
			}
			if d.IsDir() {
				if rollbackSkip[d.Name()] {
					return filepath.SkipDir
				}
				return nil
			}
			// Symlinks are recorded by name only. Following them would let a
			// link inside a tracked root pull an untracked tree into the
			// snapshot, and restoring through one would write outside the root.
			if !d.Type().IsRegular() {
				return nil
			}
			count++
			if count > rollbackMaxFiles {
				snap.Skipped = append(snap.Skipped,
					fmt.Sprintf("%s (over %d files)", root, rollbackMaxFiles))
				return filepath.SkipAll
			}
			fi, err := d.Info()
			if err != nil {
				return nil
			}
			e := snapEntry{Path: p, Size: fi.Size(), Mode: fi.Mode(), Mod: fi.ModTime().UTC()}
			if fi.Size() <= rollbackMaxFileSize {
				if h, err := storeFile(p, store); err == nil {
					e.Hash = h
				}
			}
			snap.Entries = append(snap.Entries, e)
			return nil
		})
		if err != nil {
			return nil, err
		}
	}
	sort.Slice(snap.Entries, func(i, j int) bool { return snap.Entries[i].Path < snap.Entries[j].Path })
	return snap, nil
}

// storeFile hashes a file and, when store is set, keeps a copy under its hash.
func storeFile(path, store string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	sum := hex.EncodeToString(h.Sum(nil))
	if store == "" {
		return sum, nil
	}

	// Two levels of fan-out: one directory with a hundred thousand entries is
	// slow to read on most filesystems.
	dir := filepath.Join(store, sum[:2])
	dst := filepath.Join(dir, sum[2:])
	if _, err := os.Stat(dst); err == nil {
		return sum, nil // content-addressed: already have it
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return sum, err
	}
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return sum, err
	}
	tmp := dst + ".part"
	out, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return sum, err
	}
	if _, err := io.Copy(out, f); err != nil {
		out.Close()
		os.Remove(tmp)
		return sum, err
	}
	out.Close()
	// Rename last: a partially written object under its final name would be
	// restored as truncated content, which is worse than not having it.
	return sum, os.Rename(tmp, dst)
}

// diffSnapshots reports what the jail did, in the terms an operator reviews.
//
// Additions are reported but carry no stored content: putting back an addition
// means deleting it, and this tool does not delete things on the operator's
// behalf. They are listed so "what did it do" is answerable.
func diffSnapshots(before, after *snapshot) []change {
	was := map[string]snapEntry{}
	for _, e := range before.Entries {
		was[e.Path] = e
	}
	now := map[string]snapEntry{}
	for _, e := range after.Entries {
		now[e.Path] = e
	}

	var out []change
	for _, e := range before.Entries {
		cur, ok := now[e.Path]
		switch {
		case !ok:
			out = append(out, change{Path: e.Path, Kind: "deleted", Hash: e.Hash, Size: e.Size})
		case cur.Hash != e.Hash || cur.Size != e.Size:
			out = append(out, change{Path: e.Path, Kind: "modified", Hash: e.Hash, Size: e.Size})
		}
	}
	for _, e := range after.Entries {
		if _, ok := was[e.Path]; !ok {
			out = append(out, change{Path: e.Path, Kind: "added", Size: e.Size})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Path < out[j].Path })
	return out
}

// restore puts one recorded file back.
//
// Refuses rather than guessing when the content is not in the store — a
// "restore" that writes an empty file over a deleted one is worse than a
// failure, because it looks like it worked.
func restore(c change, store string) error {
	if c.Kind == "added" {
		return errors.New("added by the run; putting it back would mean deleting it, which is yours to do")
	}
	if c.Hash == "" {
		return errors.New("no stored content (too large, or unreadable when the snapshot was taken)")
	}
	src := filepath.Join(store, c.Hash[:2], c.Hash[2:])
	data, err := os.ReadFile(src)
	if err != nil {
		return fmt.Errorf("content %s is not in the store: %w", c.Hash[:12], err)
	}
	// Verify on the way out. A corrupted object restored silently is the one
	// failure that would make this feature actively harmful.
	sum := sha256.Sum256(data)
	if hex.EncodeToString(sum[:]) != c.Hash {
		return errors.New("stored content does not match its hash; refusing to write it")
	}
	if err := os.MkdirAll(filepath.Dir(c.Path), 0o755); err != nil {
		return err
	}
	return os.WriteFile(c.Path, data, 0o600)
}

// --- the session on disk -----------------------------------------------------

// rollbackSession is one run's before/after pair.
type rollbackSession struct {
	ID     string    `json:"id"`
	Cmd    []string  `json:"command"`
	Cwd    string    `json:"cwd"`
	Start  time.Time `json:"start"`
	End    time.Time `json:"end"`
	Before *snapshot `json:"before"`
	After  *snapshot `json:"after"`
}

func (s *rollbackSession) path() string {
	return filepath.Join(rollbackDir(), s.ID+".json")
}

func (s *rollbackSession) save() error {
	if err := os.MkdirAll(rollbackDir(), 0o700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(s.path(), data, 0o600)
}

func loadSession(id string) (*rollbackSession, error) {
	data, err := os.ReadFile(filepath.Join(rollbackDir(), id+".json"))
	if err != nil {
		return nil, err
	}
	var s rollbackSession
	if err := json.Unmarshal(data, &s); err != nil {
		return nil, err
	}
	return &s, nil
}

func listSessions() []*rollbackSession {
	entries, err := os.ReadDir(rollbackDir())
	if err != nil {
		return nil
	}
	var out []*rollbackSession
	for _, e := range entries {
		name := strings.TrimSuffix(e.Name(), ".json")
		if name == e.Name() {
			continue
		}
		if s, err := loadSession(name); err == nil {
			out = append(out, s)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Start.After(out[j].Start) })
	return out
}

// --- the subcommand ----------------------------------------------------------

func rollbackCommand(argv []string) {
	if len(argv) == 0 {
		rollbackUsage()
		fatal(2, "rollback needs a subcommand")
	}
	switch argv[0] {
	case "list":
		rollbackList()
	case "show":
		rollbackShow(argv[1:], false)
	case "restore":
		rollbackShow(argv[1:], true)
	case "cleanup":
		rollbackCleanup(argv[1:])
	default:
		rollbackUsage()
		fatal(2, "unknown rollback subcommand "+argv[0])
	}
}

func rollbackList() {
	sessions := listSessions()
	if len(sessions) == 0 {
		fmt.Println("no rollback sessions in " + rollbackDir() + " — run with --rollback first")
		return
	}
	for _, s := range sessions {
		changes := diffSnapshots(s.Before, s.After)
		var deleted, modified int
		for _, c := range changes {
			switch c.Kind {
			case "deleted":
				deleted++
			case "modified":
				modified++
			}
		}
		fmt.Printf("%s  %s  %d deleted, %d modified  (%s)\n",
			s.ID, s.Start.Local().Format("2006-01-02 15:04"), deleted, modified,
			strings.Join(s.Cmd, " "))
	}
}

func rollbackShow(argv []string, apply bool) {
	if len(argv) == 0 {
		fatal(2, "which session? see `azkaban rollback list`")
	}
	s, err := loadSession(argv[0])
	if err != nil {
		fatal(1, "no session "+argv[0]+": "+err.Error())
	}
	changes := diffSnapshots(s.Before, s.After)
	if len(changes) == 0 {
		fmt.Println("nothing changed in the tracked roots")
		return
	}

	// A filter, because "put back the one file it ate" is the common case and
	// restoring everything would also undo the work you wanted.
	var only []string
	if len(argv) > 1 {
		only = argv[1:]
	}
	matched := 0
	for _, c := range changes {
		if !matchesAny(c.Path, only) {
			continue
		}
		matched++
		if !apply {
			fmt.Printf("  %-9s %s\n", c.Kind, c.Path)
			continue
		}
		if c.Kind == "added" {
			continue // never deleted on the operator's behalf; see restore()
		}
		if err := restore(c, rollbackStore()); err != nil {
			fmt.Printf("  FAILED    %s: %v\n", c.Path, err)
			continue
		}
		fmt.Printf("  restored  %s\n", c.Path)
	}
	if matched == 0 {
		fmt.Println("no changes matched")
		return
	}
	if !apply {
		fmt.Printf("\n%d change(s). Put them back with:\n  azkaban rollback restore %s [path-substring...]\n",
			matched, s.ID)
	}
}

func matchesAny(path string, subs []string) bool {
	if len(subs) == 0 {
		return true
	}
	for _, s := range subs {
		if strings.Contains(path, s) {
			return true
		}
	}
	return false
}

// rollbackCleanup drops sessions, and then any stored content nothing refers to.
//
// Order matters: sweeping the store while a session still points into it would
// leave that session restorable in name only.
func rollbackCleanup(argv []string) {
	keep := 10
	if len(argv) > 0 {
		if n, err := parsePositive(argv[0]); err == nil {
			keep = n
		}
	}
	sessions := listSessions()
	for i, s := range sessions {
		if i < keep {
			continue
		}
		os.Remove(s.path())
	}

	live := map[string]bool{}
	for _, s := range listSessions() {
		for _, e := range s.Before.Entries {
			if e.Hash != "" {
				live[e.Hash] = true
			}
		}
	}
	store := rollbackStore()
	removed, freed := 0, int64(0)
	dirs, _ := os.ReadDir(store)
	for _, d := range dirs {
		if !d.IsDir() {
			continue
		}
		objs, _ := os.ReadDir(filepath.Join(store, d.Name()))
		for _, o := range objs {
			if live[d.Name()+o.Name()] {
				continue
			}
			p := filepath.Join(store, d.Name(), o.Name())
			if fi, err := os.Stat(p); err == nil {
				freed += fi.Size()
			}
			if os.Remove(p) == nil {
				removed++
			}
		}
	}
	fmt.Printf("kept the newest %d session(s); dropped %d unreferenced object(s), %s\n",
		keep, removed, humanSize(freed))
}

func parsePositive(s string) (int, error) {
	n := 0
	for _, r := range s {
		if r < '0' || r > '9' {
			return 0, errors.New("not a number")
		}
		n = n*10 + int(r-'0')
	}
	if n == 0 {
		return 0, errors.New("must be positive")
	}
	return n, nil
}

func humanSize(b int64) string {
	switch {
	case b >= 1<<30:
		return fmt.Sprintf("%.1f GiB", float64(b)/(1<<30))
	case b >= 1<<20:
		return fmt.Sprintf("%.1f MiB", float64(b)/(1<<20))
	case b >= 1<<10:
		return fmt.Sprintf("%.1f KiB", float64(b)/(1<<10))
	}
	return fmt.Sprintf("%d B", b)
}

func rollbackUsage() {
	fmt.Fprint(os.Stderr, `azkaban rollback <list|show|restore|cleanup>

  Runs started with --rollback write for real and are snapshotted either side,
  so destruction is a diff to review rather than a loss.

  list                       every recorded session, newest first
  show ID [substring...]     what that run changed
  restore ID [substring...]  put those files back
  cleanup [N]                keep the newest N sessions (default 10) and drop
                             any stored content nothing refers to

  A path substring narrows show and restore, because "put back the one file it
  ate" is the common case and restoring everything would also undo the work.
`)
}
