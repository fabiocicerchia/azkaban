package main

// --------------------------------------------------------------------------- //
// The run record.
//
// --dry-run is the auditability mechanism for what a jail *would* do, and it is
// exact. What was missing is the other tense: after a run, there was no way to
// answer "what did this jail actually have access to, and what did it do?".
// Everything that could have told you — the degradation warnings, the docker
// filter's denials — went to stderr and scrolled away with the terminal, which
// is precisely where you are looking when something has already gone wrong.
//
// One JSONL file per run, written by the OUTER process. Deliberately plain:
// greppable, jq-able, and readable by someone who has never seen this file.
// Hash-chaining and DSSE are what you add once the log is evidence against the
// child that produced it; this is not that yet, and pretending otherwise would
// be worse than the honest version.
//
// On by default, because a log nobody enabled records nothing.
// --------------------------------------------------------------------------- //

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"
)

// auditor writes one run's events. A nil *auditor is a working no-op, so every
// call site can be unconditional and --no-audit costs one nil check.
type auditor struct {
	mu    sync.Mutex
	f     *os.File
	path  string
	start time.Time
}

// auditLog is the process-wide record. Package-level because the docker proxy
// runs in this same process on its own goroutines and has no other route to it,
// and threading a handle through the whole call graph for one consumer would
// cost more readability than it buys.
var auditLog *auditor

// startAudit opens the run's log. Failure is never fatal: an unwritable state
// directory must not be the reason a jail refuses to start.
func startAudit(enabled bool, now time.Time) *auditor {
	if !enabled {
		return nil
	}
	dir := auditDir()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		fmt.Fprintln(os.Stderr, "azkaban: warning: cannot create "+dir+"; this run is not being recorded")
		return nil
	}
	name := fmt.Sprintf("%s-%d.jsonl", now.UTC().Format("20060102T150405Z"), os.Getpid())
	f, err := os.OpenFile(filepath.Join(dir, name), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		fmt.Fprintln(os.Stderr, "azkaban: warning: cannot write the run record ("+err.Error()+"); continuing")
		return nil
	}
	return &auditor{f: f, path: f.Name(), start: now}
}

// auditDir is $XDG_STATE_HOME/azkaban/audit, or the spec's default for it.
func auditDir() string {
	base := os.Getenv("XDG_STATE_HOME")
	if base == "" {
		home, _ := os.UserHomeDir()
		base = filepath.Join(home, ".local", "state")
	}
	return filepath.Join(base, "azkaban", "audit")
}

// event appends one record. Order of writes is the order things happened, which
// is the only structure this file has.
func (a *auditor) event(kind string, fields map[string]any) {
	if a == nil {
		return
	}
	rec := map[string]any{
		"t":     time.Now().UTC().Format(time.RFC3339Nano),
		"event": kind,
	}
	for k, v := range fields {
		rec[k] = v
	}
	line, err := json.Marshal(rec)
	if err != nil {
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	fmt.Fprintln(a.f, string(line))
}

// close records the exit and shuts the file. Separate from event() so the
// duration is measured against the same clock that opened it.
func (a *auditor) close(code int) {
	if a == nil {
		return
	}
	a.event("exit", map[string]any{
		"code":        code,
		"duration_ms": time.Since(a.start).Milliseconds(),
	})
	a.mu.Lock()
	defer a.mu.Unlock()
	a.f.Close()
}

// degraded records something that silently made the jail weaker than asked for.
//
// These are the events worth having most: every one of them is currently a
// single stderr line, and every one of them is what you go looking for after
// something has already gone wrong. It prints as well as records, because the
// warning is still worth seeing live.
func (a *auditor) degraded(what, detail string) {
	fmt.Fprintln(os.Stderr, "azkaban: WARNING: "+detail)
	a.event("degraded", map[string]any{"what": what, "detail": detail})
}

// --- redaction ---------------------------------------------------------------

// secretFlag matches an argument that names a credential. The VALUE after such
// a flag is dropped, and so is the inline half of --token=abc.
var secretFlag = regexp.MustCompile(`(?i)(token|secret|password|passwd|api[-_]?key|credential|auth)`)

// looksLikeSecret catches a bare value that is probably a credential even
// though nothing named it: long, no spaces, and made of the alphabet keys and
// tokens are made of.
var looksLikeSecret = regexp.MustCompile(`^(?:[A-Za-z0-9_\-]{32,}|[A-Za-z0-9+/]{40,}={0,2})$`)

// redactArgv scrubs credentials out of a command line before it is written down.
//
// Scrubbed on the way in rather than stored and hoped about: a run record is a
// file that outlives the run, and `--token abc123` on a command line is exactly
// the sort of thing that ends up in one and is never thought about again.
//
// This is a heuristic and cannot be complete. It errs towards redacting: a
// record that says <redacted> where a harmless argument was is a mild
// annoyance, and the other mistake is a credential on disk.
func redactArgv(argv []string) []string {
	out := make([]string, 0, len(argv))
	dropNext := false
	for _, arg := range argv {
		if dropNext {
			out = append(out, "<redacted>")
			dropNext = false
			continue
		}
		name, value, inline := strings.Cut(arg, "=")
		switch {
		case inline && secretFlag.MatchString(name):
			out = append(out, name+"=<redacted>")
		case strings.HasPrefix(arg, "-") && secretFlag.MatchString(arg):
			// The credential is the *next* argument.
			out = append(out, arg)
			dropNext = true
		case !strings.HasPrefix(arg, "-") && looksLikeSecret.MatchString(arg):
			out = append(out, "<redacted>")
		default:
			_ = value
			out = append(out, arg)
		}
	}
	return out
}

// envNames records WHICH host variables were forwarded, never their values.
//
// `env NAME` in the config is how ANTHROPIC_API_KEY reaches the jail. The names
// are the useful half — "this run could see that variable" — and the values are
// the half that must never be in a file.
func envNames(keys []string) []string {
	out := make([]string, 0, len(keys))
	for _, k := range keys {
		if _, ok := os.LookupEnv(k); ok {
			out = append(out, k)
		}
	}
	return out
}
