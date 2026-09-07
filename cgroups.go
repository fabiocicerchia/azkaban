package main

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"
)

// cgroup v2 limits.

// --------------------------------------------------------------------------- //
// cgroup v2 limits.
//
// RLIMIT_FSIZE caps one file; it cannot cap the OVERLAY, whose pages live in
// tmpfs and are charged as memory. memory.max is the only thing that actually
// bounds "agent writes in a loop until the host OOMs". pids.max backs up
// RLIMIT_NPROC, which is per-UID and therefore shared with the rest of your
// session.
//
// A cgroup is created as a SIBLING of our own: cgroup v2 forbids enabling
// controllers on a cgroup that holds processes, and ours holds this one. The
// child is placed with clone3(CLONE_INTO_CGROUP) so it cannot fork before being
// confined. Every step degrades to a warning — an unavailable cgroup tree must
// not stop the jail from running.
// --------------------------------------------------------------------------- //

// setupCgroup - Creates the sibling cgroup and returns a handle to it, or nil
// when the tree is unusable. The caller passes the handle to clone3 so the
// child lands in the cgroup before it can fork; nil simply means the memory cap
// is not enforced, never that the jail should refuse to start.
func setupCgroup(memMax string, pidsMax int) *os.File {
	// An explicitly requested cap that cannot be enforced is a hard failure, not
	// a warning. docs/design.md positions --mem-max as "the real bound" on the
	// RAM-backed overlay — the rlimits are per-file and do not bound total
	// overlay growth — so degrading leaves the flag looking like it worked while
	// the jail runs with no memory bound at all, having printed one line that
	// scrolls away. Nothing asked for cannot be refused; only the pidsMax-only
	// path still degrades, because nobody asked for that one.
	unavailable := func(why string) *os.File {
		if memMax != "" {
			fatal(1, "--mem-max "+memMax+" cannot be enforced: "+why+".\n"+
				"  A cap that silently does nothing is worse than no cap — this run would have\n"+
				"  had no memory bound at all. Delegate a cgroup v2 memory controller, or drop\n"+
				"  --mem-max to run without one.")
		}
		return cgroupUnavailable(why)
	}

	data, err := os.ReadFile("/proc/self/cgroup")
	if err != nil {
		return unavailable("cannot read /proc/self/cgroup")
	}
	var rel string
	for _, l := range strings.Split(string(data), "\n") {
		if after, ok := strings.CutPrefix(l, "0::"); ok {
			rel = after
		}
	}
	if rel == "" {
		return unavailable("no cgroup v2 mount for this process")
	}
	parent := filepath.Dir(filepath.Join("/sys/fs/cgroup", rel))
	//nolint:errcheck // a file that cannot be read is answered as absent by the check below
	sub, _ := os.ReadFile(filepath.Join(parent, "cgroup.subtree_control"))
	if !strings.Contains(string(sub), "memory") {
		return unavailable("no delegated memory controller at " + parent)
	}

	dir := filepath.Join(parent, fmt.Sprintf("azkaban-%d", os.Getpid()))
	if err := os.Mkdir(dir, 0o755); err != nil {
		return unavailable("cannot create " + dir + ": " + err.Error())
	}
	tempTrack(dir) // removed by the same cleanup path as the temp files

	if memMax != "" {
		// Same reasoning: reaching here means the tree is usable, so a refused
		// write is the cap not being applied, and it must not pass as a warning.
		if err := os.WriteFile(filepath.Join(dir, "memory.max"), []byte(memMax), 0o644); err != nil {
			fatal(1, "--mem-max "+memMax+" cannot be enforced: could not set memory.max: "+err.Error())
		}
		// Without this the cap is advisory: memory.max triggers reclaim, and on a
		// machine with swap the excess is simply paged out instead of refused.
		// Measured: 256 MiB allocated fine under a 64 MiB cap until swap was
		// disabled for the group.
		if err := os.WriteFile(filepath.Join(dir, "memory.swap.max"), []byte("0"), 0o644); err != nil {
			auditLog.degraded("cgroup-swap",
				"could not disable swap for the cgroup; --mem-max will page out rather than refuse.")
		}
	}
	if pidsMax > 0 {
		// Same reasoning as memory.max above: reaching here means the tree is
		// usable, so a refused write is the cap not being applied.
		if err := os.WriteFile(filepath.Join(dir, "pids.max"), []byte(strconv.Itoa(pidsMax)), 0o644); err != nil {
			fatal(1, "--pids-max cannot be enforced: could not set pids.max: "+err.Error())
		}
	}

	fd, err := os.Open(dir)
	if err != nil {
		return unavailable("cannot open " + dir)
	}
	return fd
}

// maskFileOnce - Lazily creates the single empty file used to blank out every
// masked path; one file serves them all.
func maskFileOnce(p *string) string {
	if *p == "" {
		*p = tempWith("azkaban-mask-", "")
	}
	return *p
}

// cgroupUnavailable - Warns once and returns nil, the "no cap" answer for a run
// that did not ask for one. Loud on purpose: a silently uncapped jail is the one
// that takes the host down. A run that DID ask is refused instead — see the
// unavailable closure in setupCgroup.
func cgroupUnavailable(why string) *os.File {
	auditLog.degraded("cgroup-unavailable", "resource cgroup unavailable ("+why+"); memory is NOT capped.")
	return nil
}

// mentionedInConfig - Reports whether the user's trusted config names this
// path, in which case it is not masked — that is the opt-out for someone who
// genuinely needs `gh` or a registry login inside the jail.
func mentionedInConfig(rel, abs, home string, userRO, userRW, userPersist []string) bool {
	for _, e := range slices.Concat(userRO, userRW, userPersist) {
		if e == rel || resolve(home, e) == abs {
			return true
		}
	}
	return false
}

// llJoin - Serialises one Landlock allowlist for the AZKABAN_LL_* channel.
//
// The inner stage splits these on "\n", so a path that CONTAINS a newline injects
// extra entries into the allowlist. `mkdir $'proj\n/run' && cd it && azkaban` was
// enough to grant Landlock write access to /run — the mount layer still refused,
// but layer 3 was defeated by a directory name.
//
// Refuse rather than sanitise: a newline or NUL in a bind path is always either an
// attack or a mistake, and silently dropping it would hide both.
func llJoin(what string, paths []string) string {
	for _, p := range paths {
		if strings.ContainsAny(p, "\n\x00") {
			fatal(2, "refusing to run: "+what+" path contains a newline or NUL, which would inject "+
				"entries into the landlock allowlist: "+strconv.Quote(p))
		}
	}
	return strings.Join(paths, "\n")
}

// bwrapHas reports whether this bubblewrap advertises a flag, e.g. --tmp-overlay
// (bubblewrap >= 0.9). Note it does NOT prove the kernel allows unprivileged
// overlayfs (Linux >= 5.11); if the kernel refuses, bwrap fails with a clear
// error and --persist is the way out.
var bwrapHelp = sync.OnceValue(func() string {
	// A bubblewrap that cannot answer --help advertises nothing, which is the
	// same conservative answer as a build without the flag.
	out, _ := exec.CommandContext(context.Background(), bwrapBin, "--help").CombinedOutput() //nolint:errcheck // see above
	return string(out)
})

// bwrapHas - Reports whether this bubblewrap advertises a flag.
func bwrapHas(flag string) bool { return strings.Contains(bwrapHelp(), flag) }

// tempCopy - Duplicates a file into /tmp so it can be bound over the original,
// giving a single file the same disposable-write behaviour as --tmp-overlay.
func tempCopy(src string) (string, error) {
	data, err := os.ReadFile(src)
	if err != nil {
		return "", err
	}
	return tempWith("azkaban-copy-", string(data)), nil
}

// Temp files azkaban creates on the host (patched hosts/resolv, mask, file
// overlays, the proxy dir). Tracked centrally because Go does not run defers when
// the process is killed by a signal, and --dry-run used to skip cleanup entirely:
// between them they had left 454 files in /tmp on the author's machine.
var (
	tempMu    sync.Mutex
	tempPaths []string
)

// tempTrack - Records a host path for tempCleanup and hands it back, so a temp
// file can be created and registered in one expression.
func tempTrack(p string) string {
	tempMu.Lock()
	tempPaths = append(tempPaths, p)
	tempMu.Unlock()
	return p
}

// tempCleanup - Removes every tracked temp path. Safe to call twice: the list
// is emptied under the lock, so the signal handler and the normal exit path
// cannot double-remove or race.
func tempCleanup() {
	tempMu.Lock()
	defer tempMu.Unlock()
	for _, p := range tempPaths {
		// Best effort by definition: this also runs from a signal handler, and
		// a file that will not delete is a leaked temp file, not a failed run.
		_ = os.RemoveAll(p) //nolint:errcheck // see above
	}
	tempPaths = nil
}

// cleanupOnSignal - Removes the temp files on Ctrl-C. It restores the default
// handler and re-raises, so the exit status still reflects the signal.
func cleanupOnSignal() {
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)
	go func() {
		s := <-ch
		tempCleanup()
		// The channel only ever carries the three signals registered above, all
		// of which are syscall.Signal.
		sig, _ := s.(syscall.Signal) //nolint:errcheck // see above
		signal.Reset(sig)
		_ = syscall.Kill(os.Getpid(), sig) //nolint:errcheck // re-raising to exit with the signal's status
	}()
}

// tempWith - Writes content to a new /tmp file and tracks it. A failure here
// is fatal rather than degraded: every caller is building a file the jail is
// about to have bound over a real one.
func tempWith(prefix, content string) string {
	return tempWithMode(prefix, content, 0)
}

// tempWithMode - tempWith, with an explicit mode. Only the Claude Code hook
// needs one: it is a script the agent executes, and CreateTemp's 0600 is not
// executable.
func tempWithMode(prefix, content string, mode os.FileMode) string {
	f, err := os.CreateTemp("/tmp", prefix)
	if err != nil {
		fatal(1, err.Error())
	}
	if _, err := f.WriteString(content); err != nil {
		_ = f.Close() //nolint:errcheck // closing on the way out; a failed close has nothing left to report
		fatal(1, "writing "+f.Name()+": "+err.Error())
	}
	if err := f.Close(); err != nil {
		// A short write surfaces at close; binding a truncated file over a real
		// one is exactly what this function must not do quietly.
		fatal(1, "writing "+f.Name()+": "+err.Error())
	}
	if mode != 0 {
		if err := os.Chmod(f.Name(), mode); err != nil {
			fatal(1, err.Error())
		}
	}
	return tempTrack(f.Name())
}

// presentUnder - The $HOME-relative entries that actually exist on the host.
//
// The jail's self-description must list what it got, not what was asked for:
// every bind loop skips an entry with no source, so naming one here would tell
// the agent a path is available when it is not — which is the exact confusion
// this file exists to remove.
func presentUnder(home string, entries []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, rel := range entries {
		p := resolve(home, rel)
		if !exists(p) || seen[p] {
			continue
		}
		seen[p] = true
		out = append(out, p)
	}
	return out
}

// splitEnv - Reads one AZKABAN_LL_* allowlist. FieldsFunc drops empty fields,
// so blank entries and a trailing newline need no special-casing.
func splitEnv(k string) []string {
	//nolint:forbidigo // the AZKABAN_LL_* allowlists, read inside the jail from
	// the environment the outer stage set for exactly this
	return strings.FieldsFunc(os.Getenv(k), func(r rune) bool { return r == '\n' })
}

// exists - Follows symlinks on purpose: bwrap resolves bind SOURCES, so a
// dangling symlink is not a usable source and must not be offered as one (Lstat
// would say it exists and bwrap would then hard-fail with "Can't find source
// path").
func exists(p string) bool { _, err := os.Stat(p); return err == nil }

// isDir - Reports whether p is a directory, following symlinks like exists.
func isDir(p string) bool { fi, err := os.Stat(p); return err == nil && fi.IsDir() }

// resolve - Turns a config entry into an absolute path: absolute entries are
// used as-is, everything else is relative to $HOME.
func resolve(home, p string) string {
	if filepath.IsAbs(p) {
		return p
	}
	return filepath.Join(home, p)
}

// bindSafe - Rejects a writable bind that would undo the home tmpfs: "/", $HOME
// itself, or any ancestor of $HOME re-exposes every path the jail just hid.
func bindSafe(home, p string) bool {
	p = filepath.Clean(p)
	return p != "/" && p != home && !strings.HasPrefix(home, p+string(os.PathSeparator))
}

// loadUserBinds reads extra binds and env passthrough from the per-user config
// at ~/.config/azkaban/config. That file is trusted, which is only true because
// the jail re-binds its directory read-only (see azkabanCfgDir) — the repo's own
// files are never consulted.
// Format: one "ro <path>", "rw <path>", "persist <path>", "env <NAME>" or
// "mask <path>" per line; # comments; blank lines ok. Paths are $HOME-relative
// unless absolute.
// "mask" blanks a path out; naming a masked path with "ro"/"rw"/"persist"
// un-masks it. "persist" also opts that one path out of the throwaway overlay.
type userConf struct {
	ro, rw, env, mask, persist, net, credential []string
	// AF_UNIX grants, the every-run form of --unix-socket/--unix-socket-dir.
	unixSocket, unixSocketDir []string
	// auditOff records `audit off`. A bool rather than a list because it is a
	// switch, and the default (record) has to survive a config that says
	// nothing about it.
	auditOff bool
}

// loadUserBinds - Reads ~/.config/azkaban/config, or an empty config when
// there is none. A missing file is the normal case, not an error.
func loadUserBinds(home string) userConf {
	data, err := os.ReadFile(filepath.Join(home, azkabanCfgDir, "config"))
	if err != nil {
		return userConf{}
	}
	return parseUserBinds(string(data))
}

// parseUserBinds - Parses the config format. Unknown keywords and malformed
// lines are skipped rather than rejected: this file is trusted input, and a
// typo must not stop the jail from starting with the rest of the list.
func parseUserBinds(data string) userConf {
	var c userConf
	for _, line := range strings.Split(data, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		kind, val, ok := strings.Cut(line, " ")
		if !ok {
			continue
		}
		switch val = strings.TrimSpace(val); kind {
		case "ro":
			c.ro = append(c.ro, val)
		case "rw":
			c.rw = append(c.rw, val)
		case "env":
			c.env = append(c.env, val)
		case "mask":
			c.mask = append(c.mask, val)
		case "persist":
			c.persist = append(c.persist, val)
		case "net":
			c.net = append(c.net, val)
		case "credential":
			c.credential = append(c.credential, val)
		case "unix-socket":
			c.unixSocket = append(c.unixSocket, val)
		case "unix-socket-dir":
			c.unixSocketDir = append(c.unixSocketDir, val)
		case "audit":
			// Only "off" turns it off. Anything else — including a typo — leaves
			// the record on, which is the direction a mistake should fail in.
			c.auditOff = val == "off"
		}
	}
	return c
}

// stringList collects a repeatable string flag ("--ro A --ro B") into a slice.
type stringList []string

// String - Renders the collected values, for flag's usage output.
func (s *stringList) String() string { return strings.Join(*s, ",") }

// Set - Appends one occurrence of the flag rather than replacing the previous
// one, which is what makes it repeatable.
func (s *stringList) Set(v string) error { *s = append(*s, v); return nil }

// shquote - Renders a command so it can be pasted into a shell verbatim. Used
// only by --dry-run: an audit line nobody can copy and run is not an audit
// line.
func shquote(args []string) string {
	var b strings.Builder
	for i, a := range args {
		if i > 0 {
			b.WriteByte(' ')
		}
		if a == "" || strings.ContainsAny(a, " \t\n\\\"'$") {
			b.WriteString("'" + strings.ReplaceAll(a, "'", `'\''`) + "'")
		} else {
			b.WriteString(a)
		}
	}
	return b.String()
}

// fatal - Cleans up the temp files, prints the message and exits. os.Exit does
// not run defers, so the cleanup has to happen here rather than being trusted
// to the caller.
func fatal(code int, msg string) {
	// os.Exit runs no defers, so both of these have to be done by hand. A
	// record with no exit line is one that cannot be told apart from a run
	// still in progress — and a run that died is exactly the one being read.
	auditLog.event("fatal", map[string]any{"message": msg})
	auditLog.close(code)
	tempCleanup()
	fmt.Fprintln(os.Stderr, "azkaban: "+msg)
	os.Exit(code)
}

// usage - Prints the flag reference. Hand-written rather than generated from
// the FlagSet: the defaults are the security model, and each one needs a
// sentence saying what it costs to change it.
func usage() {
	fmt.Print(`azkaban [flags] [--] <command> [args...]

  --no-gpu       do not bind GPU devices (/dev/nvidia*, /dev/dri)
  --persist      let writes to $HOME allowlist dirs really land on disk. Default
                 is a throwaway overlay: the tool sees them writable, but writes
                 and deletes evaporate on exit and cannot destroy real data.
  --bind-docker  bind the docker socket behind the filtering proxy (OFF by
                 default; containerd is not offered — gRPC, which the proxy
                 cannot inspect)
  --bind-podman  same, for podman's Docker-compatible REST socket
  --unfiltered-container-socket
                 bind the socket with NO filtering at all. Says how to bind, not
                 which — pair it with --bind-docker or --bind-podman.
  --display      pass through X11/wayland/XAUTHORITY + the wayland/pulse sockets
                 from /run/user (OFF by default; ssh-agent, gpg-agent, dbus and
                 any rootless container socket in there stay hidden)
  --ssh-agent    forward the agent (+ known_hosts read-only) so git push over ssh
                 works. The jail talks to a FILTERING PROXY in the outer process
                 that forwards only "list keys" and "sign this" and refuses add,
                 remove, lock and extensions — so a tool inside can no longer
                 delete the keys you loaded or lock your host agent. The keys
                 stay on the host either way; the jail gets a signing oracle,
                 and that oracle still authenticates as you to every host they
                 open. OFF by default; ~/.ssh itself is never bound.
  --ssh-agent-confirm
                 ...and ask on the terminal before every signature. This is
                 "ssh-add -c" for a jail that cannot reach the host's prompt.
  --ssh-agent-raw
                 ...bind the REAL agent socket with no filter, the pre-proxy
                 behaviour. Anything in the jail can then add, remove or lock
                 your keys as well as sign with them.
  --unix-socket PATH
                 bind ONE unix socket, and nothing around it. For "this tool may
                 reach Postgres at /tmp/.s.PGSQL.5432" without granting /tmp.
                 Repeatable; connect and bind are not distinguished. For every
                 run, use "unix-socket" lines in the config.
  --unix-socket-dir DIR
                 same, for a directory whose socket names are generated at
                 runtime (PID-suffixed paths). Wider by exactly one directory,
                 which is why both exist. Repeatable.
  --allow-userns permit nested user namespaces (needed by Chrome/Electron tools)
  --no-net       isolate the network in a new namespace (breaks internet access)
  --net-ports L  allow outbound TCP only to these ports (comma-separated), enforced
                 by landlock. Blocks localhost services and LAN scanning. UDP and
                 therefore DNS are unaffected. Needs the landlock stage.
  --net-host H   allow outbound traffic only to this host, through a CONNECT
                 proxy in the outer process. Repeatable; "*.example.com" covers
                 subdomains but not the bare domain. TLS is NOT intercepted —
                 the target is checked and raw bytes relayed. Sets HTTPS_PROXY
                 in the jail and narrows --net-ports to the proxy, so a client
                 that ignores the variable is refused by the kernel rather than
                 connecting directly. Needs the landlock stage. For every run,
                 use "net <host>" lines in the config.
  --keep-env     inherit the whole host environment (default: clear it and pass
                 only HOME/PATH/TERM/LANG/...; add more with "env NAME" in
                 ~/.config/azkaban/config)
  --mem-max SIZE cap total memory with a cgroup (e.g. 8G). The overlay writes to
                 tmpfs, i.e. RAM, and this is the only thing that bounds it. Off
                 by default: a cap also disables swap for the jail, so a workload
                 that would have paged out is killed instead.
  --no-rlimits   do not cap file size / process count (default caps them; the
                 overlay writes to RAM, so a runaway write can OOM the host)
  --no-landlock  skip the landlock stage
  --ro PATH      bind one extra path read-only, this run only. Repeatable.
  --rw PATH      same, writable (still overlaid unless --persist). Repeatable.
                 $HOME-relative; / and $HOME are refused; un-masks any credential
                 store named. For every run, use "ro"/"rw" lines in the config.
  --persist-path PATH
                 exempt ONE path from the throwaway overlay: writes to it land on
                 the host, everything else still evaporates. For the file a tool
                 must keep across runs (a login token) without --persist making
                 the whole allowlist destroyable. Repeatable; name the file, not
                 its directory. For every run, use "persist" lines in the config.
  --credential P allow the jail to use a host credential WITHOUT giving it the
                 secret: it talks plain HTTP to a loopback broker, which attaches
                 the real token and makes the TLS connection itself. "github" is
                 the only provider so far; add " write" to permit push, which the
                 default read-only policy refuses. Repeatable. For every run, use
                 "credential <provider>" lines in the config.
  --rollback     snapshot the writable $HOME roots either side of the run and
                 let writes land FOR REAL, so destruction becomes a diff to
                 review rather than a loss. An alternative to the default
                 throwaway overlay, not a layer on it. Review and undo with
                 "azkaban rollback show|restore".
  --elevate      let a denied READ be approved on the terminal instead of ending
                 the run. A seccomp supervisor in the outer process traps opens,
                 asks you about any path outside the allowlist, and hands back a
                 read-only descriptor it opened itself — so a grant is bounded by
                 your own permissions and cannot exceed them. Landlock stays the
                 floor: anything the supervisor does not answer is denied by the
                 kernel as usual. Writes are never elevated. OFF by default, and
                 rate-limited to 10 prompts/s so a tool in a loop cannot wear you
                 down. Needs the landlock stage.
  --dry-run      print the bwrap command instead of running it
  --no-guidance  do not describe the jail to the tool inside it. By default
                 /run/azkaban holds a read-only policy.json, a README, a Claude
                 Code PostToolUse hook and this binary, so a confused agent can
                 run "azkaban why --self" instead of guessing at an error.
  --no-audit     do not record this run. Every run is otherwise written as JSONL
                 to $XDG_STATE_HOME/azkaban/audit/ — the resolved policy, the
                 mode flags, every degradation, every docker-filter decision and
                 the exit code. "audit off" in the config turns it off for good.
  -h, --help     this help

  azkaban why    explain what the jail would do with one path, host or port,
                 without starting one. "azkaban why -h" for its flags.
  azkaban rollback  list, review and undo what a --rollback run changed.
`)
}

// --------------------------------------------------------------------------- //
