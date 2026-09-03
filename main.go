// azkaban — minimal, auditable bwrap + landlock sandbox for AI CLIs.
//
// A small, self-contained sandbox, small enough to read in one sitting. One
// binary, two roles:
//
//	default            build the bwrap command and re-exec self inside the jail
//	--landlock-exec    (runs INSIDE bwrap) apply landlock, then exec the command
//
// Defaults, all chosen so that the damaging case needs an explicit flag:
//   - $HOME allowlist writes go to a THROWAWAY OVERLAY (--persist for real writes)
//   - NO container socket is bound (--bind-docker/--bind-podman bind one behind a filtering
//     proxy; --unfiltered-container-socket hands over the unfiltered socket)
//   - the host environment is CLEARED but for a small allowlist (--keep-env)
//   - credential stores inside allowlisted dirs are MASKED (see maskPaths)
//   - file size and process count are CAPPED (--no-rlimits); memory is NOT
//     (--mem-max, opt-in: a cap also disables swap for the jail)
//   - display/IPC passthrough OFF (--display), network shared (--no-net)
//
// See the ESCAPE VECTORS note at the bottom for what is NOT closed.
//
// Build:  CGO_ENABLED=0 go build -o azkaban .
// Usage:  azkaban [flags] [--] <command> [args...]
package main

import (
	"cmp"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"unicode"

	"github.com/landlock-lsm/go-landlock/landlock"
	"golang.org/x/sys/unix"
	"time"
)

// --------------------------------------------------------------------------- //
// Config — the whole security model lives in these lists. Review them.
// --------------------------------------------------------------------------- //

const jailHostname = "azkaban"

// $HOME entries tools must WRITE to. Everything else under $HOME is HIDDEN
// (not bound) unless listed here or in roPaths. Keep this tight — each entry
// here is attack surface. NOTE: ~/.config is writable, so ~/.config/azkaban is
// re-bound READ-ONLY on top of it (see azkabanCfgDir below) — otherwise the jail
// could rewrite its own bind list and escape on the next run.
// The second group is language toolchains: version managers whose tree holds the
// interpreter itself (a pyenv shim without ~/.pyenv is a dangling script, and
// $PATH silently falls back to /usr/bin/python3 — a different interpreter with
// different packages), and package caches without which a build cannot resolve a
// single dependency. They are rw for the same reason .npm and .gradle are: an
// install inside the jail should work, and the overlay throws the write away on
// exit. Most also carry a bin/ dir that is on the host $PATH — that only bites
// under --persist. A non-standard prefix (`npm config set prefix`, a venv outside
// the project) is per-user, so it belongs in ~/.config/azkaban/config, not here.
var rwPaths = []string{
	".cache", ".claude", ".claude.json", ".config",
	".docker", ".dotnet", ".gradle",
	".local/share", ".local/state", ".npm", ".yarn",

	".asdf", ".bun", ".cargo", ".deno", ".gem", ".local/lib", ".m2",
	".nuget", ".nvm", ".pyenv", ".rbenv", ".rustup", ".sdkman", ".volta", "go",
}

// $HOME entries bound READ-ONLY. Only configs tools genuinely need — NOT a
// blanket "every dotfile" (that leaked ~/.ssh, ~/.aws, ~/.gnupg). Extend via
// the per-user config file ~/.config/azkaban/config (see loadUserBinds).
// .local/bin is where user-installed CLIs live (claude, pipx, uv, ...). Their
// payload under .local/share is already bound, so hiding the launcher symlinks
// only breaks PATH lookups; read-only costs nothing extra.
var roPaths = []string{".gitconfig", ".local/bin"}

// roFreeze entries are re-bound READ-ONLY *after* the rw list, so a writable
// parent directory cannot be used to rewrite them. Each is config that steers a
// tool into running code on the NEXT invocation:
//
//	.config/azkaban    our own bind list — writable = a one-line escape
//	.config/containers containers.conf hooks_dir = arbitrary code on container run
//
// These matter most under --persist; with the default tmp-overlay a write would
// land in a discarded tmpfs anyway. ~/.docker (credsStore) relies on that
// overlay rather than being frozen, since the docker CLI legitimately writes it.
var roFreeze = []string{azkabanCfgDir, ".config/containers"}

// maskPaths are credential stores that live INSIDE directories the allowlist
// binds wholesale. The top-level model is deny-by-default — ~/.ssh simply does
// not exist in the jail — but ~/.config is bound entire, and on a normal dev box
// that directory holds API tokens. The overlay stops them being destroyed; it
// does nothing to stop them being read and sent somewhere, and azkaban does not
// filter network egress.
//
// Each entry is replaced by an empty tmpfs (dirs) or an empty file, AFTER the
// allowlist binds. To keep one, name it in ~/.config/azkaban/config with
// `ro <path>`; anything the user config mentions is left alone.
var maskPaths = []string{
	".config/containers/auth.json", // podman/skopeo registry auth
	".config/doctl",                // DigitalOcean
	".config/gcloud",               // Google Cloud credentials db
	".config/gh",                   // GitHub OAuth token (hosts.yml)
	".config/git/credentials",      // git credential store
	".config/hub",                  // legacy gh
	".docker/config.json",          // docker registry auth + credsStore
	".local/share/keyrings",        // GNOME keyring
}

// displaySockets are the only $XDG_RUNTIME_DIR entries --display binds. Globs,
// matched against that directory alone. Everything else there stays hidden.
var displaySockets = []string{"at-spi", "dconf", "pipewire-*", "pulse", "wayland-*"}

// containerSockets maps a runtime flag to its socket candidates, best first.
// Podman's REST service speaks the SAME Docker-compatible API, so one filter
// covers both — see the libpod note in dockerproxy.go for what is NOT covered.
// containerd is deliberately absent: it is gRPC, not HTTP, so this proxy cannot
// inspect it at all and binding it unfiltered would be worse than not binding it.
var containerSockets = map[string][]string{
	"docker": {"$XDG/docker.sock", "/var/run/docker.sock"},
	"podman": {"$XDG/podman/podman.sock", "/run/podman/podman.sock"},
}

// envKeep is the ONLY host environment forwarded into the jail; everything else
// is dropped by --clearenv. Inheriting the whole env hands a prompt-injected
// agent ANTHROPIC_API_KEY, GITHUB_TOKEN, AWS_*, and SSH_AUTH_SOCK — hiding
// ~/.ssh is pointless if the agent socket's address rides along for free.
// Add more with `env NAME` in ~/.config/azkaban/config, or --keep-env for the
// old inherit-everything behaviour.
var envKeep = []string{
	"COLORTERM", "HOME", "LANG", "LC_ALL", "LC_CTYPE", "LOGNAME",
	"NO_COLOR", "PATH", "SHELL", "TERM", "TZ", "USER",
}

// /proc entries masked with an empty file. slabinfo and sched_debug are already
// unreadable to a normal user; these two are not.
var procMask = []string{"kallsyms", "modules"}

// /sys subtrees masked with an empty tmpfs (hide firmware/debug/security).
var sysMask = []string{"firmware", "fs/fuse", "kernel/debug", "kernel/security"}

// Path inside the jail where we re-bind this executable for the landlock stage.
const selfInJail = "/tmp/.azkaban-self"

// azkabanCfgDir is $HOME-relative; it holds the TRUSTED bind list, so the jail
// must never be able to write it.
const azkabanCfgDir = ".config/azkaban"

// bwrapBin - The bubblewrap binary, by absolute path: $PATH belongs to the
// caller and this is the process that builds the sandbox.
const bwrapBin = "/usr/bin/bwrap"

// landlockExecFlag - argv[1] that selects the inner stage. main dispatches on
// it and outer prepends it to the inner command; the two must agree or the
// jail re-runs its own outer stage instead of applying Landlock.
const landlockExecFlag = "--landlock-exec"

// The AZKABAN_LL_* channel carries the Landlock allowlists from the outer
// stage to the inner one across the bwrap boundary. Both stages have to spell
// each name identically: splitEnv on an unset variable yields an EMPTY list,
// which Landlock accepts as "grant nothing", so a typo on either side does not
// fail — it silently produces a ruleset that denies the target everything, or,
// for a name the inner stage never reads, one that was never narrowed at all.
// Named once here so the two ends cannot drift apart.
const (
	llEnvPrefix  = "AZKABAN_LL_"
	llEnvRO      = llEnvPrefix + "RO"
	llEnvROFiles = llEnvPrefix + "ROFILES"
	llEnvRW      = llEnvPrefix + "RW"
	llEnvRWFiles = llEnvPrefix + "RWFILES"
	llEnvPorts   = llEnvPrefix + "PORTS"
)

// main - Dispatches to one of the two roles. --landlock-exec means this
// process is already inside bwrap and is the inner stage; anything else is the
// outer stage that has yet to build the jail.
func main() {
	if len(os.Args) > 1 && os.Args[1] == landlockExecFlag {
		landlockStage(os.Args[2:]) // runs inside bwrap
		return
	}
	// A query over the resolved policy, not a run. Kept a subcommand rather
	// than a flag because it takes its own argument set and starts no jail.
	if len(os.Args) > 1 && os.Args[1] == "why" {
		whyCommand(os.Args[2:])
		return
	}
	if len(os.Args) > 1 && os.Args[1] == "rollback" {
		rollbackCommand(os.Args[2:])
		return
	}
	outer(os.Args[1:])
}

// --------------------------------------------------------------------------- //
// Inner role: apply landlock, then exec the target command.
// The allowlists arrive via env vars set by the outer role (auditable: they are
// printed verbatim by --dry-run).
// --------------------------------------------------------------------------- //

// landlockStage - Applies the Landlock ruleset and execs the target command.
// Runs INSIDE bwrap, so the mount layer is already in place; this is layer
// three, and it is the only one that survives into the process the user asked
// for.
func landlockStage(args []string) {
	if len(args) < 2 || args[0] != "--" {
		fatal(2, "usage: "+landlockExecFlag+" -- <cmd> [args...]")
	}
	cmd := args[1:]

	// WithIoctlDev is required, not decorative: landlock ABI v5 added
	// LANDLOCK_ACCESS_FS_IOCTL_DEV, and V5 HANDLES that right while RWDirs/RWFiles
	// deliberately do not GRANT it. Without this, every ioctl on a newly opened
	// device node is denied — openpty() fails with EACCES and any tool that runs a
	// subprocess in a pty breaks. (stdin/stdout keep working: fds inherited from
	// before the sandbox are not re-checked, which is why this hides so well.)
	rules := []landlock.Rule{
		landlock.RODirs(splitEnv(llEnvRO)...).IgnoreIfMissing(),
		landlock.ROFiles(splitEnv(llEnvROFiles)...).IgnoreIfMissing(),
		// WithRefer is the same kind of trap: without it landlock denies every
		// link/rename that CROSSES two directories, with EXDEV. That is how npm,
		// pnpm and yarn populate their cache (link _cacache/tmp/x ->
		// _cacache/content-v2/...), so `npm install` fails on any fresh package
		// while same-directory renames (go, pip) keep working. Refer is granted
		// only on the writable set, and the kernel requires it on BOTH ends of the
		// operation, so it cannot move anything out to a read-only path.
		landlock.RWDirs(splitEnv(llEnvRW)...).WithIoctlDev().WithRefer().IgnoreIfMissing(),
		landlock.RWFiles(splitEnv(llEnvRWFiles)...).WithIoctlDev().IgnoreIfMissing(),
	}

	// Network egress. RestrictPaths deliberately drops network handling, so the
	// ports only take effect through Restrict. Landlock covers TCP connect/bind
	// only: UDP is untouched, so DNS keeps working without an explicit rule.
	//
	// Opt-in, because default-denying would break `curl localhost:3000` — which
	// is a thing agents do constantly — and a sandbox people disable is worth
	// nothing. With it, localhost services, LAN scanning and exfil to arbitrary
	// ports are closed at the kernel, with no proxy in the path.
	ports := splitEnv(llEnvPorts)
	for _, p := range ports {
		n, err := strconv.ParseUint(p, 10, 16)
		if err != nil {
			fatal(2, "bad --net-ports entry: "+p)
		}
		rules = append(rules, landlock.ConnectTCP(uint16(n)))
	}

	// Opt-in dynamic layer, and it goes on BEFORE Landlock deliberately: seccomp
	// is evaluated at syscall entry, the LSM hooks Landlock installs are
	// evaluated inside the syscall. So a supervisor that fails to answer, or
	// answers wrongly, drops the syscall onto the static floor. See elevate.go.
	//
	// A failure here is fatal rather than a warning: --elevate asked for a
	// supervisor, and a run that silently did not get one is the same class of
	// silent no-op that --mem-max used to be.
	if fd := os.Getenv(elevateFDEnv); fd != "" {
		sock, err := strconv.Atoi(fd)
		if err != nil {
			fatal(2, "bad "+elevateFDEnv+": "+fd)
		}
		listener, err := installElevationFilter()
		if err != nil {
			fatal(1, "--elevate: "+err.Error())
		}
		if err := sendListener(sock, listener); err != nil {
			fatal(1, "--elevate: could not hand the listener to the supervisor: "+err.Error())
		}
		// The supervisor holds the only copy from here on. Keeping ours would
		// mean the jail could answer its own notifications.
		syscall.Close(listener)
		syscall.Close(sock)
	}

	cfg := landlock.V5.BestEffort()
	restrict := cfg.RestrictPaths
	if len(ports) > 0 {
		restrict = cfg.Restrict // also handles (and therefore denies) TCP
	}
	if err := restrict(rules...); err != nil {
		fatal(1, "landlock: "+err.Error())
	}

	bin, err := exec.LookPath(cmd[0])
	if err != nil {
		fatal(127, err.Error())
	}
	// Replace this process; landlock restrictions are inherited across exec.
	// Drop our own AZKABAN_LL_* channel — the target has no business reading the
	// allowlist, and it only advertises what the sandbox looks like.
	var env []string
	for _, kv := range os.Environ() {
		if !strings.HasPrefix(kv, llEnvPrefix) {
			env = append(env, kv)
		}
	}
	if err := syscall.Exec(bin, cmd, env); err != nil {
		fatal(126, err.Error())
	}
}

// --------------------------------------------------------------------------- //
// Outer role: parse flags, build the bwrap invocation, run it.
// --------------------------------------------------------------------------- //

// bwrapArgs - The bwrap option list under construction. Order is load-bearing:
// bwrap applies its arguments in sequence, so a bind added later wins over one
// added earlier, and roFreeze/maskPaths depend on exactly that. Appending is
// the only operation, which is what keeps that sequence readable as one pass
// down outer() and verbatim in --dry-run's output.
type bwrapArgs []string

// add - Appends one option and its operands to the invocation.
func (b *bwrapArgs) add(xs ...string) { *b = append(*b, xs...) }

// jailOpts - What the flags decided, resolved once. Named for what the jail
// will BE rather than for the flag that was typed: several are negatives
// (--no-gpu, --no-landlock, --persist), and inverting them here keeps every
// test further down positive.
type jailOpts struct {
	gpu, overlay, landlockOn, rlimits  bool
	display, netIsolate, sshAgent      bool
	keepEnv, dry, allowUserns, rawSock bool
	memMax, netPorts                   string
	// socketKind is "", "docker" or "podman": which container socket to bind.
	socketKind string
	// Per-run additions to the config file's ro/rw/persist lists.
	ro, rw, persist []string

	// noAudit, noGuidance and rollback control what the run leaves behind: the
	// JSON run record, the note telling the agent it is jailed, and the
	// reviewable snapshot of what it changed.
	noAudit, noGuidance, rollback bool
	// elevate runs the seccomp supervisor, which can hand the jail a read-only
	// descriptor for a path outside the bind list after a prompt.
	elevate bool
	// sshAgentRaw binds the real agent socket; sshAgentConfirm puts the
	// filtering proxy in front of it and asks before each signature.
	sshAgentRaw, sshAgentConfirm bool
	// Extra sockets and socket directories to bind, and the egress allowlist
	// and broker ports the network filter enforces.
	unixSocket, unixSocketDir []string
	egressHosts, brokerPorts  []string
	// Per-run additions to the config file's net/credential lists.
	netHost, credential []string
	// persistAll is --persist as asked for. `overlay` cannot stand in for it:
	// --rollback clears the overlay too, and the run record has to say which of
	// the two turned it off.
	persistAll bool
}

// parseFlags - Turns argv into the settings above plus the command to run.
// done is true when --help was served and the caller should stop; every other
// parse failure exits through fatal(2) rather than returning.
func parseFlags(argv []string) (o jailOpts, cmd []string, done bool) {
	// flag.Parse stops at the first non-flag argument and honours "--", which is
	// exactly the "everything from here on is the command" rule this needs.
	// ContinueOnError (rather than ExitOnError) so -h still exits 0 and every
	// other parse error goes through fatal(2) like the rest of the tool.
	fs := flag.NewFlagSet("azkaban", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	fNoGPU := fs.Bool("no-gpu", false, "")
	fDocker := fs.Bool("bind-docker", false, "")
	fPodman := fs.Bool("bind-podman", false, "")
	fRawSock := fs.Bool("unfiltered-container-socket", false, "")
	// Writes to $HOME allowlist dirs go to a throwaway tmpfs by default, so a
	// destructive tool cannot delete real data. --persist opts back into real writes.
	fPersist := fs.Bool("persist", false, "")
	fNoRlimits := fs.Bool("no-rlimits", false, "")
	fAllowUserns := fs.Bool("allow-userns", false, "")
	fMemMax := fs.String("mem-max", "", "")
	fNetPorts := fs.String("net-ports", "", "")
	fDisplay := fs.Bool("display", false, "")
	fSSHAgent := fs.Bool("ssh-agent", false, "")
	// The agent grant, narrowed. By default --ssh-agent now goes through a
	// filtering proxy that forwards only "list keys" and "sign this"; these two
	// widen it back or narrow it further. See sshagentproxy.go.
	fSSHAgentRaw := fs.Bool("ssh-agent-raw", false, "")
	fSSHAgentConfirm := fs.Bool("ssh-agent-confirm", false, "")
	// One unix socket, bound as a file. The alternative was `--rw /tmp`, which
	// grants the socket and everything around it. Repeatable.
	var fUnixSocket, fUnixSocketDir stringList
	fs.Var(&fUnixSocket, "unix-socket", "")
	fs.Var(&fUnixSocketDir, "unix-socket-dir", "")
	fNoNet := fs.Bool("no-net", false, "")
	fNoLandlock := fs.Bool("no-landlock", false, "")
	fKeepEnv := fs.Bool("keep-env", false, "")
	fDry := fs.Bool("dry-run", false, "")
	// On by default: a log nobody enabled records nothing. --no-audit and an
	// `audit off` line in the config are the two ways out.
	fNoAudit := fs.Bool("no-audit", false, "")
	// The jail describes itself to the tool inside it. Opt-out for a run where
	// three extra read-only binds under /run are unwanted.
	fNoGuidance := fs.Bool("no-guidance", false, "")
	// Snapshot either side of the run instead of discarding writes. An
	// ALTERNATIVE to the overlay, not a layer on it: rollback implies real
	// writes, because there is nothing to review if they never happened.
	fRollback := fs.Bool("rollback", false, "")
	// A denial normally ends the run: Landlock is irreversible, so "the tool
	// needed one path nobody listed" costs the whole session. --elevate puts a
	// seccomp supervisor above the floor that can approve ONE READ, on the
	// terminal, at the moment it is needed. Off by default and loudly so — it
	// is a hole in a wall whose value is being solid. See elevate.go.
	fElevate := fs.Bool("elevate", false, "")
	// Per-run equivalents of the config file's "ro"/"rw" lines, for a path this
	// one run needs and every future run should not. Repeatable; same $HOME-relative
	// resolution, same bindSafe rejection, same un-masking power as the file.
	// Repeatable host allowlist for the egress proxy. Same file-and-flag pairing
	// as ro/rw: `net <host>` in the config is the every-run form.
	var fNetHost, fCredential stringList
	fs.Var(&fNetHost, "net-host", "")
	// `credential github` / `credential github write`. Same file-and-flag
	// pairing as everything else.
	fs.Var(&fCredential, "credential", "")
	var fRO, fRW, fPersistPath stringList
	fs.Var(&fRO, "ro", "")
	fs.Var(&fRW, "rw", "")
	// Per-path form of --persist: one path whose writes must outlive the jail
	// (a login token), without making the whole $HOME allowlist real.
	fs.Var(&fPersistPath, "persist-path", "")
	if err := fs.Parse(argv); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			usage()
			return o, nil, true
		}
		fatal(2, err.Error())
	}

	o.gpu, o.overlay, o.landlockOn, o.rlimits = !*fNoGPU, !*fPersist, !*fNoLandlock, !*fNoRlimits
	o.display, o.netIsolate, o.sshAgent = *fDisplay, *fNoNet, *fSSHAgent
	o.keepEnv, o.dry, o.allowUserns, o.rawSock = *fKeepEnv, *fDry, *fAllowUserns, *fRawSock
	o.memMax, o.netPorts = *fMemMax, *fNetPorts
	o.ro, o.rw, o.persist = fRO, fRW, fPersistPath
	o.noAudit, o.noGuidance, o.rollback = *fNoAudit, *fNoGuidance, *fRollback
	o.elevate = *fElevate
	o.sshAgentRaw, o.sshAgentConfirm = *fSSHAgentRaw, *fSSHAgentConfirm
	o.unixSocket, o.unixSocketDir = fUnixSocket, fUnixSocketDir
	o.netHost, o.credential = fNetHost, fCredential
	o.persistAll = *fPersist
	if (o.sshAgentRaw || o.sshAgentConfirm) && !o.sshAgent {
		fatal(2, "--ssh-agent-raw/--ssh-agent-confirm say HOW to forward the agent; pair with --ssh-agent")
	}
	if o.sshAgentRaw && o.sshAgentConfirm {
		// The raw socket is the real agent: there is nothing in the path that
		// could stop to ask. Refused rather than silently ignoring one of them.
		fatal(2, "--ssh-agent-raw binds the real agent socket; nothing is left to confirm with")
	}
	if o.elevate && !o.landlockOn {
		// Without the floor underneath it, the supervisor is the only thing
		// deciding, and a supervisor that has to be right every time is exactly
		// the design this one avoids. Refused rather than degraded.
		fatal(2, "--elevate needs landlock as its floor; not usable with --no-landlock")
	}
	if o.rollback {
		if *fPersist {
			fatal(2, "--rollback already means real writes; --persist is redundant with it")
		}
		// The overlay is what rollback replaces. Leaving it on would snapshot a
		// directory nothing ever writes to, and report that the run changed
		// nothing — a review screen that is always empty is worse than none.
		o.overlay = false
	}
	// No container socket is bound unless explicitly asked for. On-by-default
	// meant every run exposed a full container API — the one interface the jail
	// cannot police from the inside.
	// --unfiltered-container-socket says HOW to bind, not WHICH socket, so it
	// names no runtime of its own and one of the --bind-* flags is required. It
	// used to imply docker, which made the least explicit spelling the most
	// dangerous request: on a host with no rootless daemon that is the ROOTFUL
	// socket, unfiltered, from a flag that never says "docker" anywhere in it.
	switch {
	case *fPodman:
		o.socketKind = "podman"
	case *fDocker:
		o.socketKind = "docker"
	case o.rawSock:
		fatal(2, "--unfiltered-container-socket says how to bind the socket, not which one: add --bind-docker or --bind-podman")
	}

	cmd = fs.Args()
	if len(cmd) == 0 {
		if sh := os.Getenv("SHELL"); sh != "" {
			cmd = []string{sh}
		} else {
			cmd = []string{"bash"}
		}
	}

	return o, cmd, false
}

// outer - Parses the flags, builds the bwrap invocation from the allowlists at
// the top of this file, and runs it. Everything the jail will be is decided
// here; --dry-run prints the result instead of executing it, which is what
// makes the decision auditable.
func outer(argv []string) {
	var agentProxy *sshAgentProxy
	o, cmd, done := parseFlags(argv)
	if done {
		return
	}

	home, _ := os.UserHomeDir()
	cwd, _ := os.Getwd()
	// cwd is bound read-write; if it IS $HOME (or an ancestor of it) the whole
	// home becomes writable/deletable inside the jail. Refuse — accidental rm
	// protection is the point. The cwd == "/" case is special-cased because
	// "/"+separator is "//", so the HasPrefix ancestor test never fires for it.
	if cwd == "/" {
		fatal(2, "refusing to run: cwd is / — only a project dir should be writable. cd into the project first.")
	}
	if cwd == home || strings.HasPrefix(home, cwd+string(os.PathSeparator)) {
		fatal(2, "refusing to run: cwd ("+cwd+") contains $HOME — only the project dir should be writable. cd into the project first.")
	}
	uid := os.Getuid()
	runtimeDir := fmt.Sprintf("/run/user/%d", uid)
	var maskFile string
	uc := loadUserBinds(home)
	// Merged here, before every consumer (ro binds, rw binds, the mask opt-out),
	// so a flag path and a config path are indistinguishable from this point on.
	uc.ro = append(uc.ro, o.ro...)
	uc.rw = append(uc.rw, o.rw...)
	uc.persist = append(uc.persist, o.persist...)
	uc.net = append(uc.net, o.netHost...)
	uc.credential = append(uc.credential, o.credential...)

	// --dry-run changes nothing, so there is nothing to record; recording it
	// would fill the directory with runs that never happened.
	auditLog = startAudit(!o.noAudit && !uc.auditOff && !o.dry, time.Now())
	defer auditLog.close(0)
	auditLog.event("start", map[string]any{
		"argv":    redactArgv(os.Args[1:]),
		"command": redactArgv(cmd),
		"cwd":     cwd,
		"home":    home,
		"pid":     os.Getpid(),
	})

	// Patched /etc/hosts and /etc/resolv.conf. /run is tmpfs'd (empty) inside
	// the jail, which breaks the usual resolv.conf -> /run/.../stub-resolv.conf
	// symlink, so we re-provide a concrete file.
	cleanupOnSignal()
	defer tempCleanup()
	hostsFile := writeHosts()
	resolvFile := writeResolv()

	// Landlock allowlists, accumulated alongside the mounts. Deliberately TIGHTER
	// than the bwrap mounts — otherwise this stage is a no-op mirror of them and
	// buys nothing. /dev and /run are readable but not writable wholesale; only
	// the handful of device nodes a program actually writes are listed.
	llRO := []string{"/dev", "/etc", "/opt", "/proc", "/run", "/sys", "/usr", home}
	llRW := []string{"/dev/pts", "/dev/shm", "/tmp", cwd}
	llRWFiles := []string{
		"/dev/full", "/dev/null", "/dev/ptmx", "/dev/random",
		"/dev/tty", "/dev/urandom", "/dev/zero",
	}
	var llROFiles []string

	var a bwrapArgs

	// Environment: drop the host env, then re-add the allowlist. MUST come before
	// every --setenv below — bwrap applies args in order and --clearenv wipes
	// whatever preceded it.
	if !o.keepEnv {
		a.add("--clearenv")
		for _, k := range slices.Concat(envKeep, uc.env) {
			if v, ok := os.LookupEnv(k); ok {
				a.add("--setenv", k, v)
			}
		}
	}

	// Base read-only root.
	a.add("--ro-bind", "/usr", "/usr")
	a.add("--symlink", "usr/bin", "/bin")
	a.add("--symlink", "usr/lib", "/lib")
	a.add("--symlink", "usr/lib64", "/lib64")
	a.add("--symlink", "usr/sbin", "/sbin")
	a.add("--ro-bind", "/etc", "/etc")
	a.add("--ro-bind", hostsFile, "/etc/hosts")

	// ssh fatals ("Bad owner or permissions") on any Include'd config file whose
	// owner is neither root nor the caller. bwrap maps ONE uid, so every
	// root-owned file reads as nobody (65534) inside the jail and every
	// /etc/ssh/ssh_config.d drop-in trips that check — `git push` over ssh dies
	// before it opens a socket. Re-serve the same bytes from a file we own.
	sshDropIns, _ := filepath.Glob("/etc/ssh/ssh_config.d/*.conf")
	for _, p := range sshDropIns {
		// Bind at the symlink's TARGET: these drop-ins are usually symlinks into
		// /usr/lib, and bwrap cannot create a mountpoint at a dangling-in-the-jail
		// symlink. ssh follows the link and lands on our copy either way.
		if t, err := filepath.EvalSymlinks(p); err == nil {
			p = t
		}
		if data, err := os.ReadFile(p); err == nil {
			a.add("--ro-bind", tempWith("azkaban-sshconf-", string(data)), p)
		}
	}

	if exists("/opt") {
		a.add("--ro-bind", "/opt", "/opt")
	}
	a.add("--ro-bind", "/sys", "/sys")

	// Kernel interfaces.
	a.add("--dev", "/dev")
	a.add("--proc", "/proc")
	a.add("--tmpfs", "/tmp")
	a.add("--tmpfs", "/run")

	// resolv.conf is usually a symlink into /run (tmpfs'd above, now empty), so
	// bind our copy at the symlink's real target AFTER the tmpfs — otherwise the
	// /etc/resolv.conf symlink dangles and bwrap fails. bwrap makes parent dirs.
	resolvTarget := "/etc/resolv.conf"
	if fi, err := os.Lstat("/etc/resolv.conf"); err == nil && fi.Mode()&os.ModeSymlink != 0 {
		if t, err := filepath.EvalSymlinks("/etc/resolv.conf"); err == nil {
			resolvTarget = t
		}
	}
	a.add("--ro-bind", resolvFile, resolvTarget)

	// /proc entries that describe the host kernel. Addresses are usually zeroed by
	// kptr_restrict, but the symbol and module lists still fingerprint the exact
	// kernel build, which is the first step in picking an exploit.
	for _, p := range procMask {
		a.add("--ro-bind", maskFileOnce(&maskFile), "/proc/"+p)
	}

	// Mask sensitive /sys subtrees.
	for _, s := range sysMask {
		if exists("/sys/" + s) {
			a.add("--tmpfs", "/sys/"+s)
		}
	}

	// GPU passthrough. Landlock now denies /dev writes by default, so each device
	// that is bound must also be granted explicitly or the GPU is unusable.
	if o.gpu {
		devs, _ := filepath.Glob("/dev/nvidia*")
		devs = append(devs, "/dev/dri")
		for _, d := range devs {
			if !exists(d) {
				continue
			}
			a.add("--dev-bind", d, d)
			if isDir(d) {
				llRW = append(llRW, d)
			} else {
				llRWFiles = append(llRWFiles, d)
			}
		}
	}

	// Container socket — OPT-IN (--bind-docker / --bind-podman), because it is the one
	// interface the jail cannot police from the inside: a bind mount requested
	// over this socket is performed by the DAEMON, on the host, outside bwrap and
	// Landlock. On-by-default meant every run handed out a full container API.
	//
	// Prefer the ROOTLESS socket. It runs as this user in a userns, so
	// `--privileged -v /:/host` yields uid-1000-on-host, not root. But rootless
	// does NOT stop `-v /:/host` reaching ~/.ssh as your user, so the socket is
	// bound through a FILTERING PROXY (dockerproxy.go) unless --unfiltered-container-socket.
	// Podman's REST service speaks the same Docker API, so the same proxy applies.
	if o.socketKind != "" {
		realSock := ""
		for _, cand := range containerSockets[o.socketKind] {
			p := strings.ReplaceAll(cand, "$XDG", runtimeDir)
			if exists(p) {
				realSock = p
				break
			}
		}
		switch {
		case realSock == "":
			fatal(1, "no "+o.socketKind+" socket found (looked in "+
				strings.Join(containerSockets[o.socketKind], ", ")+
				"). containerd is not offered: it speaks gRPC, which the filtering proxy cannot inspect.")
		case realSock == "/var/run/docker.sock" || realSock == "/run/podman/podman.sock":
			auditLog.degraded("rootful-container-socket", "no rootless "+o.socketKind+
				"; using ROOTFUL "+realSock+" = host root inside the jail. Set up a rootless daemon to close this.")
		}

		sockForJail := realSock // path bound FROM the host
		switch {
		case o.rawSock:
			auditLog.degraded("unfiltered-container-socket", "--unfiltered-container-socket binds the UNFILTERED socket; `docker run -v /:/h` can read/write everything your user owns.")
		case !o.dry:
			ps, err := startDockerFilterProxy(realSock, cwd)
			if err != nil {
				fatal(1, "container filter proxy: "+err.Error())
			}
			sockForJail = ps
		default:
			// --dry-run exists to be audited, so do not let it imply the raw
			// socket is what gets bound.
			fmt.Fprintln(os.Stderr, "azkaban: note: --dry-run prints the RAW socket as the bind source; a real run substitutes the filtering proxy socket there.")
		}
		a.add("--bind", sockForJail, realSock)
		a.add("--setenv", "DOCKER_HOST", "unix://"+realSock)
		if o.socketKind == "podman" {
			a.add("--setenv", "CONTAINER_HOST", "unix://"+realSock)
		}
		llRWFiles = append(llRWFiles, realSock)
	}

	// Shared memory (needed by chromium/electron based tools).
	if exists("/dev/shm") {
		a.add("--dev-bind", "/dev/shm", "/dev/shm")
	}

	// Display passthrough: X11 + wayland + auth + the whole XDG runtime dir.
	// That dir also holds ssh-agent/gpg-agent/dbus sockets — see vector 3.
	if o.display {
		if exists("/tmp/.X11-unix") {
			a.add("--bind", "/tmp/.X11-unix", "/tmp/.X11-unix")
		}
		if xa := os.Getenv("XAUTHORITY"); xa != "" && exists(xa) {
			a.add("--ro-bind", xa, xa)
		}
		// Bind ONLY the display sockets, never the directory. $XDG_RUNTIME_DIR also
		// holds ssh-agent, gpg-agent, dbus — and a ROOTLESS docker/podman socket,
		// so binding it wholesale handed over the container socket raw and bypassed
		// the --bind-docker opt-in entirely.
		if exists(runtimeDir) {
			a.add("--tmpfs", runtimeDir)
			llRW = append(llRW, runtimeDir)
			for _, pat := range displaySockets {
				ms, _ := filepath.Glob(filepath.Join(runtimeDir, pat))
				for _, m := range ms {
					a.add("--bind", m, m)
				}
			}
		}
	}

	// Home: empty tmpfs, then bind back ONLY an allowlist. Everything else under
	// $HOME (~/.ssh, ~/.aws, ~/.gnupg, sibling projects, ...) stays hidden.
	// Extra paths come from the TRUSTED per-user config, never from the cwd.
	a.add("--tmpfs", home)
	for _, rel := range slices.Concat(roPaths, uc.ro) {
		p := resolve(home, rel)
		if !exists(p) {
			continue
		}
		a.add("--ro-bind", p, p)
		if isDir(p) {
			llRO = append(llRO, p)
		} else {
			llROFiles = append(llROFiles, p)
		}
	}
	// Writable $HOME entries. By DEFAULT each one is an overlay whose upper layer
	// is a throwaway tmpfs: the tool sees a normal writable directory, but every
	// write — and every DELETE — evaporates when the jail exits, and the host copy
	// is untouched. This is the difference between confining *where* writes land
	// (which never stopped `rm -rf ~/.claude` from destroying real data) and
	// making destruction impossible in the first place.
	//
	// --persist turns it off for the runs where writes are meant to survive.
	// Note the project dir is NEVER overlaid; it is the workspace, and it has git.
	if o.overlay && !bwrapHas("--tmp-overlay") {
		auditLog.degraded("no-tmp-overlay", "this bwrap has no --tmp-overlay; falling back to real writes. Upgrade bubblewrap (>= 0.9) or pass --persist to silence this.")
		o.overlay = false
	}
	for _, rel := range slices.Concat(rwPaths, uc.rw) {
		p := resolve(home, rel)
		if !exists(p) {
			continue
		}
		if !bindSafe(home, p) {
			fatal(2, "refusing rw bind "+p+": it would re-expose $HOME (or /) that the jail just hid")
		}
		switch {
		case isDir(p) && o.overlay:
			a.add("--overlay-src", p, "--tmp-overlay", p)
			llRW = append(llRW, p)
		case isDir(p):
			a.add("--bind", p, p)
			llRW = append(llRW, p)
		case o.overlay:
			// overlayfs needs a directory; for a single file the equivalent is a
			// scratch COPY bound over it, so writes land somewhere disposable.
			cp, err := tempCopy(p)
			if err != nil {
				fatal(1, "copying "+p+" for overlay: "+err.Error())
			}
			a.add("--bind", cp, p)
			llRWFiles = append(llRWFiles, p)
		default:
			a.add("--bind", p, p)
			llRWFiles = append(llRWFiles, p)
		}
	}

	// Per-path persistence. The overlay above is all-or-nothing per RUN, which
	// makes "keep my login token" cost "make every allowlist dir really
	// destroyable" — the exact trade --persist was written to avoid. These are
	// bound to the real host inode, AFTER the rw loop so they win over the
	// parent directory's tmp-overlay: a nested bind that comes FIRST is simply
	// covered by the overlay mounted on top of it and silently does nothing.
	//
	// Deliberately narrow: name the file, not the directory. `persist .claude`
	// works and is a legitimate choice, but it hands back the whole rm -rf.
	for _, rel := range uc.persist {
		p := resolve(home, rel)
		if !bindSafe(home, p) {
			fatal(2, "refusing persist bind "+p+": it would re-expose $HOME (or /) that the jail just hid")
		}
		if !exists(p) {
			// Loud, because silence is the failure this whole feature exists to
			// fix: a persist line that does nothing looks exactly like one that
			// works until the token is gone.
			auditLog.degraded("persist-ignored", "persist "+rel+" ignored: no such path on the host. "+
				"A bind needs an existing source — create it outside the jail first.")
			continue
		}
		a.add("--bind", p, p)
		if isDir(p) {
			llRW = append(llRW, p)
		} else {
			llRWFiles = append(llRWFiles, p)
		}
	}

	// ~/.config is writable above (tools need it), which would let the jailed
	// process rewrite ~/.config/azkaban/config — the file loadUserBinds trusts —
	// and escape on the NEXT run with a single `rw /` line. Freeze it and the
	// other code-triggering configs read-only; bound after the rw loop so they
	// win. The azkaban dir has to exist to be a bind source, and creating it here
	// (rather than letting bwrap materialise a mountpoint inside the ~/.config
	// bind) keeps ownership and 0700 perms ours.
	cfgDir := filepath.Join(home, azkabanCfgDir)
	if err := os.MkdirAll(cfgDir, 0o700); err != nil {
		fatal(1, "cannot secure "+cfgDir+": "+err.Error())
	}
	for _, rel := range roFreeze {
		p := resolve(home, rel)
		if !exists(p) {
			continue
		}
		a.add("--ro-bind", p, p)
		llRO = append(llRO, p)
	}

	// Mask credential stores sitting inside the wholesale-bound allowlist dirs.
	// Bound last so they win over everything above. A path the user config names
	// is left alone — that is the escape hatch, no extra syntax needed.
	for _, rel := range slices.Concat(maskPaths, uc.mask) {
		p := resolve(home, rel)
		if !exists(p) || mentionedInConfig(rel, p, home, uc.ro, uc.rw, uc.persist) {
			continue
		}
		if isDir(p) {
			a.add("--tmpfs", p)
			continue
		}
		a.add("--ro-bind", maskFileOnce(&maskFile), p)
	}

	// ssh-agent passthrough. The private keys stay on the host: what crosses the
	// boundary is a SIGNING ORACLE, not the key material, so an exfiltrated jail
	// loses nothing permanent — the oracle dies with the socket. It is still real
	// power while the jail runs: anything inside can authenticate as you to any
	// host your loaded keys open, so this is opt-in and stays off by default.
	// `ssh-add -c` on the host narrows it further, to one confirmation prompt per
	// signature. Bound after the $HOME tmpfs and the mask loop so both binds win.
	if o.sshAgent {
		sock := os.Getenv("SSH_AUTH_SOCK")
		switch {
		case sock == "":
			fatal(1, "--ssh-agent: SSH_AUTH_SOCK is not set; no agent to forward")
		case !exists(sock):
			fatal(1, "--ssh-agent: no socket at "+sock)
		}
		// Default since the filtering proxy exists: the jail talks to a proxy in
		// the outer process, which forwards only "list keys" and "sign this" and
		// refuses add/remove/lock. --ssh-agent-raw is the old behaviour, where
		// the real socket is bound and anything inside can also DELETE the keys
		// you loaded or lock your host agent. See sshagentproxy.go.
		if !o.sshAgentRaw && !o.dry {
			// /tmp, like the args file and every other outer-stage temp: the
			// XDG runtime dir is tmpfs'd inside the jail and is where --display
			// already has too much living.
			proxyDir, err := os.MkdirTemp("/tmp", "azkaban-ssh-")
			if err != nil {
				fatal(1, "--ssh-agent: "+err.Error())
			}
			tempTrack(proxyDir)
			ap, err := newSSHAgentProxy(sock, proxyDir, o.sshAgentConfirm)
			if err != nil {
				fatal(1, "--ssh-agent: "+err.Error())
			}
			agentProxy = ap
			tempTrack(ap.path)
			go ap.serve()
			sock = ap.path
		}
		a.add("--bind", sock, sock)
		a.add("--setenv", "SSH_AUTH_SOCK", sock)
		llRWFiles = append(llRWFiles, sock)

		// Without known_hosts every push dies on "Host key verification failed",
		// which makes the flag look broken. This file holds no secret — only the
		// list of hosts you have reached, which is the small leak the flag costs.
		if kh := filepath.Join(home, ".ssh", "known_hosts"); exists(kh) {
			a.add("--ro-bind", kh, kh)
			llROFiles = append(llROFiles, kh)
		}
	}

	// AF_UNIX grants. A unix socket was previously reachable only if its path
	// happened to fall inside a bind, so "let this tool reach Postgres at
	// /tmp/.s.PGSQL.5432" meant granting /tmp and everything in it. This binds
	// the socket and nothing else. Sharpest under --no-net, where local IPC is
	// the only channel left.
	//
	// LIMIT, stated rather than implied: connect and bind are NOT distinguished.
	// Landlock has no socket-path right, so the kernel cannot tell them apart
	// here; a grant lets the jail bind a name as well as connect to one. Doing
	// better means a seccomp filter on bind(2), which elevate.go now makes
	// possible and nobody has asked for.
	for _, s := range slices.Concat(o.unixSocket, uc.unixSocket) {
		p := resolve(home, s)
		if !bindSafe(home, p) {
			fatal(2, "--unix-socket: refusing "+p)
		}
		if !exists(p) {
			// A socket that is not there yet is almost always a daemon that is
			// not running, and binding a missing path would create a directory
			// the jail then finds empty and confusing.
			fatal(1, "--unix-socket: no socket at "+p)
		}
		a.add("--bind", p, p)
		llRWFiles = append(llRWFiles, p)
	}
	// The directory form exists because tools generate socket names at runtime
	// — PID-suffixed paths, $TMPDIR/tsx-$UID/.pipe — so the name to grant is not
	// knowable when the run starts. Wider than the file form by exactly the
	// contents of one directory, which is why both exist.
	for _, s := range slices.Concat(o.unixSocketDir, uc.unixSocketDir) {
		p := resolve(home, s)
		if !bindSafe(home, p) {
			fatal(2, "--unix-socket-dir: refusing "+p)
		}
		if !isDir(p) {
			fatal(1, "--unix-socket-dir: not a directory: "+p)
		}
		a.add("--bind", p, p)
		llRW = append(llRW, p)
	}

	// Project working dir: writable, and made the cwd.
	a.add("--bind", cwd, cwd)
	a.add("--chdir", cwd)

	// Target binary: expose ONLY the resolved executable, never its $PATH dir.
	// $HOME is tmpfs'd, so a binary reached via ~/.local/bin (or a symlink into
	// a hidden dir) would vanish. Resolve it on the host, bind just that file,
	// and rewrite cmd[0] to the absolute path so no in-jail $PATH lookup is
	// needed. Bound last so it overlays the home tmpfs.
	if binPath, err := exec.LookPath(cmd[0]); err == nil {
		binPath, _ = filepath.EvalSymlinks(binPath)
		a.add("--ro-bind", binPath, binPath)
		llROFiles = append(llROFiles, binPath)
		cmd[0] = binPath
	} else {
		fatal(127, "command not found: "+cmd[0])
	}

	// Isolation.
	a.add("--die-with-parent")
	a.add("--unshare-pid")
	a.add("--unshare-uts")
	a.add("--unshare-ipc")
	a.add("--unshare-cgroup-try")
	// A nested user namespace hands the jailed process a fresh capability set,
	// which is the usual first step of a kernel-exploit chain. Blocking it makes
	// that azkaban's guarantee rather than a property of the host's sysctl.
	// Opt-out because Chrome/Electron-based tools build their own sandbox this way.
	if !o.allowUserns {
		if bwrapHas("--disable-userns") {
			// bwrap refuses --disable-userns without an explicit --unshare-user.
			// It already creates a userns implicitly when unprivileged, so this
			// states what was happening anyway; the uid still maps through to you.
			a.add("--unshare-user")
			a.add("--disable-userns")
		} else {
			fmt.Fprintln(os.Stderr, "azkaban: note: this bwrap has no --disable-userns; nested user namespaces stay available.")
		}
	}
	if o.netIsolate {
		a.add("--unshare-net")
	}
	// The jail keeps our controlling terminal, so on a kernel that still permits
	// it the jail can ioctl(TIOCSTI) characters into that terminal for the host
	// shell to run once azkaban exits. Detaching the session would close it but
	// costs job control on every run, including the majority of kernels where the
	// vector is already shut; the sysctl is the fix, so we only report it.
	if !o.dry {
		warnTIOCSTI()
	}
	a.add("--hostname", jailHostname)

	// Environment.
	if o.display {
		a.add("--setenv", "DISPLAY", cmp.Or(os.Getenv("DISPLAY"), ":0"))
		if xa := os.Getenv("XAUTHORITY"); xa != "" {
			a.add("--setenv", "XAUTHORITY", xa)
		}
		if wd := os.Getenv("WAYLAND_DISPLAY"); wd != "" {
			a.add("--setenv", "WAYLAND_DISPLAY", wd)
		}
		a.add("--setenv", "XDG_RUNTIME_DIR", runtimeDir)
	}
	a.add("--setenv", "PS1", `(jail) \w \$ `)

	// The "before" snapshot, taken while the host is still untouched. Under
	// --rollback the overlay is off, so from here on the run's writes are real.
	var rbSession *rollbackSession
	if o.rollback && !o.dry {
		roots := presentUnder(home, slices.Concat(rwPaths, uc.rw))
		start := time.Now().UTC()
		before, err := takeSnapshot(roots, rollbackStore())
		if err != nil {
			fatal(1, "rollback snapshot: "+err.Error())
		}
		for _, skipped := range before.Skipped {
			auditLog.degraded("rollback-skipped", "not snapshotted: "+skipped+
				"; changes there cannot be rolled back")
		}
		rbSession = &rollbackSession{
			ID: start.Format("20060102T150405Z"), Cmd: cmd, Cwd: cwd,
			Start: start, Before: before,
		}
		fmt.Fprintf(os.Stderr, "azkaban: rollback: snapshotted %d file(s); writes this run are REAL\n",
			len(before.Entries))
	}

	// Credential brokering. Resolved on the HOST, here, before the jail exists:
	// that is the whole mechanism, and nothing after this point has to be
	// trusted with the secret.
	for _, directive := range uc.credential {
		name, write, err := parseCredentialDirective(directive)
		if err != nil {
			fatal(2, "credential: "+err.Error())
		}
		if o.dry {
			// No listener and no secret read in a dry run, but the policy is
			// still disclosed — --dry-run is the audit trail.
			a.add("--setenv", "AZKABAN_CREDENTIAL_"+strings.ToUpper(name), "<brokered at 127.0.0.1:<port>>")
			continue
		}
		b, err := startCredentialBroker(name, write)
		if err != nil {
			fatal(1, "credential broker: "+err.Error())
		}
		for k, v := range b.JailEnv() {
			a.add("--setenv", k, v)
		}
		// The broker is on loopback, so it needs the same port exemption the
		// egress proxy does. Appended rather than replacing: a run can broker a
		// credential and filter egress at once.
		o.brokerPorts = append(o.brokerPorts, strconv.Itoa(b.Port))
		mode := "read-only"
		if write {
			mode = "read-write"
		}
		fmt.Fprintf(os.Stderr, "azkaban: brokering the %s credential (%s); the token never enters the jail\n",
			name, mode)
	}

	// Egress filtering. This must come BEFORE the inner command is assembled:
	// that is where netPorts is turned into AZKABAN_LL_PORTS, and narrowing it
	// afterwards would be a no-op that looks like a working filter.
	//
	// Narrowing --net-ports to the proxy's port is what makes this a filter
	// rather than a suggestion: a client that ignores HTTP_PROXY gets EPERM
	// from Landlock instead of a direct connection.
	if len(uc.net) > 0 {
		if !o.landlockOn {
			fatal(2, "net host filtering needs the landlock stage: without it nothing stops a client "+
				"ignoring HTTP_PROXY and connecting directly, and the allowlist would be decoration")
		}
		if o.netIsolate {
			fatal(2, "--no-net and a net host allowlist are contradictory: --no-net already denies everything")
		}
		// --dry-run is the documented audit trail, so it has to disclose this
		// policy too — but with no listener and no live credential. The port is
		// allocated at run time, so neither can be a real value here.
		ep := &egressProxy{Addr: "127.0.0.1:<port>", Token: "<per-run token>"}
		if !o.dry {
			var err error
			if ep, err = startEgressProxy(uc.net); err != nil {
				fatal(1, "egress proxy: "+err.Error())
			}
		}
		proxyURL := "http://azkaban:" + ep.Token + "@" + ep.Addr
		for _, k := range []string{"HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy"} {
			a.add("--setenv", k, proxyURL)
		}
		// Loopback and the unix socket dir have to stay reachable or the child
		// cannot talk to the proxy at all.
		a.add("--setenv", "NO_PROXY", "localhost,127.0.0.1")
		a.add("--setenv", "no_proxy", "localhost,127.0.0.1")
		// This REPLACES any --net-ports the caller gave: the whole point is that
		// the proxy port is the only way out.
		o.netPorts = strconv.Itoa(ep.Port)
		if o.dry {
			o.netPorts = "<proxy port>"
		}
		o.egressHosts = uc.net
	}

	// Broker ports join the ConnectTCP allowlist. Done after the egress block so
	// that narrowing to the proxy does not lock the jail out of its own broker.
	if len(o.brokerPorts) > 0 {
		if o.netPorts == "" && !o.netIsolate {
			// No port policy at all: the broker needs no exemption because
			// nothing is being restricted.
			o.brokerPorts = nil
		} else {
			o.netPorts = strings.Join(append(strings.FieldsFunc(o.netPorts, func(r rune) bool {
				return r == ',' || unicode.IsSpace(r)
			}), o.brokerPorts...), ",")
		}
	}

	// Assemble the inner command.
	var inner []string
	if o.landlockOn {
		self, err := os.Executable()
		if err != nil {
			fatal(1, "cannot locate self: "+err.Error())
		}
		self, _ = filepath.EvalSymlinks(self)
		a.add("--ro-bind", self, selfInJail)
		a.add("--setenv", llEnvRO, llJoin("RO", llRO))
		a.add("--setenv", llEnvROFiles, llJoin("ROFILES", llROFiles))
		a.add("--setenv", llEnvRW, llJoin("RW", llRW))
		a.add("--setenv", llEnvRWFiles, llJoin("RWFILES", llRWFiles))
		// Entries are validated (and rejected) by the landlock stage; here we only
		// normalise the comma-separated list into the newline-separated channel.
		// FieldsFunc drops empties, so "443,,80" and " 443, 80 " need no cleanup.
		if ps := strings.FieldsFunc(o.netPorts, func(r rune) bool {
			return r == ',' || unicode.IsSpace(r)
		}); len(ps) > 0 {
			a.add("--setenv", llEnvPorts, strings.Join(ps, "\n"))
		}
		// fd 3 is the --args file; the socketpair end the inner stage sends its
		// seccomp listener back on is the next one. Named through the same
		// --setenv channel as the allowlists so --dry-run prints it.
		if o.elevate {
			a.add("--setenv", elevateFDEnv, strconv.Itoa(elevateSockFD))
		}
		inner = append([]string{selfInJail, landlockExecFlag, "--"}, cmd...)
	} else {
		inner = cmd
	}

	// The jail's own description, bound read-only so the process it describes
	// cannot rewrite it — the same reason ~/.config/azkaban is frozen.
	if !o.noGuidance {
		jp := jailPolicy{
			Version: 1, Home: home, Project: cwd,
			Writable:   presentUnder(home, slices.Concat(rwPaths, uc.rw)),
			ReadOnly:   presentUnder(home, slices.Concat(roPaths, uc.ro, roFreeze)),
			Persisted:  presentUnder(home, uc.persist),
			Masked:     presentUnder(home, slices.Concat(maskPaths, uc.mask)),
			Overlay:    o.overlay,
			Landlock:   o.landlockOn,
			NetIsolate: o.netIsolate,
			NetPorts:   o.netPorts,
			NetHosts:   o.egressHosts,
			EnvNames:   envNames(slices.Concat(envKeep, uc.env)),
		}
		a.add("--ro-bind", tempWith("azkaban-policy-", jp.json()), guidancePolicyPath)
		a.add("--ro-bind", tempWith("azkaban-readme-", guidanceText(jp)), guidanceReadmePath)
		a.add("--ro-bind", tempWithMode("azkaban-hook-", claudeHook, 0o755), guidanceDir+"/claude-hook.sh")
		// The binary itself, so the command the README tells the agent to run
		// is one that certainly exists. Read-only, like everything else here.
		if self, err := os.Executable(); err == nil {
			if resolved, err := filepath.EvalSymlinks(self); err == nil {
				self = resolved
			}
			a.add("--ro-bind", self, guidanceBinPath)
		}
		// A cheap, reliable "am I jailed?" that does not need a file read. Set
		// after --clearenv, like every other --setenv here.
		a.add("--setenv", "AZKABAN_JAIL", "1")
		a.add("--setenv", "AZKABAN_POLICY", guidancePolicyPath)
	}

	full := append(append([]string{bwrapBin}, a...), "--")
	full = append(full, inner...)

	// Recorded here rather than at parse time: this is the point where every
	// list has been merged, every entry that had no source on the host has been
	// skipped, and the Landlock allowlists are final. Anything earlier would
	// record what was asked for rather than what the jail got.
	auditLog.event("policy", map[string]any{
		"ro":      slices.Concat(roPaths, uc.ro),
		"rw":      slices.Concat(rwPaths, uc.rw),
		"persist": uc.persist,
		"mask":    slices.Concat(maskPaths, uc.mask),
		"freeze":  roFreeze,
		// Names only, never values: `env NAME` is how an API key reaches the
		// jail, and the useful half is "this run could see that variable".
		"env_forwarded": envNames(slices.Concat(envKeep, uc.env)),
		"landlock": map[string]any{
			"ro": llRO, "ro_files": llROFiles, "rw": llRW, "rw_files": llRWFiles,
			"ports": o.netPorts,
		},
	})
	auditLog.event("mode", map[string]any{
		"overlay":           o.overlay,
		"persist":           o.persistAll,
		"landlock":          o.landlockOn,
		"rlimits":           o.rlimits,
		"allow_userns":      o.allowUserns,
		"keep_env":          o.keepEnv,
		"no_net":            o.netIsolate,
		"net_ports":         o.netPorts,
		"display":           o.display,
		"ssh_agent":         o.sshAgent,
		"ssh_agent_raw":     o.sshAgentRaw,
		"ssh_agent_confirm": o.sshAgentConfirm,
		"gpu":               o.gpu,
		"elevate":           o.elevate,
		"mem_max":           o.memMax,
		"socket":            o.socketKind,
		"socket_raw":        o.rawSock,
		"bwrap_command":     shquote(full),
	})

	if o.dry {
		fmt.Println(shquote(full))
		return
	}

	// Hand the OPTIONS to bwrap on a file descriptor instead of argv.
	// /proc/1/cmdline was otherwise readable from INSIDE the jail and disclosed
	// every bind and the whole landlock allowlist — not an escape, but a free map
	// of what is writable. It also removes any exposure to the ~128 KiB
	// single-argument limit once a user config adds many binds.
	//
	// Note --args carries OPTIONS ONLY: bwrap still needs "-- COMMAND" on the real
	// command line. That leaves just the program being run visible, which the
	// process knows anyway.
	argsFile, err := os.CreateTemp("/tmp", "azkaban-args-")
	if err != nil {
		fatal(1, "args file: "+err.Error())
	}
	tempTrack(argsFile.Name())
	if _, err := argsFile.WriteString(strings.Join(a, "\x00")); err != nil {
		fatal(1, "args file: "+err.Error())
	}
	if _, err := argsFile.Seek(0, 0); err != nil {
		fatal(1, "args file: "+err.Error())
	}
	defer argsFile.Close()

	// Resource caps, inherited across exec by bwrap and everything under it.
	// Applied here rather than in the landlock stage so they hold under
	// --no-landlock too. Must come after our own temp files are written.
	if o.rlimits {
		applyRlimits()
	}

	c := exec.Command(full[0], append([]string{"--args", "3", "--"}, inner...)...)
	c.ExtraFiles = []*os.File{argsFile} // becomes fd 3 in bwrap
	c.Stdin, c.Stdout, c.Stderr = os.Stdin, os.Stdout, os.Stderr
	if o.memMax != "" {
		if fd := setupCgroup(o.memMax, maxProcs); fd != nil {
			defer fd.Close()
			c.SysProcAttr = &syscall.SysProcAttr{UseCgroupFD: true, CgroupFD: int(fd.Fd())}
		}
	}

	// The elevation supervisor, if it was asked for. The socketpair is created
	// here so the child end can be inherited; the parent end stays in this
	// process, which is the trusted half for the whole run.
	var supervisor *elevator
	var supSock, jailSock *os.File
	if o.elevate {
		pair, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_STREAM, 0)
		if err != nil {
			fatal(1, "--elevate: socketpair: "+err.Error())
		}
		supSock = os.NewFile(uintptr(pair[0]), "azkaban-elevate")
		jailSock = os.NewFile(uintptr(pair[1]), "azkaban-elevate-jail")
		c.ExtraFiles = append(c.ExtraFiles, jailSock) // fd 4 in bwrap
		defer supSock.Close()
	}

	if err := c.Start(); err != nil {
		fatal(1, err.Error())
	}
	if o.elevate {
		// Dropped as soon as the child has it. Holding a second copy would mean
		// the read below never sees EOF, so a bwrap that did not pass the
		// descriptor through would hang the run instead of degrading it.
		jailSock.Close()
		// Blocks until the inner stage has installed its filter. If the listener
		// never arrives the run continues WITHOUT elevation rather than dying
		// mid-session: the jail is already up and Landlock is already on, so the
		// worst case is the behaviour azkaban had before this flag existed.
		listener, err := recvListener(int(supSock.Fd()))
		if err != nil {
			fmt.Fprintln(os.Stderr, "azkaban: --elevate: no supervisor for this run ("+err.Error()+")")
		} else {
			supervisor = newElevator(listener, slices.Concat(llRO, llRW, llROFiles, llRWFiles),
				newTerminalApprover())
			supervisor.audit = auditLog
			go supervisor.serve()
		}
	}
	runErr := c.Wait()
	if agentProxy != nil {
		agentProxy.close()
		auditLog.event("ssh_agent", agentProxy.stats())
	}
	if supervisor != nil {
		// Closed only now: the kernel turns every trapped syscall into ENOSYS
		// once the last listener is gone, so an early close would break the jail
		// rather than merely stop supervising it.
		supervisor.close()
		auditLog.event("elevation_summary", supervisor.stats())
	}
	// Taken before anything else, and on BOTH exit paths. A jail that exits
	// non-zero is exactly the one that destroyed something — the incident in
	// docs/design.md exited non-zero and had already deleted five months of
	// data. Snapshotting only on success would miss every case that matters.
	finishRollback(rbSession)
	if runErr != nil {
		if ee, ok := runErr.(*exec.ExitError); ok {
			// os.Exit runs no defers, so the record has to be closed by hand
			// here — an unclosed log is one missing its exit line, which is the
			// line that says whether the run finished.
			auditLog.close(ee.ExitCode())
			tempCleanup()
			os.Exit(ee.ExitCode())
		}
		fatal(1, runErr.Error())
	}
}

// finishRollback takes the closing snapshot and reports what changed.
func finishRollback(s *rollbackSession) {
	if s == nil {
		return
	}
	after, err := takeSnapshot(s.Before.Roots, rollbackStore())
	if err != nil {
		fmt.Fprintln(os.Stderr, "azkaban: rollback: closing snapshot failed ("+err.Error()+
			"); the run is recorded but not reviewable")
		return
	}
	s.After, s.End = after, time.Now().UTC()
	if err := s.save(); err != nil {
		fmt.Fprintln(os.Stderr, "azkaban: rollback: cannot save the session ("+err.Error()+")")
		return
	}
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
	auditLog.event("rollback", map[string]any{
		"session": s.ID, "deleted": deleted, "modified": modified, "changes": len(changes),
	})
	if deleted == 0 && modified == 0 {
		fmt.Fprintf(os.Stderr, "azkaban: rollback: %s — nothing was deleted or modified\n", s.ID)
		return
	}
	// Loud, and with the command to run. This is the moment someone needs it.
	fmt.Fprintf(os.Stderr,
		"azkaban: rollback: %s — %d deleted, %d modified.\n  Review: azkaban rollback show %s\n",
		s.ID, deleted, modified, s.ID)
}

// --------------------------------------------------------------------------- //
// Helpers.
// --------------------------------------------------------------------------- //

// writeHosts - Copies /etc/hosts and makes sure the jail's own hostname
// resolves, since --unshare-uts + --hostname would otherwise leave it
// unresolvable.
func writeHosts() string {
	data, _ := os.ReadFile("/etc/hosts")
	out := string(data)
	if !strings.Contains(out, " "+jailHostname) && !strings.Contains(out, "\t"+jailHostname) {
		out += "\n127.0.0.1 " + jailHostname
	}
	return tempWith("azkaban-hosts-", out)
}

// writeResolv - Copies the REAL resolv.conf. /run is an empty tmpfs inside the
// jail, which breaks the usual /etc/resolv.conf -> /run/.../stub-resolv.conf
// symlink, so a concrete copy has to be re-provided.
func writeResolv() string {
	real, err := filepath.EvalSymlinks("/etc/resolv.conf")
	if err != nil {
		real = "/etc/resolv.conf"
	}
	data, _ := os.ReadFile(real)
	return tempWith("azkaban-resolv-", string(data))
}

// warnTIOCSTI - Flags the terminal-injection vector when the kernel permits it.
// Kernels >= 6.2 gate TIOCSTI behind dev.tty.legacy_tiocsti (default 0); on
// older kernels the knob is absent and the ioctl always works.
func warnTIOCSTI() {
	b, err := os.ReadFile("/proc/sys/dev/tty/legacy_tiocsti")
	if err == nil && strings.TrimSpace(string(b)) == "0" {
		return
	}
	if fi, err := os.Stdin.Stat(); err != nil || fi.Mode()&os.ModeCharDevice == 0 {
		return // not on a terminal, nothing to inject into
	}
	auditLog.degraded("tiocsti-permissive", "this kernel allows TIOCSTI; the jail shares your terminal and can inject commands your shell runs after it exits. Close it host-wide with: sysctl -w dev.tty.legacy_tiocsti=0")
}

// Resource caps. The default overlay puts writes in a tmpfs, i.e. in RAM, which
// turns a runaway write from "fills the disk" into "exhausts memory and the OOM
// killer starts shooting". A confused agent in a write loop is precisely the
// threat this tool exists for, so cap what one process can produce.
//
// KNOWN LIMITATION: RLIMIT_FSIZE is per-FILE. A loop creating many small files
// still fills the overlay. bwrap's --size applies only to --tmpfs, not
// --tmp-overlay, so there is no clean total cap; this raises the bar, it does
// not close the hole. --persist avoids it entirely by writing to real disk.
const (
	maxFileSize = 4 << 30 // 4 GiB — big enough for build artifacts and images
	maxProcs    = 4096    // forkbomb guard; per-UID, so keep it generous
	maxFiles    = 8192    // fd exhaustion, incl. flooding the docker proxy
)

// applyRlimits - Sets the per-process caps above on this process, so bwrap and
// everything it spawns inherit them. An existing hard limit that is already
// lower wins: raising it would be a privilege the caller did not ask for.
func applyRlimits() {
	for _, l := range []struct {
		res  int
		cur  uint64
		name string
	}{
		{unix.RLIMIT_FSIZE, maxFileSize, "RLIMIT_FSIZE"},
		{unix.RLIMIT_NPROC, maxProcs, "RLIMIT_NPROC"},
		{unix.RLIMIT_CORE, 0, "RLIMIT_CORE"}, // core dumps would fill the overlay
		{unix.RLIMIT_NOFILE, maxFiles, "RLIMIT_NOFILE"},
	} {
		var old unix.Rlimit
		if unix.Getrlimit(l.res, &old) == nil && old.Max != 0 && old.Max < l.cur {
			continue // an existing lower hard limit is already stricter; leave it
		}
		rl := unix.Rlimit{Cur: l.cur, Max: l.cur}
		if err := unix.Setrlimit(l.res, &rl); err != nil {
			fmt.Fprintln(os.Stderr, "azkaban: warning: could not set "+l.name+": "+err.Error())
		}
	}
}

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
			auditLog.degraded("cgroup-swap", "could not disable swap for the cgroup; --mem-max will page out rather than refuse.")
		}
	}
	if pidsMax > 0 {
		os.WriteFile(filepath.Join(dir, "pids.max"), []byte(strconv.Itoa(pidsMax)), 0o644)
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
	out, _ := exec.Command(bwrapBin, "--help").CombinedOutput()
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
		os.RemoveAll(p)
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
		signal.Reset(s.(syscall.Signal))
		syscall.Kill(os.Getpid(), s.(syscall.Signal))
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
	f.WriteString(content)
	f.Close()
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
// KNOWN ESCAPE VECTORS (present by design):
//   1. container socket -> now OPT-IN (--bind-docker/--bind-podman); nothing is bound by
//      default. When bound, a filtering proxy (dockerproxy.go) allowlists API
//      endpoints and rejects host binds outside cwd, --privileged, --device,
//      --cap-add, host net/pid/ipc/userns. --unfiltered-container-socket restores the unfiltered
//      socket, where `docker run -v /:/h` reaches any host path as your user.
//      The proxy is NOT an authorization boundary for the rest of the API: the
//      jail can still start, exec into and DELETE your pre-existing containers,
//      images and volumes. containerd/nerdctl are not offered at all (gRPC).
//   2. rw ~/.claude (+hooks) -> plant code that runs on the host on the next
//      non-jailed invocation. Mitigated by the default tmp-overlay (writes are
//      discarded), but --persist re-opens it. ~/.config/azkaban and
//      ~/.config/containers are frozen read-only in both modes.
//   3. --display binds X11 + the whole XDG runtime dir -> keylog/inject into the
//      host GUI, launch host processes via dbus, and SIGN WITH YOUR SSH KEYS via
//      the ssh-agent socket living in that dir (hiding ~/.ssh does not help).
//      WORSE: a ROOTLESS docker/podman socket also lives in $XDG_RUNTIME_DIR, so
//      --display re-exposes the container socket RAW, bypassing the --bind-docker
//      opt-in and its filtering proxy entirely. The fix is to stop binding the
//      directory wholesale and allowlist only what display needs; until then,
//      do not combine --display with a rootless container daemon.
//   4. no net namespace: full host LAN + localhost service access. --net-ports
//      narrows this to a port list at the kernel, and `net <host>` narrows it
//      further to a host allowlist behind a CONNECT proxy — but neither closes
//      UDP, so DNS remains a usable covert channel out of the jail, and a
//      client speaking raw TCP to the proxy port is bounded by the port number
//      and nothing else. Egress filtering here is a guardrail, not a boundary.
//   5. TIOCSTI terminal injection: the jail always shares the controlling
//      terminal, and azkaban offers no mitigation of its own — detaching the
//      session closes the vector but costs job control on every run, including
//      the kernels where it is already shut. Closed by default on kernels >= 6.2
//      (dev.tty.legacy_tiocsti=0); azkaban warns and names the sysctl otherwise.
//   6. --keep-env re-inherits every host secret in your shell environment
//      (API keys, SSH_AUTH_SOCK, cloud creds). The default clears them.
//   7. --persist makes $HOME allowlist writes real again, so a destructive tool
//      can delete ~/.claude, ~/.cache, ~/.local/share for good. The default
//      tmp-overlay confines that damage to a tmpfs that dies with the jail.
//      Note the PROJECT dir is always really writable — that is the point of it.
//   8. --ro/--rw widen the allowlist for one run and un-mask any credential
//      store they name. No new vector — a pasted `--rw ~` is just an easier way
//      to reach 2 and 7 than editing the config. bindSafe still refuses / and $HOME.
//   9. persist/--persist-path is 7 scoped to one path: that path is really
//      writable and really deletable, everything else stays overlaid. A file is
//      a small target; `persist .claude` is 2 and 7 for that whole directory,
//      which is the point of naming the file instead. bindSafe still applies.
//  10. --ssh-agent is 3's ssh-agent half, deliberately and alone: the jail can
//      sign with your loaded keys and so push, pull and log in as you anywhere
//      they are authorized, for the life of the jail. It is strictly narrower
//      than the alternative it exists to prevent (`ro ~/.ssh`, which hands over
//      the key itself, permanently) and than --display, which grants the same
//      oracle plus X11 and dbus. NARROWED since: the jail now reaches a
//      filtering proxy (sshagentproxy.go) that forwards only "list keys" and
//      "sign this", so add/remove/lock are gone and --ssh-agent-confirm is the
//      in-jail equivalent of `ssh-add -c` this entry used to say did not exist.
//      What remains is the signature itself, which is the whole point of the
//      flag and cannot be filtered away. --ssh-agent-raw restores the old,
//      unfiltered socket.
//  11. --elevate lets a human hand the jail a read-only descriptor for a path
//      outside the allowlist, one path at a time and only while a terminal is
//      there to answer. It is bounded by your own filesystem permissions and
//      by Landlock underneath it — the supervisor can only ADD a read it could
//      perform anyway, never remove a denial the floor makes. The real vector
//      is the human: a prompt storm is designed to be answered "no", and the
//      rate limit exists because a tool that asks a thousand times is trying
//      to be approved by fatigue. Writes are never elevated, so nothing here
//      reaches vectors 2, 7 or 9.
//  12. --unix-socket/--unix-socket-dir bind a named socket into the jail, which
//      is whatever the daemon on the other end lets your user do. It replaces
//      the wider grant people reached for instead (`--rw /tmp`), and connect
//      and bind are NOT distinguished — Landlock has no socket-path right, so
//      a grant lets the jail bind a name as well as connect to one.
// --------------------------------------------------------------------------- //
