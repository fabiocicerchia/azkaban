package main

import (
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"

	"github.com/landlock-lsm/go-landlock/landlock"
)

// Inner role: apply landlock, then exec the target command.

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
	//nolint:forbidigo // this is how the inner stage learns its descriptor:
	// azkaban sets it on the re-exec and reads it back on the other side
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
		syscall.Close(listener) //nolint:errcheck // closing a descriptor this process is finished with
		syscall.Close(sock)     //nolint:errcheck // closing a descriptor this process is finished with
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
