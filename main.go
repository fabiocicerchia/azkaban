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
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"unicode"

	"time"
)

func outer(argv []string) {
	var agentProxy *sshAgentProxy
	o, cmd, done := parseFlags(argv)
	if done {
		return
	}

	home, err := os.UserHomeDir()
	if err != nil {
		fatal(2, "cannot determine $HOME ("+err.Error()+"); every bind below is decided from it")
	}
	cwd, err := os.Getwd()
	if err != nil {
		fatal(2, "cannot determine the working directory ("+err.Error()+"); it is what gets bound read-write")
	}
	// cwd is bound read-write; if it IS $HOME (or an ancestor of it) the whole
	// home becomes writable/deletable inside the jail. Refuse — accidental rm
	// protection is the point. The cwd == "/" case is special-cased because
	// "/"+separator is "//", so the HasPrefix ancestor test never fires for it.
	if cwd == "/" {
		fatal(2, "refusing to run: cwd is / — only a project dir should be writable. cd into the project first.")
	}
	if cwd == home || strings.HasPrefix(home, cwd+string(os.PathSeparator)) {
		fatal(2,
			"refusing to run: cwd ("+cwd+") contains $HOME — only the project dir should be writable. cd into the project "+
				"first.")
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
	//nolint:forbidigo // read once, here, and passed in: the auditor measures
	// the run's duration against this same value
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
	//nolint:errcheck // a literal pattern: Glob only fails on a malformed one
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
		devs, _ := filepath.Glob("/dev/nvidia*") //nolint:errcheck // a literal pattern: Glob only fails on a malformed one
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
		switch realSock {
		case "":
			fatal(1, "no "+o.socketKind+" socket found (looked in "+
				strings.Join(containerSockets[o.socketKind], ", ")+
				"). containerd is not offered: it speaks gRPC, which the filtering proxy cannot inspect.")
		case "/var/run/docker.sock", "/run/podman/podman.sock":
			auditLog.degraded("rootful-container-socket", "no rootless "+o.socketKind+
				"; using ROOTFUL "+realSock+" = host root inside the jail. Set up a rootless daemon to close this.")
		}

		sockForJail := realSock // path bound FROM the host
		switch {
		case o.rawSock:
			auditLog.degraded("unfiltered-container-socket",
				"--unfiltered-container-socket binds the UNFILTERED socket; "+
					"`docker run -v /:/h` can read/write everything your user owns.")
		case !o.dry:
			ps, err := startDockerFilterProxy(realSock, cwd)
			if err != nil {
				fatal(1, "container filter proxy: "+err.Error())
			}
			sockForJail = ps
		default:
			// --dry-run exists to be audited, so do not let it imply the raw
			// socket is what gets bound.
			fmt.Fprintln(os.Stderr,
				"azkaban: note: --dry-run prints the RAW socket as the bind source; a real run substitutes the filtering proxy "+
					"socket there.")
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
		//nolint:forbidigo // the caller's session is the input here, read at the
		// point the decision is made; azkaban re-execs inside the jail, where a
		// startup snapshot of the outer environment would be the wrong answer
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
				//nolint:errcheck // a literal pattern: Glob only fails on a malformed one
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
		auditLog.degraded("no-tmp-overlay",
			"this bwrap has no --tmp-overlay; falling back to real writes. Upgrade bubblewrap (>= 0.9) or pass --persist to "+
				"silence this.")
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
		//nolint:forbidigo // the caller's session is the input here, read at the
		// point the decision is made; azkaban re-execs inside the jail, where a
		// startup snapshot of the outer environment would be the wrong answer
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
		// EvalSymlinks returns "" on failure, and binding "" would produce a
		// jail with no target binary at all. An unresolvable path is still the
		// path LookPath found.
		if resolved, err := filepath.EvalSymlinks(binPath); err == nil {
			binPath = resolved
		}
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
		//nolint:forbidigo // the display the caller is on is what gets forwarded;
		// the three reads below are the same decision
		a.add("--setenv", "DISPLAY", cmp.Or(os.Getenv("DISPLAY"), ":0"))
		//nolint:forbidigo // see above
		if xa := os.Getenv("XAUTHORITY"); xa != "" {
			a.add("--setenv", "XAUTHORITY", xa)
		}
		//nolint:forbidigo // see above
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
		//nolint:forbidigo // stamping when this happened; the record is the
		// only consumer and a jail runs once
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
		// As with the target binary: "" would bind nothing at selfInJail and
		// the landlock stage would have no executable to re-exec.
		if resolved, err := filepath.EvalSymlinks(self); err == nil {
			self = resolved
		}
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
	defer argsFile.Close() //nolint:errcheck // closing on the way out; a failed close has nothing left to report

	// Resource caps, inherited across exec by bwrap and everything under it.
	// Applied here rather than in the landlock stage so they hold under
	// --no-landlock too. Must come after our own temp files are written.
	if o.rlimits {
		applyRlimits()
	}

	// context.Background(), deliberately: azkaban is one process supervising one
	// child, and the only cancellation it has is the signal handler that cleans up
	// and re-raises.
	c := exec.CommandContext(context.Background(), full[0], append([]string{"--args", "3", "--"}, inner...)...)
	c.ExtraFiles = []*os.File{argsFile} // becomes fd 3 in bwrap
	c.Stdin, c.Stdout, c.Stderr = os.Stdin, os.Stdout, os.Stderr
	if o.memMax != "" {
		if fd := setupCgroup(o.memMax, maxProcs); fd != nil {
			defer fd.Close() //nolint:errcheck // closing on the way out; a failed close has nothing left to report
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
		//nolint:errcheck // closing on the way out; a failed close has nothing left to report
		defer supSock.Close()
	}

	if err := c.Start(); err != nil {
		fatal(1, err.Error())
	}
	if o.elevate {
		// Dropped as soon as the child has it. Holding a second copy would mean
		// the read below never sees EOF, so a bwrap that did not pass the
		// descriptor through would hang the run instead of degrading it.
		jailSock.Close() //nolint:errcheck // closing on the way out; a failed close has nothing left to report
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
		var ee *exec.ExitError
		if errors.As(runErr, &ee) {
			// os.Exit runs no defers, so the record has to be closed by hand
			// here — an unclosed log is one missing its exit line, which is the
			// line that says whether the run finished.
			auditLog.close(ee.ExitCode())
			if supSock != nil {
				// Same reason as the log: the deferred close below never runs.
				_ = supSock.Close() //nolint:errcheck // exiting; there is nothing left to tell
			}
			tempCleanup()
			os.Exit(ee.ExitCode()) //nolint:gocritic // the defers above are run by hand for exactly this reason
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
	//nolint:forbidigo // stamping when this happened; the record is the
	// only consumer and a jail runs once
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
