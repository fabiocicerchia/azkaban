package main

import (
	"errors"
	"flag"
	"io"
	"os"
)

// Flag parsing and the shape of a jail request.

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
		fatal(2,
			"--unfiltered-container-socket says how to bind the socket, not which one: add --bind-docker or --bind-podman")
	}

	cmd = fs.Args()
	if len(cmd) == 0 {
		//nolint:forbidigo // the caller's session is the input here, read at the
		// point the decision is made; azkaban re-execs inside the jail, where a
		// startup snapshot of the outer environment would be the wrong answer
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
