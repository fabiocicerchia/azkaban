package main

import (
	"os"
)

// Config — the whole security model lives in these lists.

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
