package main

// Behavioural tests for the jail itself. Every test here starts a real bwrap +
// Landlock sandbox against the ephemeral $HOME from harness_test.go.
//
// Naming convention:
//   Test<Area>_<Behaviour>      a guarantee azkaban makes; a failure is a bug
//   TestKnownGap_<Behaviour>    a documented weakness, asserted as it is TODAY
//                               so that fixing it fails the test and forces the
//                               assertion (and the docs) to be updated.

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// --------------------------------------------------------------------------- //
// The tripwire itself. If this breaks, a destructive test could be pointed at a
// real home — which is exactly how five months of data was lost once already.
// --------------------------------------------------------------------------- //

func TestGuardRejectsUnsafeHomes(t *testing.T) {
	const real = "/home/alice"
	for _, c := range []struct {
		name, fake, real string
		wantSafe         bool
	}{
		{"ephemeral", "/var/tmp/azkaban-test-1/home", real, true},
		{"is the real home", real, real, false},
		{"inside the real home", "/home/alice/tmp/fake", real, false},
		{"ancestor of the real home", "/home", real, false},
		{"root", "/", real, false},
		{"outside /var/tmp", "/srv/scratch/home", real, false},
		{"trailing slash still the real home", "/home/alice/", real, false},
		{"real home unset", "/var/tmp/azkaban-test-1/home", "", false},
		{"real home is /", "/var/tmp/azkaban-test-1/home", "/", false},
	} {
		got := guardReason(c.fake, c.real) == ""
		if got != c.wantSafe {
			t.Errorf("%s: guardReason(%q,%q) safe=%v, want %v (reason=%q)",
				c.name, c.fake, c.real, got, c.wantSafe, guardReason(c.fake, c.real))
		}
	}
}

// --------------------------------------------------------------------------- //
// Visibility: what the jailed process can see at all.
// --------------------------------------------------------------------------- //

func TestVisibility_SecretsAreHidden(t *testing.T) {
	e := newEnv(t)
	r := e.run(t, nil, ""+
		probe("ssh", `[ -e "$HOME/.ssh" ]`)+
		probe("aws", `[ -e "$HOME/.aws" ]`)+
		probe("gnupg", `[ -e "$HOME/.gnupg" ]`)+
		probe("documents", `[ -e "$HOME/Documents" ]`)+
		probe("sibling", `[ -e "$HOME/sibling-project" ]`))

	for _, label := range []string{"aws", "documents", "gnupg", "sibling", "ssh"} {
		r.assert(t, label, false)
	}
}

// The secrets must not merely be absent — their content must never be readable
// through any path, including a symlink planted in the writable project dir.
func TestVisibility_SecretsUnreadableViaSymlink(t *testing.T) {
	e := newEnv(t)
	if err := os.Symlink(e.path(".ssh/id_rsa"), filepath.Join(e.proj, "link")); err != nil {
		t.Fatal(err)
	}
	r := e.run(t, nil, `cat ./link 2>/dev/null | head -c 20; echo "[end]"`)
	if strings.Contains(r.stdout, "PRIVATE-KEY") {
		t.Errorf("private key leaked through a symlink in the project dir:\n%s", r.stdout)
	}
}

func TestVisibility_AllowlistedPathsArePresent(t *testing.T) {
	e := newEnv(t)
	r := e.run(t, nil, ""+
		probe("gitconfig", `[ -r "$HOME/.gitconfig" ]`)+
		probe("cache", `[ -d "$HOME/.cache" ]`)+
		probe("config", `[ -d "$HOME/.config" ]`)+
		probe("claude", `[ -d "$HOME/.claude" ]`)+
		probe("project", `[ -r ./src.txt ]`))

	for _, label := range []string{"cache", "claude", "config", "gitconfig", "project"} {
		r.assert(t, label, true)
	}
}

// ssh fatals on any Include'd config file owned by neither root nor the caller.
// bwrap maps ONE uid, so every root-owned /etc/ssh/ssh_config.d drop-in reads as
// nobody inside the jail and ssh dies before opening a socket — `git push` with
// it. Guards the re-served user-owned copies.
func TestVisibility_SSHConfigDropInsAreUsable(t *testing.T) {
	if drops, _ := filepath.Glob("/etc/ssh/ssh_config.d/*.conf"); len(drops) == 0 {
		t.Skip("no /etc/ssh/ssh_config.d drop-ins on this host")
	}
	if _, err := os.Stat("/usr/bin/ssh"); err != nil {
		t.Skip("ssh not installed")
	}
	e := newEnv(t)
	// -G only parses the config and prints the result; it opens no connection.
	r := e.run(t, nil, probe("sshconf", `ssh -G example.com >/dev/null 2>&1`))
	r.assert(t, "sshconf", true)
}

// --------------------------------------------------------------------------- //
// Write confinement.
// --------------------------------------------------------------------------- //

func TestWrite_OnlyIntendedPathsAreWritable(t *testing.T) {
	e := newEnv(t)
	r := e.run(t, nil, ""+
		probe("etc", `echo x > /etc/azkaban-probe 2>/dev/null`)+
		probe("usr", `echo x > /usr/azkaban-probe 2>/dev/null`)+
		probe("homeroot", `echo x > "$HOME/azkaban-probe" 2>/dev/null`)+
		probe("run", `echo x > /run/azkaban-probe 2>/dev/null`)+
		probe("dev", `echo x > /dev/azkaban-probe 2>/dev/null`)+
		probe("azkabancfg", `echo x > "$HOME/.config/azkaban/config" 2>/dev/null`)+
		// these must succeed
		probe("project", `echo x > ./probe 2>/dev/null`)+
		probe("tmp", `echo x > /tmp/probe 2>/dev/null`)+
		probe("devnull", `echo x > /dev/null 2>/dev/null`))

	for _, label := range []string{"azkabancfg", "dev", "etc", "homeroot", "run", "usr"} {
		r.assert(t, label, false)
	}
	for _, label := range []string{"devnull", "project", "tmp"} {
		r.assert(t, label, true)
	}
}

// Landlock must be strictly tighter than the mount layer, otherwise the whole
// second stage is ceremony. /run is mounted as a writable tmpfs, so with
// Landlock off it is writable; with Landlock on it must not be.
func TestWrite_LandlockIsTighterThanMounts(t *testing.T) {
	e := newEnv(t)
	off := e.run(t, []string{"--no-landlock"}, probe("run", `echo x > /run/p 2>/dev/null`))
	on := e.run(t, nil, probe("run", `echo x > /run/p 2>/dev/null`))

	off.assert(t, "run", true) // mount layer alone permits it
	on.assert(t, "run", false) // Landlock is what actually denies it
}

// Landlock denies link/rename ACROSS directories unless "refer" is granted, and
// reports it as EXDEV — which is how `npm install` used to die on a cache miss.
// Refer is granted on the writable set only, and the kernel demands it on both
// ends, so the crossing must still stop at the edge of that set.
func TestWrite_CrossDirectoryLinkAndRename(t *testing.T) {
	e := newEnv(t)
	r := e.run(t, nil, ""+
		// npm's cacache: hardlink a temp file into a sibling directory.
		probe("link", `mkdir -p "$HOME/.cache/a" "$HOME/.cache/b" && : > "$HOME/.cache/a/f" && ln "$HOME/.cache/a/f" "$HOME/.cache/b/f" 2>/dev/null`)+
		// Crossing between two separately allowed trees is still inside the set.
		probe("rename", `: > ./mv-probe && mv ./mv-probe /tmp/mv-probe 2>/dev/null`)+
		// Read-only destination: refer on one end is not enough.
		probe("escape", `: > ./esc-probe && mv ./esc-probe /etc/esc-probe 2>/dev/null`))

	r.assert(t, "link", true)
	r.assert(t, "rename", true)
	r.assert(t, "escape", false)
}

// --------------------------------------------------------------------------- //
// Destruction. The reason this file exists.
// --------------------------------------------------------------------------- //

func TestDestruction_HiddenDataSurvivesRecursiveDelete(t *testing.T) {
	e := newEnv(t)
	e.run(t, nil, `rm -rf "$HOME"/.ssh "$HOME"/.aws "$HOME"/.gnupg "$HOME"/Documents "$HOME"/sibling-project 2>/dev/null; echo done`)

	e.mustContain(t, ".ssh/id_rsa", decoys[".ssh/id_rsa"])
	e.mustContain(t, ".aws/credentials", decoys[".aws/credentials"])
	e.mustContain(t, ".gnupg/secring.gpg", decoys[".gnupg/secring.gpg"])
	e.mustContain(t, "Documents/taxes.txt", decoys["Documents/taxes.txt"])
	e.mustContain(t, "sibling-project/main.go", decoys["sibling-project/main.go"])
}

func TestDestruction_SystemFilesSurvive(t *testing.T) {
	e := newEnv(t)
	before, err := os.ReadFile("/etc/hostname")
	if err != nil {
		t.Skip("no /etc/hostname to compare")
	}
	e.run(t, nil, `rm -rf /etc/hostname /etc/ssl 2>/dev/null; echo done`)

	after, err := os.ReadFile("/etc/hostname")
	if err != nil || string(after) != string(before) {
		t.Fatalf("/etc/hostname was modified or destroyed (err=%v)", err)
	}
}

// THE fix for the data loss. By default every writable $HOME entry is an overlay
// over a throwaway tmpfs, so a tool can delete its entire contents — successfully,
// as far as it can tell — and the host copy is untouched.
func TestOverlay_DestructionIsDiscardedByDefault(t *testing.T) {
	e := newEnv(t)
	if !bwrapHas("--tmp-overlay") {
		t.Skip("this bwrap has no --tmp-overlay")
	}
	r := e.run(t, nil, `rm -rf "$HOME"/.claude/* "$HOME"/.cache/* "$HOME"/.local/share/* 2>/dev/null;`+
		probe("looks_deleted", `[ ! -e "$HOME/.claude/settings.json" ]`))

	// Inside the jail the deletion appears to have worked…
	r.assert(t, "looks_deleted", true)
	// …and on the host nothing was lost.
	e.mustContain(t, ".claude/settings.json", decoys[".claude/settings.json"])
	e.mustContain(t, ".claude/projects/p1/s.jsonl", decoys[".claude/projects/p1/s.jsonl"])
	e.mustContain(t, ".cache/tool/blob", decoys[".cache/tool/blob"])
	e.mustContain(t, ".local/share/thing/data", decoys[".local/share/thing/data"])
}

// `rm -rf ~` is the shape the real accident took. Everything survives now.
func TestOverlay_RmRfHomeLosesNothing(t *testing.T) {
	e := newEnv(t)
	if !bwrapHas("--tmp-overlay") {
		t.Skip("this bwrap has no --tmp-overlay")
	}
	e.run(t, nil, `rm -rf "$HOME" 2>/dev/null; echo done`)

	for rel, want := range decoys {
		if strings.HasPrefix(rel, "proj/") {
			continue // the project dir is deliberately real; see below
		}
		e.mustContain(t, rel, want)
	}
}

// Writes still WORK inside the jail — an overlay that broke tooling would just
// get switched off. They are simply not durable.
func TestOverlay_WritesSucceedButDoNotPersist(t *testing.T) {
	e := newEnv(t)
	if !bwrapHas("--tmp-overlay") {
		t.Skip("this bwrap has no --tmp-overlay")
	}
	r := e.run(t, nil, `echo new > "$HOME/.claude/fresh.txt" && echo "wrote:ok"; `+
		`echo edited > "$HOME/.claude/settings.json" && echo "edited:ok"; `+
		probe("readback", `grep -q edited "$HOME/.claude/settings.json"`))

	if !r.has("wrote:ok") || !r.has("edited:ok") {
		t.Errorf("writes failed inside the overlay; tooling would break:\n%s\n%s", r.stdout, r.stderr)
	}
	r.assert(t, "readback", true)

	// Nothing reached the host.
	if _, err := os.Stat(e.path(".claude/fresh.txt")); err == nil {
		t.Error("a file created inside the jail persisted to the host")
	}
	e.mustContain(t, ".claude/settings.json", decoys[".claude/settings.json"])
}

// The project directory is NEVER overlaid — it is the workspace, and work has to
// survive. This is the one place destruction is possible by design (git is the
// backstop, which is why the docs say to keep the project under version control).
func TestOverlay_ProjectDirIsReallyWritable(t *testing.T) {
	e := newEnv(t)
	e.run(t, nil, `echo persisted > ./out.txt; rm -f ./src.txt`)

	if b, err := os.ReadFile(filepath.Join(e.proj, "out.txt")); err != nil || string(b) != "persisted\n" {
		t.Errorf("project writes must persist: %v %q", err, b)
	}
	if _, err := os.Stat(filepath.Join(e.proj, "src.txt")); err == nil {
		t.Error("project deletes must take effect (the workspace is genuinely writable)")
	}
}

// Per-path persistence: the login-token case. One named file survives, and the
// blast radius of --persist (every allowlist dir really destroyable) does not
// come with it.
//
// The ordering is the whole trick and the reason this is a test rather than an
// assumption: a nested bind emitted BEFORE its parent's --tmp-overlay is simply
// covered by it and does nothing — silently, because the overlay's lower layer
// still serves the old contents, so reads look fine right up until the write is
// lost. That is the shape of the `ro .claude/.credentials.json` bug this
// replaces.
func TestPersistPath_OneFileSurvivesTheOverlay(t *testing.T) {
	e := newEnv(t)
	if !bwrapHas("--tmp-overlay") {
		t.Skip("this bwrap has no --tmp-overlay")
	}
	tok := e.path(".claude/.credentials.json")
	os.WriteFile(tok, []byte(`{"token":"old"}`), 0o600)

	r := e.run(t, []string{"--persist-path", ".claude/.credentials.json"},
		`echo '{"token":"new"}' > "$HOME/.claude/.credentials.json" && echo "wrote:ok"; `+
			// Atomic-save shape: many CLIs write a temp file and rename over the
			// target. rename(2) onto a bind MOUNTPOINT fails with EBUSY, so a tool
			// that saves this way needs the directory persisted, not the file.
			probe("rename", `sh -c 'echo x > "$HOME/.claude/.tmp" && mv "$HOME/.claude/.tmp" "$HOME/.claude/.credentials.json"' 2>/dev/null`)+
			// Everything else in the same directory is still throwaway.
			`echo edited > "$HOME/.claude/settings.json"`)

	if !r.has("wrote:ok") {
		t.Fatalf("persisted file was not writable inside the jail:\n%s\n%s", r.stdout, r.stderr)
	}
	if b, _ := os.ReadFile(tok); !strings.Contains(string(b), "new") {
		t.Errorf("persist-path did not reach the host: %q", b)
	}
	e.mustContain(t, ".claude/settings.json", decoys[".claude/settings.json"])
}

// A persist line naming a path that does not exist on the host cannot be bound.
// It must say so: silence here reproduces the exact failure the feature fixes.
func TestPersistPath_MissingSourceWarns(t *testing.T) {
	e := newEnv(t)
	r := e.run(t, []string{"--persist-path", ".claude/nope.json"}, `echo ran`)
	if !strings.Contains(r.stderr, "nope.json") {
		t.Errorf("a persist path with no host source must warn, got stderr:\n%s", r.stderr)
	}
}

// persist is also an un-mask, same as ro/rw — otherwise the mask loop (bound
// last, so it wins) would blank out the very credential you asked to keep.
func TestPersistPath_UnmasksCredentialStore(t *testing.T) {
	e := newEnv(t)
	p := e.path(".config/gh/hosts.yml")
	os.MkdirAll(filepath.Dir(p), 0o700)
	os.WriteFile(p, []byte("oauth_token: NEEDED-BY-GH"), 0o600)

	r := e.run(t, []string{"--persist-path", ".config/gh"}, `cat "$HOME/.config/gh/hosts.yml" 2>/dev/null; echo "[end]"`)
	if !strings.Contains(r.stdout, "NEEDED-BY-GH") {
		t.Errorf("persist did not un-mask the credential store:\n%s", r.stdout)
	}
}

// --persist restores real writes — and with them the original trap, documented
// here so the trade-off is explicit rather than discovered the hard way.
//
// `rm -rf <dir>` deletes a directory's CONTENTS first, then removes the directory
// itself. When <dir> is a bind mount, only that last step fails (EBUSY), so rm
// exits NON-ZERO while everything inside is already gone. Reading that exit code
// as "the sandbox blocked it" is exactly the mistake that destroyed real data.
func TestPersist_ExitCodeIsNotEvidence(t *testing.T) {
	e := newEnv(t)
	r := e.run(t, []string{"--persist"}, `rm -rf "$HOME/.claude"; echo "rc=$?"; `+
		probe("mountpoint_survived", `[ -d "$HOME/.claude" ]`)+
		probe("contents_survived", `[ -e "$HOME/.claude/settings.json" ]`))

	if strings.Contains(r.stdout, "rc=0") {
		t.Error("expected rm to exit non-zero (EBUSY on the bind-mount root)")
	}
	r.assert(t, "mountpoint_survived", true) // the trap: the dir is still there
	r.assert(t, "contents_survived", false)  // …but everything in it is gone
	e.mustBeGone(t, ".claude/settings.json")
	e.mustBeGone(t, ".claude/projects/p1/s.jsonl")

	// Hidden paths are still hidden even in persist mode.
	e.mustContain(t, ".ssh/id_rsa", decoys[".ssh/id_rsa"])
}

// Even with --persist, the config that steers the NEXT run stays frozen.
func TestPersist_TrustedConfigIsStillFrozen(t *testing.T) {
	e := newEnv(t)
	cfgDir := e.path(".config/azkaban")
	os.MkdirAll(cfgDir, 0o700)
	cfg := filepath.Join(cfgDir, "config")
	os.WriteFile(cfg, []byte("# legitimate\n"), 0o600)

	e.run(t, []string{"--persist"}, `echo "rw /" > "$HOME/.config/azkaban/config" 2>/dev/null; echo done`)

	got, err := os.ReadFile(cfg)
	if err != nil || string(got) != "# legitimate\n" {
		t.Fatalf("trusted config was modified under --persist: %v %q", err, got)
	}
}

// --------------------------------------------------------------------------- //
// Credential masking and resource caps.
// --------------------------------------------------------------------------- //

// ~/.config is bound wholesale because tools need it, and on a normal dev box it
// holds API tokens. The overlay stops those being destroyed; only masking stops
// them being read, and azkaban does not filter network egress.
func TestMask_CredentialsInsideAllowlistedDirsAreHidden(t *testing.T) {
	e := newEnv(t)
	for rel, content := range map[string]string{
		".config/gh/hosts.yml":       "oauth_token: gho_MUST-NOT-BE-READABLE",
		".config/gcloud/creds.db":    "GCLOUD-MUST-NOT-BE-READABLE",
		".config/git/credentials":    "https://u:MUST-NOT-BE-READABLE@github.com",
		".docker/config.json":        `{"auths":{"r.io":{"auth":"MUST-NOT-BE-READABLE"}}}`,
		".local/share/keyrings/l.kr": "KEYRING-MUST-NOT-BE-READABLE",
	} {
		p := e.path(rel)
		os.MkdirAll(filepath.Dir(p), 0o700)
		os.WriteFile(p, []byte(content), 0o600)
	}

	r := e.run(t, nil, `cat "$HOME"/.config/gh/hosts.yml "$HOME"/.config/gcloud/creds.db `+
		`"$HOME"/.config/git/credentials "$HOME"/.docker/config.json `+
		`"$HOME"/.local/share/keyrings/l.kr 2>/dev/null; echo "[end]"`)

	if strings.Contains(r.stdout, "MUST-NOT-BE-READABLE") {
		t.Errorf("a credential leaked through a masked path:\n%s", r.stdout)
	}
	// The host copies must be untouched — masking hides, it does not delete.
	e.mustContain(t, ".config/gh/hosts.yml", "oauth_token: gho_MUST-NOT-BE-READABLE")
}

// Masking has to be opt-out-able or it makes `gh` unusable in the jail. Naming
// the path in the trusted config is the escape hatch; no new syntax.
func TestMask_UserConfigCanOptOut(t *testing.T) {
	e := newEnv(t)
	p := e.path(".config/gh/hosts.yml")
	os.MkdirAll(filepath.Dir(p), 0o700)
	os.WriteFile(p, []byte("oauth_token: NEEDED-BY-GH"), 0o600)

	cfgDir := e.path(".config/azkaban")
	os.MkdirAll(cfgDir, 0o700)
	os.WriteFile(filepath.Join(cfgDir, "config"), []byte("ro .config/gh\n"), 0o600)

	r := e.run(t, nil, `cat "$HOME/.config/gh/hosts.yml" 2>/dev/null; echo "[end]"`)
	if !strings.Contains(r.stdout, "NEEDED-BY-GH") {
		t.Errorf("config opt-out did not un-mask the path:\n%s", r.stdout)
	}
}

// The overlay writes to tmpfs, i.e. RAM. Without a cap, a runaway write stops
// being "fills the disk" and becomes "OOM-kills the host" — a strictly worse
// failure for the accident this tool exists to contain.
func TestRlimit_FileSizeIsCapped(t *testing.T) {
	e := newEnv(t)
	r := e.run(t, nil, `ulimit -f; ulimit -c`)
	lines := strings.Fields(r.stdout)
	if len(lines) < 2 {
		t.Fatalf("could not read ulimits: %q", r.stdout)
	}
	if lines[0] == "unlimited" {
		t.Error("RLIMIT_FSIZE is unlimited; a runaway write can exhaust host RAM via the overlay")
	}
	if lines[1] != "0" {
		t.Errorf("RLIMIT_CORE = %s, want 0 (core dumps would fill the overlay)", lines[1])
	}
}

func TestRlimit_CanBeDisabled(t *testing.T) {
	e := newEnv(t)
	r := e.run(t, []string{"--no-rlimits"}, `ulimit -f`)
	if !strings.Contains(r.stdout, "unlimited") {
		t.Errorf("--no-rlimits did not lift the cap: %q", r.stdout)
	}
}

// A write past the cap must fail rather than consume host memory.
func TestRlimit_OversizedWriteIsRefused(t *testing.T) {
	e := newEnv(t)
	// Set a small limit via the shell, then prove the mechanism bites. Using the
	// real 4 GiB default would mean actually allocating 4 GiB of host RAM.
	r := e.run(t, nil, `ulimit -f 1; dd if=/dev/zero of="$HOME/.cache/big" bs=1M count=4 2>&1 | tail -1; `+
		probe("capped", `[ ! -s "$HOME/.cache/big" ] || [ "$(stat -c%s "$HOME/.cache/big")" -lt 4194304 ]`))
	r.assert(t, "capped", true)
}

// --------------------------------------------------------------------------- //
// ssh-agent passthrough.
// --------------------------------------------------------------------------- //

// The agent socket is a signing oracle for every key you have loaded, so an
// SSH_AUTH_SOCK sitting in the host environment must not ride along on its own.
func TestSSHAgent_NotForwardedByDefault(t *testing.T) {
	e := newEnv(t)
	r := e.runIn(t, e.proj, []string{"--dry-run"}, "", "SSH_AUTH_SOCK=/run/user/0/decoy-agent")
	if strings.Contains(r.stdout, "SSH_AUTH_SOCK") || strings.Contains(r.stdout, "decoy-agent") {
		t.Errorf("default run forwards the agent socket:\n%s", r.stdout)
	}
}

// Opting in binds the socket AND known_hosts — without the latter every push
// dies on "Host key verification failed" and the flag looks broken.
func TestSSHAgent_OptInBindsSocketAndKnownHosts(t *testing.T) {
	e := newEnv(t)
	sock := filepath.Join(e.root, "agent.sock")
	l, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()

	r := e.runIn(t, e.proj, []string{"--ssh-agent", "--dry-run"}, "", "SSH_AUTH_SOCK="+sock)
	for _, want := range []string{sock, "SSH_AUTH_SOCK", "known_hosts"} {
		if !strings.Contains(r.stdout, want) {
			t.Errorf("--ssh-agent did not bind %s:\n%s", want, r.stdout)
		}
	}
	// The keys themselves never cross the boundary — that is the whole trade.
	if strings.Contains(r.stdout, "id_rsa") {
		t.Errorf("--ssh-agent bound private key material:\n%s", r.stdout)
	}
}

// Asking for the agent when there is none must fail loudly, not silently produce
// a jail where every git push fails for a reason nobody can see.
func TestSSHAgent_MissingAgentIsAnError(t *testing.T) {
	e := newEnv(t)
	r := e.runIn(t, e.proj, []string{"--ssh-agent", "--dry-run"}, "", "SSH_AUTH_SOCK=/run/user/0/nope.sock")
	if r.code == 0 {
		t.Errorf("--ssh-agent with a dead socket exited 0:\n%s", r.stdout)
	}
}

// --------------------------------------------------------------------------- //
// Container runtimes.
// --------------------------------------------------------------------------- //

// The socket is the one interface the jail cannot police from inside, so nothing
// is bound unless explicitly requested.
func TestRuntime_NoSocketIsBoundByDefault(t *testing.T) {
	e := newEnv(t)
	r := e.runIn(t, e.proj, []string{"--dry-run"}, "")
	for _, s := range []string{"CONTAINER_HOST", "DOCKER_HOST", "docker.sock", "podman.sock"} {
		if strings.Contains(r.stdout, s) {
			t.Errorf("default run exposes %s:\n%s", s, r.stdout)
		}
	}
}

func TestRuntime_OptInBindsTheSocket(t *testing.T) {
	e := newEnv(t)
	if !exists("/var/run/docker.sock") && !exists("/run/user/"+strconv.Itoa(os.Getuid())+"/docker.sock") {
		t.Skip("no docker socket on this host")
	}
	r := e.runIn(t, e.proj, []string{"--bind-docker", "--dry-run"}, "")
	if !strings.Contains(r.stdout, "docker.sock") || !strings.Contains(r.stdout, "DOCKER_HOST") {
		t.Errorf("--bind-docker did not bind a socket:\n%s", r.stdout)
	}
}

// Asking for a runtime that is not running must fail loudly rather than silently
// continuing without it.
func TestRuntime_MissingSocketIsAnError(t *testing.T) {
	e := newEnv(t)
	if exists("/run/podman/podman.sock") || exists("/run/user/"+strconv.Itoa(os.Getuid())+"/podman/podman.sock") {
		t.Skip("podman is actually running here")
	}
	r := e.run(t, []string{"--bind-podman"}, `echo SHOULD-NOT-RUN`)
	if r.has("SHOULD-NOT-RUN") {
		t.Error("--bind-podman ran the command despite no podman socket")
	}
	if !strings.Contains(r.stderr, "no podman socket") {
		t.Errorf("expected a clear error, got: %q", r.stderr)
	}
}

// --------------------------------------------------------------------------- //
// The trusted config — the escape that mattered most.
// --------------------------------------------------------------------------- //

func TestConfig_JailCannotRewriteItsOwnBindList(t *testing.T) {
	e := newEnv(t)
	cfgDir := e.path(".config/azkaban")
	if err := os.MkdirAll(cfgDir, 0o700); err != nil {
		t.Fatal(err)
	}
	cfg := filepath.Join(cfgDir, "config")
	if err := os.WriteFile(cfg, []byte("# legitimate\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	e.run(t, nil, `echo "rw /" > "$HOME/.config/azkaban/config" 2>/dev/null;`+
		`echo "rw /" >> "$HOME/.config/azkaban/config" 2>/dev/null;`+
		`rm -f "$HOME/.config/azkaban/config" 2>/dev/null; echo done`)

	got, err := os.ReadFile(cfg)
	if err != nil {
		t.Fatalf("the trusted config was deleted from inside the jail: %v", err)
	}
	if string(got) != "# legitimate\n" {
		t.Fatalf("the trusted config was modified from inside the jail: %q", got)
	}
}

func TestConfig_RefusesBindsThatWouldUndoTheJail(t *testing.T) {
	for _, line := range []string{"rw $HOME", "rw $HOMEPARENT", "rw /"} {
		e := newEnv(t)
		body := strings.NewReplacer("$HOMEPARENT", filepath.Dir(e.home), "$HOME", e.home).Replace(line)
		cfgDir := e.path(".config/azkaban")
		os.MkdirAll(cfgDir, 0o700)
		os.WriteFile(filepath.Join(cfgDir, "config"), []byte(body+"\n"), 0o600)

		r := e.run(t, nil, `echo SHOULD-NOT-RUN`)
		if r.has("SHOULD-NOT-RUN") {
			t.Errorf("config %q was accepted; the jail ran anyway", body)
		}
		if !strings.Contains(r.stderr, "refusing") {
			t.Errorf("config %q: expected a refusal on stderr, got %q", body, r.stderr)
		}
	}
}

func TestConfig_LegitimateEntriesStillWork(t *testing.T) {
	e := newEnv(t)
	cfgDir := e.path(".config/azkaban")
	os.MkdirAll(cfgDir, 0o700)
	os.WriteFile(filepath.Join(cfgDir, "config"),
		[]byte("# comment\nro /etc/hostname\nenv MY_TOOL_TOKEN\n"), 0o600)

	r := e.run(t, nil, probe("ro", `[ -r /etc/hostname ]`)+`echo "tok=[$MY_TOOL_TOKEN]"`,
		"MY_TOOL_TOKEN=passed-through")
	r.assert(t, "ro", true)
	if !r.has("tok=[passed-through]") {
		t.Errorf("env passthrough via config failed: %q", r.stdout)
	}
}

// --------------------------------------------------------------------------- //
// Environment.
// --------------------------------------------------------------------------- //

func TestEnv_HostSecretsAreCleared(t *testing.T) {
	e := newEnv(t)
	secrets := []string{
		"ANTHROPIC_API_KEY=sk-must-not-leak",
		"AWS_SECRET_ACCESS_KEY=must-not-leak",
		"GITHUB_TOKEN=ghp-must-not-leak",
		"SSH_AUTH_SOCK=/run/user/1000/keyring/ssh",
	}
	r := e.run(t, nil, `echo "k=[$ANTHROPIC_API_KEY] g=[$GITHUB_TOKEN] a=[$AWS_SECRET_ACCESS_KEY] s=[$SSH_AUTH_SOCK]"`, secrets...)
	if !r.has("k=[] g=[] a=[] s=[]") {
		t.Errorf("host secrets leaked into the jail: %q", r.stdout)
	}

	// …and the allowlist still arrives, or nothing would run.
	r = e.run(t, nil, `echo "home=[${HOME:+set}] path=[${PATH:+set}] term=[${TERM:+set}]"`)
	if !r.has("home=[set] path=[set] term=[set]") {
		t.Errorf("the env allowlist did not arrive: %q", r.stdout)
	}
}

func TestEnv_KeepEnvRestoresInheritance(t *testing.T) {
	e := newEnv(t)
	r := e.run(t, []string{"--keep-env"}, `echo "k=[$ANTHROPIC_API_KEY]"`, "ANTHROPIC_API_KEY=sk-inherited")
	if !r.has("k=[sk-inherited]") {
		t.Errorf("--keep-env did not inherit: %q", r.stdout)
	}
}

func TestEnv_InternalLandlockChannelIsStripped(t *testing.T) {
	e := newEnv(t)
	r := e.run(t, nil, `env | grep -c AZKABAN_LL_ || true`)
	if !strings.Contains(r.stdout, "0") {
		t.Errorf("AZKABAN_LL_* reached the target process: %q", r.stdout)
	}
}

// --------------------------------------------------------------------------- //
// Refusals and misuse.
// --------------------------------------------------------------------------- //

func TestRefusal_CwdContainingHome(t *testing.T) {
	e := newEnv(t)
	for _, cwd := range []string{e.home, filepath.Dir(e.home)} {
		r := e.runIn(t, cwd, nil, `echo SHOULD-NOT-RUN`)
		if r.has("SHOULD-NOT-RUN") {
			t.Errorf("cwd %q was accepted; $HOME would have been writable", cwd)
		}
		if r.code != 2 {
			t.Errorf("cwd %q: exit = %d, want 2", cwd, r.code)
		}
	}
}

func TestRefusal_UnknownFlagAndMissingCommand(t *testing.T) {
	e := newEnv(t)
	r := e.run(t, []string{"--not-a-flag"}, `echo SHOULD-NOT-RUN`)
	if r.code != 2 || r.has("SHOULD-NOT-RUN") {
		t.Errorf("unknown flag was not rejected: code=%d out=%q", r.code, r.stdout)
	}
}

func TestExitCode_IsPropagated(t *testing.T) {
	e := newEnv(t)
	if r := e.run(t, nil, `exit 42`); r.code != 42 {
		t.Errorf("exit code = %d, want 42", r.code)
	}
}

// --------------------------------------------------------------------------- //
// Regressions.
// --------------------------------------------------------------------------- //

// Landlock ABI v5 handles LANDLOCK_ACCESS_FS_IOCTL_DEV but go-landlock's
// RWDirs/RWFiles do not grant it, so device ioctls need an explicit
// .WithIoctlDev(). Without it openpty() returns EACCES and every TUI that spawns
// a child in a pty breaks — while inherited stdio keeps working, which is what
// makes the breakage so easy to miss.
func TestRegression_PtyAllocationWorksUnderLandlock(t *testing.T) {
	e := newEnv(t)
	// Not exec.LookPath: a version-manager shim (pyenv, asdf) resolves into the
	// REAL home, which by design does not exist inside the jail. Use the system
	// interpreter, which lives under /usr and is always bound.
	py := "/usr/bin/python3"
	if _, err := os.Stat(py); err != nil {
		t.Skip("no /usr/bin/python3")
	}
	script := py + ` -c 'import pty,os; m,s=pty.openpty(); os.write(m,b"x"); print("PTY-OK")'`
	r := e.run(t, nil, script)
	if !r.has("PTY-OK") {
		t.Errorf("openpty() failed under Landlock (IoctlDev regression):\n%s\n%s", r.stdout, r.stderr)
	}
}

func TestProcessIsolation_HostProcessesAreInvisible(t *testing.T) {
	e := newEnv(t)
	r := e.run(t, nil, `ls /proc | grep -cE '^[0-9]+$'`)
	hostPids, _ := filepath.Glob("/proc/[0-9]*")
	got := strings.TrimSpace(r.stdout)
	if got == "" {
		t.Fatal("no pid count returned")
	}
	if len(hostPids) < 50 {
		t.Skip("implausibly few host pids to compare against")
	}
	if got > "20" && len(got) >= 2 {
		t.Errorf("jail sees %s pids; expected a handful, not the host's %d", got, len(hostPids))
	}
}

// The host environment must NOT be reachable through pid 1 either, or --clearenv
// would be cosmetic. ptrace_scope normally denies this; assert it holds.
func TestEnv_HostEnvironmentIsNotReadableViaProc1(t *testing.T) {
	e := newEnv(t)
	r := e.run(t, nil, `tr '\0' '\n' < /proc/1/environ 2>/dev/null | grep -c LEAK_CANARY || echo "unreadable"`,
		"LEAK_CANARY=must-not-be-visible")
	if strings.Contains(r.stdout, "1") && !strings.Contains(r.stdout, "unreadable") {
		t.Error("host environment is readable via /proc/1/environ, defeating --clearenv")
	}
}

// --------------------------------------------------------------------------- //
// P0 hardening regressions.
// --------------------------------------------------------------------------- //

// The Landlock allowlist travels as newline-separated env vars, so a path
// CONTAINING a newline injects extra entries. `mkdir $'proj\n/run'` was enough to
// grant Landlock write access to /run — the mount layer still refused, but layer
// 3 was defeated by a directory name.
func TestInjection_NewlineInPathIsRefused(t *testing.T) {
	e := newEnv(t)
	evil := filepath.Join(e.home, "proj\n/run")
	if err := os.MkdirAll(evil, 0o700); err != nil {
		t.Skip("filesystem rejects newlines in names: " + err.Error())
	}
	r := e.runIn(t, evil, nil, `echo x > /run/pwned 2>/dev/null && echo BYPASSED; echo ran`)

	if r.has("BYPASSED") {
		t.Error("newline in cwd injected /run into the Landlock RW list")
	}
	if r.has("ran") {
		t.Error("expected azkaban to refuse the path outright, not merely survive it")
	}
	if !strings.Contains(r.stderr, "newline") {
		t.Errorf("expected a clear refusal naming the newline, got: %q", r.stderr)
	}
}

// Go does not run defers on signal death, and os.Exit skips them too — so every
// failing run used to leave three files in /tmp. 454 had accumulated.
func TestTemp_NoLeakOnAnyExitPath(t *testing.T) {
	e := newEnv(t)
	count := func() int {
		m, _ := filepath.Glob("/tmp/azkaban-*")
		return len(m)
	}
	for _, c := range []struct {
		name   string
		flags  []string
		script string
	}{
		{"success", nil, `true`},
		{"failure", nil, `exit 3`},
		{"dry-run", []string{"--dry-run"}, ""},
	} {
		before := count()
		e.run(t, c.flags, c.script)
		if got := count() - before; got != 0 {
			t.Errorf("%s: leaked %d temp files", c.name, got)
		}
	}
}

// Nested user namespaces are the usual first step of a kernel-exploit chain.
// Blocking them makes it azkaban's guarantee rather than the host's sysctl.
func TestUserns_NestingIsBlockedByDefault(t *testing.T) {
	e := newEnv(t)
	if _, err := os.Stat("/usr/bin/python3"); err != nil {
		t.Skip("no /usr/bin/python3")
	}
	probe := `/usr/bin/python3 -c 'import ctypes;print("NESTED-OK" if ctypes.CDLL("libc.so.6").unshare(0x10000000)==0 else "blocked")'`
	if r := e.run(t, nil, probe); r.has("NESTED-OK") {
		t.Error("a nested user namespace was created despite --disable-userns")
	}
	if r := e.run(t, []string{"--allow-userns"}, probe); !r.has("NESTED-OK") {
		t.Error("--allow-userns did not restore nesting")
	}
}

// $XDG_RUNTIME_DIR holds ssh-agent, gpg-agent, dbus and — on a rootless setup —
// the container socket. Binding it wholesale handed that over raw and bypassed
// the --bind-docker opt-in entirely.
func TestDisplay_BindsNamedSocketsNotTheWholeRuntimeDir(t *testing.T) {
	e := newEnv(t)
	r := e.runIn(t, e.proj, []string{"--display", "--dry-run"}, "")
	rt := "/run/user/" + strconv.Itoa(os.Getuid())
	if strings.Contains(r.stdout, "--bind "+rt+" "+rt) {
		t.Errorf("--display still binds the whole runtime dir:\n%s", r.stdout)
	}
	if !strings.Contains(r.stdout, "--tmpfs "+rt) {
		t.Errorf("--display should mask the runtime dir with a tmpfs first:\n%s", r.stdout)
	}
	for _, leak := range []string{"bus", "docker.sock", "gnupg", "podman.sock", "ssh-agent"} {
		if strings.Contains(r.stdout, rt+"/"+leak) {
			t.Errorf("--display exposes %s from the runtime dir", leak)
		}
	}
}

// --------------------------------------------------------------------------- //
// P1/P2 hardening.
// --------------------------------------------------------------------------- //

// Landlock ABI v4+ restricts TCP connect. RestrictPaths deliberately drops
// network handling, so this only takes effect through Restrict — the reason it
// was inert. Opt-in, because default-denying would break `curl localhost:3000`.
func TestNetPorts_RestrictOutboundTCP(t *testing.T) {
	e := newEnv(t)
	if _, err := os.Stat("/usr/bin/python3"); err != nil {
		t.Skip("no /usr/bin/python3")
	}
	// Something listening on the host loopback that the jail should not reach.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skip("cannot listen on loopback")
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()
	port := ln.Addr().(*net.TCPAddr).Port
	probe := fmt.Sprintf(`/usr/bin/python3 -c '
import socket
s=socket.socket(); s.settimeout(3)
try:
    s.connect(("127.0.0.1",%d)); print("REACHED")
except PermissionError: print("BLOCKED")
except Exception as e: print(type(e).__name__)'`, port)

	if r := e.run(t, nil, probe); !r.has("REACHED") {
		t.Skipf("loopback unreachable even unrestricted (%q); environment cannot show the difference", r.stdout)
	}
	if r := e.run(t, []string{"--net-ports", "443"}, probe); !r.has("BLOCKED") {
		t.Errorf("--net-ports did not block a non-listed port: %q %q", r.stdout, r.stderr)
	}
}

// The overlay writes to tmpfs, i.e. RAM. RLIMIT_FSIZE caps one file and cannot
// bound it; memory.max can, but only with swap disabled for the group — with
// swap on, 256 MiB allocated fine under a 64 MiB cap.
func TestMemMax_CapsTheOverlay(t *testing.T) {
	e := newEnv(t)
	r := e.run(t, []string{"--mem-max", "32M"},
		`dd if=/dev/zero of="$HOME/.cache/blob" bs=1M count=256 2>/dev/null; echo "rc=$?"`)
	if strings.Contains(r.stderr, "cgroup unavailable") {
		t.Skip("no delegated cgroup v2 tree here")
	}
	if r.has("rc=0") {
		t.Error("256MB written into a 32MB-capped overlay; the cap is not enforced")
	}
}

// /proc/1/cmdline used to disclose every bind and the whole Landlock allowlist.
func TestProc_SandboxSpecIsNoLongerInCmdline(t *testing.T) {
	e := newEnv(t)
	// The needles are split so the probe script — which ends up in that very
	// cmdline as the shell's -c argument — does not match itself.
	r := e.run(t, nil, `tr '\0' '\n' < /proc/1/cmdline > /tmp/c; `+
		`a="AZKABAN"; b="_LL"; grep -c "$a$b" /tmp/c || true; `+
		`c="--ro"; d="-bind"; grep -c -- "$c$d" /tmp/c || true`)
	for _, line := range strings.Fields(r.stdout) {
		if line != "0" {
			t.Errorf("sandbox spec still visible in /proc/1/cmdline:\n%s", r.stdout)
			break
		}
	}
}

func TestProc_KernelSymbolsAreMasked(t *testing.T) {
	e := newEnv(t)
	r := e.run(t, nil, `echo "kallsyms=$(wc -c < /proc/kallsyms) modules=$(wc -c < /proc/modules)"`)
	if !r.has("kallsyms=0") || !r.has("modules=0") {
		t.Errorf("kernel symbol/module lists are readable: %q", r.stdout)
	}
}

// A user must be able to blank out a credential path azkaban does not know about.
func TestMask_UserConfigCanAddPaths(t *testing.T) {
	e := newEnv(t)
	p := e.path(".config/mytool/token")
	os.MkdirAll(filepath.Dir(p), 0o700)
	os.WriteFile(p, []byte("CUSTOM-SECRET"), 0o600)

	cfgDir := e.path(".config/azkaban")
	os.MkdirAll(cfgDir, 0o700)
	os.WriteFile(filepath.Join(cfgDir, "config"), []byte("mask .config/mytool/token\n"), 0o600)

	if r := e.run(t, nil, `cat "$HOME/.config/mytool/token" 2>/dev/null; echo "[end]"`); r.has("CUSTOM-SECRET") {
		t.Errorf("mask directive did not hide the path: %q", r.stdout)
	}
	e.mustContain(t, ".config/mytool/token", "CUSTOM-SECRET")
}

// --------------------------------------------------------------------------- //

// --ro/--rw are the config file's "ro"/"rw" lines scoped to a single run: they
// must reach a path the allowlist hides, keep read-only actually read-only, and
// go through the same bindSafe refusal that stops a bind undoing the home tmpfs.
func TestExtraBinds_PerRunFlags(t *testing.T) {
	e := newEnv(t)
	p := e.path("extra")
	os.MkdirAll(p, 0o700)
	os.WriteFile(filepath.Join(p, "f"), []byte("VISIBLE"), 0o600)

	if r := e.run(t, nil, `cat "$HOME/extra/f" 2>/dev/null; echo "[end]"`); r.has("VISIBLE") {
		t.Errorf("~/extra reachable with no flag: %q", r.stdout)
	}
	if r := e.run(t, []string{"--ro", "extra"}, `cat "$HOME/extra/f"`); !r.has("VISIBLE") {
		t.Errorf("--ro did not bind the path: %q %q", r.stdout, r.stderr)
	}
	// Not covered by mustContain below: the default overlay leaves the host copy
	// untouched for a *writable* bind too, so only an in-jail failure proves "ro".
	if r := e.run(t, []string{"--ro", "extra"}, `echo x > "$HOME/extra/f" 2>/dev/null && echo WROTE; echo "[end]"`); r.has("WROTE") {
		t.Error("--ro bind accepted a write")
	}
	e.mustContain(t, "extra/f", "VISIBLE")

	// "." resolves to $HOME itself — the one bind that would re-expose everything.
	if r := e.run(t, []string{"--rw", "."}, "true"); r.code != 2 {
		t.Errorf("--rw $HOME not refused: code=%d %q", r.code, r.stderr)
	}
}

// --unfiltered-container-socket picks the filtering, not the runtime. It used to be evaluated
// before --bind-podman, so `--bind-podman --unfiltered-container-socket` silently bound the DOCKER socket —
// a raw socket for a runtime the caller did not ask for.
func TestRuntime_RawComposesWithPodman(t *testing.T) {
	e := newEnv(t)
	r := e.runIn(t, e.proj, []string{"--bind-podman", "--unfiltered-container-socket", "--dry-run"}, "")
	if strings.Contains(r.stdout, "docker.sock") {
		t.Errorf("--bind-podman --unfiltered-container-socket bound a docker socket:\n%s", r.stdout)
	}
	// No podman on the host is a legitimate outcome; binding docker is not.
	if r.code != 0 && !strings.Contains(r.stderr, "no podman socket found") {
		t.Errorf("unexpected failure: %q", r.stderr)
	}
}

// --unfiltered-container-socket picks the filtering, not the runtime. On its own
// it used to imply docker, so the least explicit flag bound the most dangerous
// socket — rootful and unproxied on a host with no rootless daemon.
func TestRuntime_UnfilteredNeedsARuntime(t *testing.T) {
	e := newEnv(t)
	r := e.runIn(t, e.proj, []string{"--unfiltered-container-socket", "--dry-run"}, "")
	if r.code != 2 {
		t.Errorf("expected exit 2, got %d:\n%s", r.code, r.stdout)
	}
	if strings.Contains(r.stdout, "docker.sock") {
		t.Errorf("bound a socket without being told which runtime:\n%s", r.stdout)
	}
}
