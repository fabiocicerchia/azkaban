# 🏰 azkaban

[![CI](https://github.com/fabiocicerchia/azkaban/actions/workflows/code-quality.yml/badge.svg)](https://github.com/fabiocicerchia/azkaban/actions/workflows/code-quality.yml)
[![Security](https://github.com/fabiocicerchia/azkaban/actions/workflows/security.yml/badge.svg)](https://github.com/fabiocicerchia/azkaban/actions/workflows/security.yml)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/fabiocicerchia/azkaban/badge)](https://securityscorecards.dev/viewer/?uri=github.com/fabiocicerchia/azkaban)
[![CI carbon](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/fabiocicerchia/azkaban/gh-pages/badge.json)](.github/workflows/carbon-badge.yml)

**A jail for AI CLIs.** `azkaban` confines a coding agent (Claude Code, aider,
etc.) to a single project directory using [bubblewrap](https://github.com/containers/bubblewrap)
and [Landlock](https://docs.kernel.org/userspace-api/landlock.html), so a
misbehaving or hallucinating tool cannot read your `~/.ssh`, exfiltrate
credentials, or `rm -rf` your home.

The primary threat is **accidental destruction** — an agent that misreads a path
and deletes the wrong folder — not a determined attacker. Network isolation is
secondary and off by default; an AI CLI that cannot reach the internet is not
much use. Everything here is arranged around that priority.

It is small and auditable: the whole security model fits in two files
(`main.go`, `dockerproxy.go`) you can read in one sitting.

> **Linux only, and it is a fence, not a vault.** The default posture is
> arranged against a confused tool, not a hostile one: the network is shared,
> the terminal is shared, and the `KNOWN ESCAPE VECTORS` block at the bottom
> of `main.go` lists what is deliberately left open. Without bubblewrap ≥ 0.9
> and kernel ≥ 5.11 the write-discarding overlay is unavailable and writes are
> real — azkaban warns, and the warning matters.

---

## How it works

One static binary, two roles. The outer role builds a bwrap command line from
the allowlists at the top of `main.go`; the inner role runs inside the jail
and adds the layer bwrap cannot:

```
  azkaban [flags] [--] <command> [args...]
      │
      │  outer role — on the host
      ├─ parse flags, read ~/.config/azkaban/config
      ├─ build the bind lists                (rwPaths, roPaths, roFreeze, maskPaths)
      ├─ --dry-run ? print the command and stop
      └─ exec /usr/bin/bwrap ...
             │
             │  the mount view — subtraction, not permission
             │    $HOME is a tmpfs; only allowlisted paths are bound back
             │    credential stores inside them are masked with an empty file
             │    ~/.config/azkaban is re-bound read-only AFTER the rw list
             │
             │  namespaces — pid, uts, ipc, cgroup (net only with --no-net)
             │  the overlay — writes land in tmpfs and evaporate on exit
             │  rlimits + a sibling cgroup, so a runaway write cannot OOM the
             │    host through that tmpfs
             │
             └─ re-exec of the same binary: --landlock-exec
                    │
                    │  landlock — what may be OPENED, enforced by the kernel
                    │    even if a mount is somehow reachable
                    │    (+ the TCP port allowlist under --net-ports)
                    │
                    └─ exec <command> [args...]

  --bind-docker / --bind-podman add one more: a filtering proxy in front of the
  container socket, since a socket that can create a privileged container is a
  hole straight through everything above.
```

Layers, not a single gate: the mount view decides what *exists*, Landlock
decides what may be *opened*, and the two are enforced by different parts of
the kernel. Numbered in full in the design doc.

More in [`docs/design.md`](docs/design.md).

## What it does

- **Subtracts, rather than permits.** `$HOME` becomes an empty tmpfs and only
  the allowlisted paths are bound back, so a directory nobody thought about is
  hidden by default rather than exposed by default.
- **Discards writes by default.** The allowlisted `$HOME` directories are
  writable through a throwaway overlay: the tool sees a working filesystem, and
  the writes evaporate on exit. Caveat: this needs bubblewrap ≥ 0.9 and kernel
  ≥ 5.11, and state you *wanted* to keep is discarded too — that is what
  `--persist-path` is for.
- **Masks credential stores** that live inside directories bound wholesale.
  `~/.config` holds API tokens; the overlay stops them being destroyed, not
  read, so they are replaced with empty files.
- **Binds no container socket** unless asked. `--bind-docker` / `--bind-podman`
  put a filtering proxy in front of one, refusing `--privileged`, device
  passthrough, escape-worthy capabilities, shared namespaces and binds of host
  paths outside the project. Caveat: containerd is not offered at all — it
  speaks gRPC, which the proxy cannot inspect.
- **Clears the environment** but for a small allowlist, so an API key in the
  host environment does not follow the tool in. Extend it with `env NAME`
  lines in the config, or hand over everything with `--keep-env`.
- **Caps file size, process count and file descriptors**, and optionally total
  memory with `--mem-max`. Caveat: `RLIMIT_FSIZE` is per-file, so a loop
  creating many small files still fills the overlay; and a memory cap also
  disables swap for the jail.
- **Shares the network by default**, because an agent that cannot reach the
  internet is not much use. `--no-net` isolates it; `--net-ports` allows
  outbound TCP to named ports only, which does not touch UDP and therefore
  does not touch DNS.
- **Prints the whole invocation** with `--dry-run`. That output is the audit
  trail, and it is meant to be read before it is trusted.

## Requirements

- Linux with unprivileged user namespaces enabled
- `bwrap` (bubblewrap) at `/usr/bin/bwrap`
- **bubblewrap ≥ 0.9 and kernel ≥ 5.11** for the default write-discarding
  overlay. Without either, azkaban warns and falls back to real writes — a
  working jail, but one where a destructive tool destroys real data.
- A kernel with Landlock (v5 best-effort; older kernels degrade gracefully,
  losing the newer access rights rather than the jail)
- Optional: rootless docker or podman, only if you pass `--bind-docker` / `--bind-podman`

Verify the overlay is actually active before trusting it:

```bash
azkaban --dry-run | grep -c tmp-overlay     # 0 means writes are real
```

## Install

```sh
git clone https://github.com/fabiocicerchia/azkaban.git
cd azkaban
make build      # -> ./azkaban
make install    # ...or into GOBIN (~/go/bin by default)
```

## Usage

```bash
cd /path/to/project      # NOT $HOME — azkaban refuses to make $HOME writable
azkaban claude           # or: azkaban -- <any command> [args...]
```

Read the jail before you trust it. `--dry-run` prints the exact bwrap command
instead of running it (elided here — the real line is long, and that is the
point):

```console
$ azkaban --dry-run -- sh -c 'echo hi'
azkaban: WARNING: this bwrap has no --tmp-overlay; falling back to real writes. Upgrade bubblewrap (>= 0.9) or pass --persist to silence this.
/usr/bin/bwrap --clearenv --setenv HOME /home/you --setenv PATH ... \
  --ro-bind /usr /usr --ro-bind /etc /etc --dev /dev --proc /proc \
  --tmpfs /tmp --tmpfs /run \
  --ro-bind /tmp/azkaban-mask-503781593 /proc/kallsyms \
  --tmpfs /home/you \
  --ro-bind /home/you/.gitconfig /home/you/.gitconfig \
  --bind /home/you/.cache /home/you/.cache \
  --bind /home/you/.config /home/you/.config \
  --ro-bind /home/you/.config/azkaban /home/you/.config/azkaban \
  --bind /path/to/project /path/to/project --chdir /path/to/project \
  --die-with-parent --unshare-pid --unshare-uts --unshare-ipc \
  --hostname azkaban \
  --setenv AZKABAN_LL_RO '...' --setenv AZKABAN_LL_RW '...' \
  /tmp/.azkaban-self --landlock-exec -- sh -c 'echo hi'
```

`--tmpfs /home/you` is the whole model in one flag: the home directory is
emptied first, and every `--bind` after it is a deliberate exception.

The flag reference, verbatim:

```console
$ azkaban --help
azkaban [flags] [--] <command> [args...]

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
  --ssh-agent    forward $SSH_AUTH_SOCK (+ known_hosts read-only) so git push
                 over ssh works. The keys stay on the host — the jail gets a
                 signing oracle, not the key — but that oracle authenticates as
                 you to every host they open, for as long as the jail runs.
                 "ssh-add -c" makes each signature prompt on the host. OFF by
                 default; ~/.ssh itself is never bound.
  --allow-userns permit nested user namespaces (needed by Chrome/Electron tools)
  --no-net       isolate the network in a new namespace (breaks internet access)
  --net-ports L  allow outbound TCP only to these ports (comma-separated), enforced
                 by landlock. Blocks localhost services and LAN scanning. UDP and
                 therefore DNS are unaffected. Needs the landlock stage.
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
```

### Asking the policy a question

`--dry-run` prints the whole resolved policy. `azkaban why` answers about one
thing:

```console
$ azkaban why --path ~/.claude --op write
/home/you/.claude
  ALLOWED (write)
  mechanism: --overlay-src + --tmp-overlay (throwaway tmpfs upper layer)
  matched:   rwPaths .claude
  survives:  no — discarded when the jail exits

$ azkaban why --path ~/.ssh/id_rsa
/home/you/.ssh/id_rsa
  ABSENT (read)
  mechanism: --tmpfs /home/you
  matched:   default deny
```

`ABSENT`, not `DENIED`: `~/.ssh` was never mounted, so a read fails as `ENOENT`
— and calling that a denial sends people hunting for a permission nobody can
grant. Add `--json` for tooling, or the run flags (`--persist`, `--net-ports`,
`--ro`, ...) to ask what the answer *would* be.

**`--self` answers from inside the jail**, off the read-only policy the jail
carries at `/run/azkaban/`. That is the variant that helps a confused agent,
because it runs at the moment the error happened — see
[docs/design.md](docs/design.md#telling-the-tool-it-is-in-a-jail).

More in [`docs/getting-started.md`](docs/getting-started.md).

## Common errors

**`azkaban: WARNING: this bwrap has no --tmp-overlay; falling back to real writes.`**
The default protection is gone: writes to the allowlisted `$HOME` directories
now land on disk. Upgrade bubblewrap to ≥ 0.9 (and the kernel to ≥ 5.11 for
unprivileged overlayfs), or pass `--persist` to say you meant it. Check with
`azkaban --dry-run | grep -c tmp-overlay` — `0` means writes are real.

**`azkaban: refusing to run: ... path contains a newline or NUL`**
A bind path with a newline in it would inject extra entries into the Landlock
allowlist, so it is refused rather than sanitised. Rename the directory.

**`azkaban: warning: resource cgroup unavailable (...); memory is NOT capped.`**
The cgroup v2 tree is not usable here — common inside another container. The
jail still runs, but the overlay writes to RAM with no cap. You did not ask for
one, so this is a warning.

**`azkaban: --mem-max 8G cannot be enforced: ...`**
The same condition, on a run that *did* ask for a cap — so it is refused rather
than warned about. A cap that silently does nothing is worse than no cap: the
flag looks like it worked while the jail runs unbounded. Delegate a cgroup v2
memory controller, or drop `--mem-max`.

**`azkaban: WARNING: this kernel allows TIOCSTI`**
The jail shares your terminal, so a tool inside it can push characters into
your shell's input queue. Close it host-wide:
`sysctl -w dev.tty.legacy_tiocsti=0`.

**`Can't find source path ...` from bwrap.**
A path in the allowlist that does not exist on this machine, usually a
dangling symlink under `$HOME`. Binds are filtered by `os.Stat`, which follows
symlinks for exactly this reason; a broken link is the case that slips through.

**The tool inside cannot see a file it needs.**
That is the design — `$HOME` is a tmpfs and everything is hidden unless it is
in a list. Add `ro`/`rw` lines to `~/.config/azkaban/config` for a permanent
exception, or `--ro`/`--rw` for one run.

## Documentation

| Page | Covers |
|---|---|
| [design.md](docs/design.md) | The five layers in detail, plus the security model and deliberate omissions |
| [configuration.md](docs/configuration.md) | `~/.config/azkaban/config`, credential masking, environment allowlist |
| [containers.md](docs/containers.md) | Docker/podman sockets and the filtering proxy |
| [testing.md](docs/testing.md) | How the suite proves containment without risking a real home |

## References

The layers are documented ones; these are what they are built on.

- [bubblewrap](https://github.com/containers/bubblewrap) — the mount and
  namespace layer, and the `--tmp-overlay` flag the default posture depends on.
- [Landlock](https://docs.kernel.org/userspace-api/landlock.html) — the kernel
  LSM behind layer 5, including the ABI versions that decide what degrades on
  an older kernel.
- [`user_namespaces(7)`](https://man7.org/linux/man-pages/man7/user_namespaces.7.html)
  — why this needs no privilege on the host, and what `--allow-userns` gives
  back.
- [cgroup v2](https://docs.kernel.org/admin-guide/cgroup-v2.html) — why the
  resource cgroup is created as a *sibling*: controllers cannot be enabled on
  a cgroup that holds processes.
- [Docker Engine API](https://docs.docker.com/reference/api/engine/) — the
  endpoints and request bodies the socket filter inspects.
- [`TIOCSTI` and `dev.tty.legacy_tiocsti`](https://man7.org/linux/man-pages/man4/tty_ioctl.4.html)
  — the terminal-injection vector the startup warning is about.

## Release cycle

[Semantic Versioning](https://semver.org/), from
[Conventional Commits](https://www.conventionalcommits.org/).

- **Major** — a change to what is confined, i.e. to the containment guarantee.
- **Minor** — new flags, new defaults that do not weaken the guarantee, and
  entries added to the bind lists.
- **Patch** — fixes; only the latest minor gets them.

Any change to the bind lists, the bwrap flags, the Landlock ruleset or the
socket filter is security-sensitive regardless of the number it ships under,
and PRs that touch them are reviewed as such — see CONTRIBUTING.md.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) — in particular the rules for PRs that
touch the bind lists, since those *are* the security model. By participating you
agree to the [Code of Conduct](CODE_OF_CONDUCT.md).

## Security

Found a vulnerability? See [SECURITY.md](SECURITY.md) — please don't open a
public issue. Note that the `KNOWN ESCAPE VECTORS` block at the bottom of
`main.go` documents what is deliberately left open.

## License

[Apache 2.0](LICENSE) © Fabio Cicerchia
