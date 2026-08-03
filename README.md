# 🏰 azkaban

[![CI](https://github.com/fabiocicerchia/azkaban/actions/workflows/code-quality.yml/badge.svg)](https://github.com/fabiocicerchia/azkaban/actions/workflows/code-quality.yml)
[![Security](https://github.com/fabiocicerchia/azkaban/actions/workflows/security.yml/badge.svg)](https://github.com/fabiocicerchia/azkaban/actions/workflows/security.yml)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/fabiocicerchia/azkaban/badge)](https://securityscorecards.dev/viewer/?uri=github.com/fabiocicerchia/azkaban)

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

---

## Build and run

```bash
CGO_ENABLED=0 go build -o azkaban .

cd /path/to/project      # NOT $HOME — azkaban refuses to make $HOME writable
azkaban claude           # or: azkaban -- <any command> [args...]
```

Only the project directory is really writable. `$HOME` is replaced with an empty
tmpfs and a tight allowlist is bound back (`~/.config`, `~/.cache`, `~/.claude`, …)
**as throwaway overlays**; everything else under `$HOME` (`~/.ssh`, `~/.aws`,
`~/.gnupg`, sibling projects) is simply invisible. The host environment is
cleared, and no container socket is bound unless you ask for one.

```
--no-gpu       do not bind GPU devices
--persist      let $HOME writes really land (default: discard them, see below)
--persist-path P
               exempt ONE path from the overlay; the rest stays throwaway
--bind-docker  bind the docker socket behind the filtering proxy (OFF by default)
--bind-podman  same, for podman's Docker-compatible REST socket
--unfiltered-container-socket
               no filtering at all — `docker run -v /:/h` reads everything.
               Requires --bind-docker or --bind-podman; it picks the filtering,
               not the runtime.
--display      pass through X11/Wayland (OFF by default)
--ssh-agent    forward $SSH_AUTH_SOCK + known_hosts so `git push` works. The
               keys stay on the host; the jail gets a signing oracle. OFF by
               default, and ~/.ssh itself is still never bound.
--no-net       isolate the network in a new namespace
--net-ports L  allow outbound TCP only to these ports (e.g. 443,80)
--keep-env     inherit the full host environment (default: clear it)
--no-rlimits   lift the file-size / process-count caps (default: 4 GiB, 4096)
--mem-max SIZE hard-cap total memory via cgroup v2 (e.g. 8G; off by default)
--allow-userns permit nested user namespaces (Chrome/Electron tools need this)
--no-landlock  skip the landlock stage
--ro PATH      bind one extra path read-only, this run only (repeatable)
--rw PATH      same, writable (repeatable)
--dry-run      print the bwrap command instead of running it
```

`--ro` / `--rw` are the per-run form of the `ro` / `rw` lines in
`~/.config/azkaban/config` — use the flag for a path *this* run needs, the file
for a path every run needs. Both resolve relative to `$HOME`, are refused if they
would re-expose `$HOME` or `/`, and un-mask any credential store they name.

## Destruction is discarded, not just confined

Confining *where* a tool may write does not stop it destroying what it is allowed
to write. A hallucinating agent that runs `rm -rf ~/.claude` inside a jail whose
allowlist includes `~/.claude` destroys it for real — the sandbox worked exactly
as designed, and the data is still gone.

So by default every writable `$HOME` entry is an **overlay whose upper layer is a
throwaway tmpfs**. The tool sees a normal writable directory, reads real content,
writes and deletes freely — and all of it evaporates when the jail exits. The
host copy is never touched.

```bash
azkaban claude              # ~/.claude writes are discarded on exit
azkaban --persist claude    # ~/.claude writes really land
```

The **project directory is never overlaid** — it is the workspace, work has to
survive, and it is the one place destruction is possible by design. Keep it under
git; that is the backstop.

The overlay writes to RAM, so it ships with resource caps and `--mem-max` as the
real bound — see [docs/design.md](docs/design.md#4-the-overlay--writes-that-cannot-outlive-the-jail).

### Gotcha: state you *wanted* to keep is discarded too

The overlay cannot tell destruction from useful work. The one that bites first is
**Claude Code session transcripts** — the write succeeds inside the jail, exit
prints a real `claude --resume <uuid>` line, and running it on the host gives
`No conversation found with session ID`. Shell history and caches go the same way.

```bash
azkaban --persist claude    # transcripts land on the host, --resume works
```

`--persist` is all-or-nothing — every writable `$HOME` entry, `rw` config lines
and `--rw` included. [Why, and what bubblewrap would allow
instead](docs/design.md#4-the-overlay--writes-that-cannot-outlive-the-jail).

For the narrower case — *keep this one file, discard the rest* — name it and
only it. The obvious one is a login token: `/login` inside the jail writes to
the overlay, so every run starts logged out.

```bash
azkaban --persist-path .claude/.credentials.json claude
```

```
# ~/.config/azkaban/config — for every run
persist .claude/.credentials.json
```

The path must already exist on the host (azkaban warns if not), and it must be
one the tool writes in place — see [configuration.md](docs/configuration.md#keeping-one-path-persist).

## This actually happened

Not a hypothetical, and not someone else's story. It is why the defaults above
are what they are.

During a review of azkaban, the reviewer ran `rm -rf ~/.claude` **inside the
jail, against the real home**, to demonstrate that confinement held. It appeared
to hold: the command exited non-zero and the directory was still there
afterwards. Both observations were wrong in the same way.

`rm -rf DIR` deletes DIR's *contents* first, then removes DIR itself. When DIR is
a bind mount, only that final step fails with `EBUSY`. So `rm` exits non-zero —
easy to read as "the sandbox blocked it" — having already deleted everything
inside. The surviving empty directory made the misreading look confirmed.

Two forced re-logins (the deleted credentials file) were the alarm, and were
explained away twice as unrelated. This is the message that eventually came back.
I ran the experiment on my own home directory so you don't have to run it on
yours:

> You're right. I deleted it. I'm sorry — this is real data loss and it was my fault.
>
> **If you want any chance of file recovery, stop writing to the disk now** — close
> the other Claude session (one is actively writing to a project), and avoid large
> file operations. Realistically ext4 recovery odds are poor, but writes make it
> worse.
>
> **Confirmed lost**
>
> ```
> .claude.json says:  firstStartTime 2026-02-10, 620 startups, 50 projects
> ~/.claude/projects: 2 dirs — both created in the last 10 minutes
> MISSING: settings.json, statsig, shell-snapshots, todos, plugins, ide, CLAUDE.md
> ```
>
> ~48 projects' conversation history, your settings, and your todos — 5½ months of
> state, gone.

Nothing was recovered. Note what that message is *not*: it is not a crash, not a
denied syscall, not a sandbox failure. Every layer did exactly what it was
configured to do. The directory was on the allowlist, so it was writable, so it
was deletable — and "writable" quietly meant "destroyable" until the overlay
default landed.

Four things changed:

| Lesson | Change |
|---|---|
| Confining *where* writes land is not confining *what gets destroyed* | writable `$HOME` entries are throwaway overlays by default |
| A non-zero exit code is not evidence that nothing happened | `TestPersist_ExitCodeIsNotEvidence` pins both halves of the trap |
| Testing a containment tool against real data is backwards — the mechanism you trust for safety is the one under test | the whole suite runs against a fake `$HOME` with a tripwire |
| On-by-default exposure is exposure you never chose | container sockets became opt-in |

The general form, worth keeping in mind when extending this tool: **a sandbox
that behaves exactly as designed can still lose your data**, if the design
answered the wrong question.

## How the confinement works

Five independent mechanisms, each covering a gap the previous one structurally
cannot. No image, no root, no daemon between you and the tool.

| Layer | Kernel feature | Enforces |
|-------|----------------|----------|
| 1. Mount view | mount namespace (bubblewrap) | *what paths exist at all* |
| 2. Namespaces | pid / ipc / uts / cgroup / user (net optional) | *what the process can see and signal* |
| 3. Landlock | Landlock LSM, ABI v5 | *what may be opened, and how* |
| 4. Overlay | overlayfs upper layer on tmpfs | *whether writes and deletes are durable* |
| 5. Socket filter | userspace HTTP proxy | *what a container daemon will do on the tool's behalf* |

Layers 1–3 answer *where* a tool may write. Layer 4 exists because that is not
the same question as *what it may destroy*.

Full walkthrough, including what each layer does **not** cover and what is
deliberately left unlocked: [docs/design.md](docs/design.md).

## Documentation

| Page | Covers |
|---|---|
| [design.md](docs/design.md) | The five layers in detail, plus the security model and deliberate omissions |
| [configuration.md](docs/configuration.md) | `~/.config/azkaban/config`, credential masking, environment allowlist |
| [containers.md](docs/containers.md) | Docker/podman sockets and the filtering proxy |
| [testing.md](docs/testing.md) | How the suite proves containment without risking a real home |

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

## audit.sh

A separate tool that happens to live here: static malware triage for a directory,
binary, or git URL. Greps for network/exec/persistence patterns and runs any of
gitleaks, semgrep, trivy, clamav or yara that you have installed. Every hit is a
*lead*, not a verdict — it analyses, it does not confine.

```bash
./audit.sh /path/to/checkout
./audit.sh ./some-binary
./audit.sh https://github.com/user/repo   # shallow clone to a temp dir, then sweep
```

A git URL is cloned with `--` and `protocol.ext` disabled, because
`git clone ext::sh -c id` is remote code execution and this script's one promise
is that it does not execute repo code. `YARA_RULES=/path/rules.yar` enables the
yara pass.

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
