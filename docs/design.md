# How the confinement works

[← README](../README.md)

Five independent mechanisms, each covering a gap the previous one structurally
cannot. None of them is a container runtime — there is no image, no root, and no
daemon between you and the tool.

| Layer | Kernel feature | Enforces | Bypassed by |
|-------|----------------|----------|-------------|
| 1. Mount view | mount namespace (bubblewrap) | *what paths exist at all* | nothing in-process; the view is built before the tool starts |
| 2. Namespaces | pid / ipc / uts / cgroup / user (net optional) | *what the process can see and signal* | shared net by default |
| 3. Landlock | Landlock LSM, ABI v5 | *what may be opened, and how* | paths already open; `--no-landlock` |
| 4. Overlay | overlayfs upper layer on tmpfs | *whether writes and deletes are durable* | `--persist`; project dir by design |
| 5. Socket filter | userspace HTTP proxy | *what a container daemon will do on the tool's behalf* | `--unfiltered-container-socket`; TOCTOU on bind paths |

Layers 1–3 answer *where* a tool may write. Layer 4 exists because that is not
the same question as *what it may destroy* — see [the incident](../README.md#this-actually-happened).

## 1. The mount view — subtraction, not permission

`$HOME` is replaced with an **empty tmpfs**, then a short allowlist is bound back
over it. This is the core move, and it is subtractive: `~/.ssh` is not "denied",
it does not exist. A tool cannot request, guess, or race its way to a path that
was never mounted, and no policy has to enumerate what to hide.

bwrap applies its arguments **in order**, and a later bind overlays an earlier
one. Three protections depend on that ordering, so the sequence in `outer()` is
load-bearing, not stylistic:

```
--tmpfs  ~                       # everything under $HOME disappears
--bind   ~/.config               # …selected dirs come back writable
--ro-bind ~/.config/azkaban      # …but the trusted config is re-frozen on top
```

The same trick pins the target binary: only the resolved executable is bound in,
never its `$PATH` directory.

## 2. Namespaces — what it can see

`--unshare-pid` gives a fresh procfs, so the tool sees 4 processes instead of
548, and cannot signal or `ptrace` anything on the host. `ipc`, `uts`, and
`cgroup` are unshared too. A **user namespace is created as well** — bubblewrap
needs one to do any of this without privilege — but your uid is mapped straight
through, so files are still touched as *you*, with an empty capability set.
Nested user namespaces are blocked by default (`--allow-userns` reopens them for
Chrome/Electron tools that build their own sandbox that way).

The network namespace is **shared by default** (`--no-net` isolates it): an AI
CLI that cannot reach the internet is not much of an AI CLI. The cost is honest —
host `localhost` and the LAN are reachable unless you pass `--net-ports`.

## 3. Landlock — what it may open

Layers 1–2 shape the filesystem *before* the tool runs. Landlock constrains it
*from inside*, per-syscall, and unlike the mount view it cannot be undone by
anything the process does afterwards — restrictions survive `execve` and are
inherited by children.

This is why azkaban runs in **two stages**. Landlock has to be applied by a
process already inside the sandbox, so the outer role re-binds the azkaban binary
at `/tmp/.azkaban-self` and re-execs it with `--landlock-exec`; that inner role
applies the ruleset and `execve`s the real command. The allowlists travel between
the two as `AZKABAN_LL_*` environment variables, which is deliberate — they show
up verbatim in `--dry-run`, so the policy is auditable without reading the code.
The inner stage strips them before handing over to the target.

The rules are kept **tighter than the mounts on purpose**. If Landlock merely
mirrored bwrap it would be ceremony: `/dev` and `/run` are bound but only
readable, with write granted to seven device nodes and `/dev/pts`, `/dev/shm`.
`$HOME` is read-only, so the home tmpfs cannot be used as scratch space to plant
decoy dotfiles.

> **The `IoctlDev` trap.** Landlock ABI v5 added
> `LANDLOCK_ACCESS_FS_IOCTL_DEV`. `V5.BestEffort()` *handles* that right —
> meaning it is denied unless granted — but go-landlock's `RWDirs`/`RWFiles`
> deliberately do **not** grant it; you must opt in with `.WithIoctlDev()`.
> Without it every ioctl on a newly opened device node fails: `openpty()` returns
> `EACCES` and any tool that runs a subprocess in a pty breaks. It hides well,
> because file descriptors inherited from before the sandbox are never
> re-checked, so `stty`, `TCGETS` and ordinary terminal I/O keep working.

`BestEffort()` degrades to the highest ABI the running kernel supports rather
than failing, so older kernels lose the newer rights instead of losing the jail.

`--net-ports` also runs here: Landlock ABI v4+ restricts TCP connect, so an
allowlist of outbound ports is enforced by the kernel with no proxy in the path.
It covers TCP only — UDP, and therefore DNS, is untouched.

## 4. The overlay — writes that cannot outlive the jail

Layers 1–3 all answer the same question: *where may this process write?* None of
them answers a different and, for this tool, more important one: *what can it
destroy?* A path on the read-write allowlist is a path a confused agent can
`rm -rf`, and the sandbox will have worked perfectly while the data goes away.

So each writable `$HOME` entry is mounted as an overlay whose upper layer is a
throwaway tmpfs (`--overlay-src DIR --tmp-overlay DIR`). Reads come from the real
directory; writes and deletes land in RAM and are dropped when the jail exits.
Single files get the same treatment via a scratch copy, since overlayfs needs a
directory.

The exception is the project directory, which is bound normally. Work has to
survive, so it is the one place destruction is real — keep it under git.

The overlay cannot tell destruction from useful work, so **state you wanted to
keep is dropped too** — shell history, caches, and most visibly Claude Code's
session transcripts (`~/.claude/projects/…/<uuid>.jsonl`): the write succeeds
inside the jail, exit prints a real `claude --resume <uuid>` line, and the file
dies with the upper layer. `--persist` is the fix, all-or-nothing — there is no
way to keep `~/.claude/projects` while `rm -rf ~/.claude` stays impossible.

bubblewrap could do that (`--overlay RWSRC WORKDIR DEST` puts the upper layer on
real disk, so deletes are whiteouts and the lower layer survives). Not used here:
the upper dir would have to sit outside the allowlist to be tamper-proof, writes
would leave RAM so `--mem-max` no longer bounds them, and recovering the survivors
is a manual copy either way.

Because the upper layer is RAM, the overlay comes with resource caps: file size
4 GiB, processes 4096, core dumps disabled (`--no-rlimits` lifts them). Those
caps are per-*file*, so a loop creating many small files still fills the overlay.
`--mem-max 8G` is the real bound — cgroup v2 charges tmpfs pages to the group.
It also sets `memory.swap.max=0`, without which the cap is advisory: with swap
enabled, 256 MiB allocated fine under a 64 MiB cap because the kernel simply
paged it out.

**A `--mem-max` that cannot be enforced is refused, not warned about.** If there
is no delegated cgroup v2 memory controller — common inside another container —
the run stops. It used to warn and continue, which meant `azkaban --mem-max 8G`
could run with no memory bound at all, having printed one line that scrolls
away, on the flag this section calls the real bound. A cap that silently does
nothing is worse than no cap, because the flag looks like it worked. Drop
`--mem-max` to run without one deliberately.

A run that did *not* ask for a cap still degrades to a warning: nobody asked for
that one, and refusing it would break every run inside a container.

It stays **opt-in** even though that leaves the overlay unbounded by default,
because disabling swap is not a side effect to impose on every run: a workload
that would have paged out gets killed instead. Worth passing on any run where a
tool downloads, extracts or builds something large. bubblewrap's `--size` would
be the cheaper mechanism, but it applies to `--tmpfs` only, not to the
`--tmp-overlay` upper layer, so the cgroup is the only lever available.

## 5. The socket filter — where the kernel cannot reach

The other layers are kernel enforcement on *this* process. A container socket
defeats all of them by design: when the tool asks for `-v /:/host`, the mount is
performed **by the daemon, on the host, in a different process**. bwrap and
Landlock never see it. The socket is the control surface, so the only place to
enforce "no host paths outside the project" is the API itself — hence a proxy
rather than another mount rule. And since no proxy can cover an API it cannot
parse, sockets are opt-in and containerd is not offered at all.

Details in [containers.md](containers.md).

---

## Asking the policy a question

`--dry-run` prints the resolved bwrap command line, and that is the audit trail:
accurate, complete, copy-pasteable. It is also an answer to *what is the whole
policy*, not to *what about this path*.

`azkaban why` is the second question:

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

The distinction in that second answer is the one worth having. `~/.ssh` was
never mounted, so a read fails as `ENOENT` — reporting it as *denied* would send
someone hunting for a permission nobody can grant.

It answers from the same lists the bind loops use, walked in the same order, so
the layer it reports is the layer that would end up on top: ro binds, then rw
(overlaid by default), then `persist`, then `roFreeze`, then masks, last wins.
It starts no jail and reads nothing but the config.

The run flags are accepted as *simulation*, so the question can be "would this
be allowed if I ran it that way": `--persist`, `--no-net`, `--net-ports`,
`--no-landlock`, `--ro`, `--rw`, `--persist-path`. `--json` makes it consumable
by tooling, and by an agent that has just hit an error it cannot interpret.

On hosts it gives the honest answer rather than a comforting one: `--net-ports`
is a port allowlist enforced by Landlock and cannot express a hostname, so a
`--host` question says so instead of implying a filter that does not exist.

**Not implemented: `--self`.** Answering from *inside* the jail is the variant
that would actually help a confused agent, but the Landlock allowlists arrive as
`AZKABAN_LL_*` and are deliberately stripped before the target command execs.
Keeping them, or writing a policy file into the jail, is a change to what the
jail contains — it belongs with the in-jail guidance work, not here.

## Security model

The known escape vectors are documented at the bottom of `main.go` and in the
`dockerproxy.go` header — read them. In short: `--unfiltered-container-socket`, `--keep-env`,
`--persist`, `--display` and `--ssh-agent` are all deliberate trade-offs you opt
into.

Two vectors are open by default:

- **TIOCSTI terminal injection.** The jail shares your controlling terminal and
  can inject keystrokes into it, which your shell runs after azkaban exits.
  Kernels ≥ 6.2 ship `dev.tty.legacy_tiocsti=0`, which closes it; azkaban warns
  and names the sysctl when yours does not. There is no flag for it: detaching
  the session would close the vector but costs Ctrl-C and job control on *every*
  run, including the large majority where the kernel has already shut it — the
  wrong trade to carry for a case the host fixes better with one sysctl.
- **TOCTOU in the docker bind check.** Known and unfixable through the socket
  API: the proxy resolves symlinks when it filters, and the daemon mounts moments
  later. The jail owns cwd, so it can swap an accepted path for a symlink in
  between. The proxy raises the bar; it is not a hard boundary.

### Deliberately not locked

- **No seccomp filter.** `Seccomp: 0` inside the jail; the full syscall surface
  is reachable. Measured rather than assumed — every escalation syscall usually
  cited is already closed by other means: `perf_event_open` and `userfaultfd`
  return EPERM, `mount` and `open_by_handle_at` need capabilities the empty
  bounding set (`CapBnd: 0`) can never grant, and `ptrace` is confined to the
  jail's own PID namespace. Against *accidents* it buys almost nothing anyway,
  since `rm -rf` is `unlinkat()` and blocking that breaks the tool. Where it would
  earn its keep is deliberate exploitation.
- **No network egress filtering by host or domain.** `--net-ports` restricts
  outbound TCP *ports* at the kernel, which closes localhost services and LAN
  scanning, but it cannot express "only api.anthropic.com". `azkaban why --host`
  says exactly that rather than implying a filter.
- **Same uid, no capability drop.** `CapEff` is already empty for a normal user;
  the tool runs as you, which is exactly why "as your user" is the boundary the
  docker proxy has to defend.
- **`NoNewPrivs` is set** by bubblewrap itself, so setuid binaries are inert
  (`sudo` and `su` exist in the jail but refuse to act). It stays set under
  `--no-landlock` — verify before crediting Landlock for it.
- **Nothing here blocks the network.** `--no-net` and `--net-ports` are the only
  network controls and both are off by default; there is no packet filtering
  anywhere in this codebase. If egress appears blocked during testing, something
  outside azkaban is doing it.

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
real bound — see [docs/design.md](design.md#4-the-overlay--writes-that-cannot-outlive-the-jail).

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
instead](design.md#4-the-overlay--writes-that-cannot-outlive-the-jail).

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
one the tool writes in place — see [configuration.md](configuration.md#keeping-one-path-persist).

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
deliberately left unlocked: [docs/design.md](design.md).
