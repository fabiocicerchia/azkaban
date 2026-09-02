# Configuration

[← README](../README.md)

Everything below is optional. azkaban runs with no config file.

## The config file

`~/.config/azkaban/config` — one directive per line, `#` comments, blank lines
ignored. Paths are `$HOME`-relative unless absolute.

```
# ~/.config/azkaban/config
ro  /etc/ssl/certs          # bind read-only
rw  /srv/shared-cache       # bind read-write (overlaid like the rest)
persist .claude/.credentials.json   # writable AND not overlaid — survives exit
env ANTHROPIC_API_KEY       # forward one host variable
mask .config/mytool/token   # blank out a path azkaban does not know about
net api.anthropic.com       # allow egress to one host (see design.md)
audit off                   # stop recording runs (they are recorded by default)
```

That file is **trusted input**, which is only safe because azkaban re-binds
`~/.config/azkaban` read-only inside the jail — otherwise the sandboxed process
could append `rw /` to it and own the host on the next run. `rw` entries naming
`/`, `$HOME`, or any ancestor of `$HOME` are refused outright.

`~/.config/containers` is frozen read-only for the same reason: its
`hooks_dir` setting is arbitrary code execution on the next container run.

## Per-run paths

`--ro PATH` and `--rw PATH` are the same two directives scoped to one
invocation. Repeatable, and otherwise identical — same `$HOME`-relative
resolution, same refusal of `/` and `$HOME`, same un-masking below.

```bash
azkaban --ro /opt/toolchain --rw ~/scratch claude
```

Flag for a path *this* run needs, file for a path *every* run needs. `--rw` is
still overlaid; add `--persist` if the writes must survive.

## Keeping one path (`persist`)

`--persist` is all-or-nothing: to keep a login token you make every `$HOME`
allowlist directory really destroyable again. `persist PATH` is the per-path
form — that one path is bound to the real host inode, everything else stays a
throwaway overlay.

```
# ~/.config/azkaban/config
persist .claude/.credentials.json
```

```bash
azkaban --persist-path .claude/.credentials.json claude   # same, one run only
```

The token written by `/login` inside the jail now lands on the host; a
`rm -rf ~/.claude` in the same run still loses nothing else. Same
`$HOME`-relative resolution, same refusal of `/` and `$HOME`, and it un-masks
like `ro`/`rw`.

Two things to know:

- **The source must already exist.** A bind needs something to bind. If the path
  is missing azkaban warns on stderr and carries on without it — create it
  outside the jail first (for Claude Code: log in once on the host).
- **Name the file, not the directory,** unless the tool saves atomically.
  `rename(2)` onto a bind *mountpoint* fails with `EBUSY`, so a tool that writes
  `x.tmp` and renames it over the target needs `persist .claude` (the directory)
  instead. Directory persistence hands back the `rm -rf` exposure for that
  directory — which is the trade `--persist` makes for all of them.

### Claude Code needs two paths

The token alone is not the login. `~/.claude.json` holds the account it belongs
to (`oauthAccount`), the onboarding flag, and the per-project "do you trust this
folder" answers — and it is a *file* in the writable allowlist, so by default it
is a throwaway copy and every write to it is dropped on exit. Persist the token
and watch the account state revert on the next run, and Claude Code asks you to
log in again with a perfectly good token sitting on disk.

```
# ~/.config/azkaban/config
persist .claude/.credentials.json
persist .claude.json
```

Check it from inside the jail — the two lines below are the bind, not the
overlay:

```bash
grep -E '\.claude(\.json|/\.cred)' /proc/self/mountinfo
```

`.claude.json` is a bigger target than the token: it is mutable state a hostile
tool can now rewrite for real, not just read. Both files were already fully
readable in the jail either way, so this costs integrity, not secrecy.

Claude Code writes both atomically, and falls back to `copyFile` when the
`rename` hits `EBUSY`/`EXDEV` — so the file-level bind above is enough, and
`persist .claude` (the whole directory, `rm -rf` and all) is not needed.

`--resume` and `--continue` need a third: transcripts live in
`~/.claude/projects/<slug>/<session-id>.jsonl`, so with the overlay every session
is gone the moment the jail exits and `claude --resume <id>` answers "No
conversation found". This one has to be the *directory* — the session file's name
is not known in advance:

```
persist .claude/projects
```

Transcripts are the one thing here worth losing on purpose; keep the line out if
you would rather a hostile tool could not read (or delete) past sessions.

## Pushing from inside the jail

`~/.ssh` is not bound, so by default `git push` inside the jail fails with
`Host key verification failed` — there are no keys, no agent and no
`known_hosts`. That is the boundary working, not a bug.

`--ssh-agent` is the narrow way through:

```bash
azkaban --ssh-agent claude
```

It binds `$SSH_AUTH_SOCK` and `known_hosts` (read-only) and nothing else. The
private keys never enter the jail — what crosses is a *signing oracle*, so an
exfiltrated jail keeps nothing after it exits. While it runs, though, anything
inside can authenticate as you to every host those keys open. `ssh-add -c` on
the host reduces that to one confirmation prompt per signature.

Do not reach for `ro .ssh` instead. It is the same capability plus permanent
key theft, and `--display` is the same oracle plus X11 and dbus.

`gh` is a separate problem: if `gh auth status` says `(keyring)`, the token
lives behind the D-Bus secret service, which the jail does not bind — so `gh`
inside is unauthenticated and `gh auth login` cannot fix it from there (it would
try the same keyring, and `ro .config/gh` is read-only besides). With
`--ssh-agent` you do not need it for pushes; for `gh pr create` you would have
to hand the jail a token via `env GH_TOKEN`, which *is* stealable — prefer
opening the PR from the host.

## Checking what a line actually did

A config file that merges with built-in lists and run flags is exactly the kind
of thing that is easy to get subtly wrong, and the failure is silent — a `mask`
line that does nothing looks identical to one that works.

`azkaban why` answers from the merged result:

```console
$ azkaban why --path ~/.config/gh --op read
  DENIED (read)
  mechanism: masked (empty tmpfs or empty file)
  matched:   maskPaths .config/gh

$ azkaban why --path ~/.config/gh --op read --ro .config/gh
  ALLOWED (read)
  matched:   rwPaths .config
```

The second is the documented un-masking opt-out, checked without editing the
file first. Add `--json` for a machine, or for an agent trying to work out why a
read failed.

## The run record

Every run writes one JSONL file to `$XDG_STATE_HOME/azkaban/audit/` unless you
say otherwise: `--no-audit` for one run, `audit off` in the config for good.
Only the literal word `off` disables it — a typo leaves the record on, which is
the direction a mistake should fail in.

It answers the question `--dry-run` cannot, because `--dry-run` is in the future
tense: *what did that run actually have access to, and what did it do?* The
resolved policy after the merge, the mode flags, the full bwrap command line,
every degradation that would otherwise have scrolled off your terminal, every
docker-filter decision, and the exit code. See
[design.md](design.md#what-a-run-actually-did).

Two things worth knowing before you point anything at those files:

- **`env NAME` is recorded by name, never by value.** The record says this run
  could see `ANTHROPIC_API_KEY`; it does not say what it was.
- **Command lines are scrubbed.** `--token abc` and a bare high-entropy
  argument both land as `<redacted>`. The heuristic errs towards redacting, so
  an ordinary argument occasionally disappears — that is the intended trade.

Nothing prunes the directory. One small file per run adds up on a machine that
runs the jail all day; a `find … -mtime +30 -delete` in a timer is the whole
answer, and inventing a retention policy inside the tool would be a second thing
to configure.

## Credential masking

Top-level hiding is deny-by-default — `~/.ssh` does not exist in the jail. But
`~/.config` is bound *wholesale* because tools need it, and on a normal dev box
that directory holds API tokens. The overlay stops those being destroyed; it does
nothing to stop them being read, and azkaban does not filter network egress.

So these are masked with an empty tmpfs or empty file, bound last so they win:

```
~/.config/gh            ~/.config/gcloud        ~/.config/doctl
~/.config/hub           ~/.config/git/credentials
~/.config/containers/auth.json                  ~/.docker/config.json
~/.local/share/keyrings
```

To keep one — say you genuinely want `gh` working in the jail — name it with
`ro` or `rw` and it is left alone. No extra syntax:

```
ro .config/gh
```

The flags un-mask identically, which is the better fit here: `azkaban --ro
.config/gh` hands over the token for one run instead of every run.

## Environment

The host environment is **cleared** by default; only `HOME`, `PATH`, `TERM`,
`LANG` and a few similar vars are forwarded. Inheriting it wholesale would hand a
prompt-injected agent every secret in your shell — `ANTHROPIC_API_KEY`,
`GITHUB_TOKEN`, `AWS_*` — and, worse, `SSH_AUTH_SOCK`: hiding `~/.ssh` achieves
nothing if the agent can still ask your ssh-agent to sign for it.

Allow what a tool actually needs by name (`env NAME`) rather than reopening the
whole environment with `--keep-env`.
