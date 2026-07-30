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
env ANTHROPIC_API_KEY       # forward one host variable
mask .config/mytool/token   # blank out a path azkaban does not know about
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
