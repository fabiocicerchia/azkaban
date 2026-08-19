# CLAUDE.md

Guidance for Claude Code (and other AI agents) working in this repo.

## Project

azkaban is a jail for AI CLIs: it confines a coding agent to a single project
directory with [bubblewrap](https://github.com/containers/bubblewrap) and
[Landlock](https://docs.kernel.org/userspace-api/landlock.html), so a tool that
misreads a path cannot read `~/.ssh` or `rm -rf` a home directory. Go, no cgo,
one static binary with two roles: the outer stage builds the bwrap invocation,
and `--landlock-exec` is the inner stage that applies Landlock and execs the
command. The whole security model is two files — `main.go` and
`dockerproxy.go` — and **being small enough to read in one sitting is the
product**; a feature that costs that readability costs more than it is worth.

The threat is accidental destruction, not a determined attacker. Network
isolation is secondary and off by default, because an agent that cannot reach
the internet is not much use. Every default is arranged around that priority:
the damaging case needs an explicit flag.

## Commands

```sh
make help        # every verb this repo exposes
make setup       # Install the pre-commit hook
make version     # Print the version make would stamp
make deps        # Download and verify module dependencies
make build       # Build the jail (static / CGO-free)
make install     # Install the jail into GOBIN
make run         # Run the jail (pass args with ARGS="...")
make clean       # Remove build output and coverage artifacts
make lint        # Run all pre-commit checks on the whole tree
make fmt         # Format
make tidy        # Tidy go.mod/go.sum
make audit       # Threat-sweep this tree with audit.sh
make test        # Run the test suite
make test-docker # ...including the docker-socket integration tests
make cover       # Run tests and write a coverage profile
```

## The bind lists are the security model

The `rwPaths`, `roPaths`, `roFreeze`, `maskPaths` and `displaySockets` lists at
the top of `main.go` are not configuration — they are the whole of what the
jail allows. Treat a change to one of them the way you would treat a change to
a firewall rule:

- Every entry is attack surface. Adding one needs a stated reason for why the
  tool genuinely cannot work without it, in the comment next to it.
- `roFreeze` is re-bound read-only *after* the rw list on purpose: a writable
  parent must not be usable to rewrite the jail's own bind list.
- `maskPaths` exists because `~/.config` is bound whole and holds API tokens.
  The overlay stops them being destroyed, not read.
- `--dry-run` prints the resulting bwrap command verbatim. That output is the
  audit trail; keep it copy-pasteable.
- The `KNOWN ESCAPE VECTORS` block at the bottom of `main.go` is the published
  list of what is deliberately left open. Keep it honest and current.

## Tooling

- `make setup` installs the pre-commit hook, and that is the whole of it.
  Don't add a `.githooks/` directory: `core.hooksPath` replaces `.git/hooks/`
  wholesale, so setting it silently stops every pre-commit hook from running.
- Hooks and actions are pinned by commit SHA with the tag in a trailing
  comment. A tag can be moved, a SHA cannot.
- CI runs this same `.pre-commit-config.yaml` through `pre-commit/action`, so
  what passes locally is what gates the pull request.
- `CGO_ENABLED=0` is exported by the Makefile: the binary has to be static, and
  the tests have to build the way CI and users build. That is also why there is
  no `-race` target.
- `-count=1` on every test target. These tests probe the live kernel —
  Landlock, namespaces, mounts — so a cached pass against unchanged sources
  proves nothing.

## Conventions

- Match existing style; don't reformat unrelated code. `gofmt` is
  non-negotiable.
- Doc comments read `// Name - Description.` and explain *why*, not what.
- Section banners (`// ---- Config ----`) mark the seams; the banner sequence
  is the file's table of contents.
- Conventional Commits for messages (see CONTRIBUTING.md).
- Update `docs/` with behaviour changes — `design.md` for the layers,
  `configuration.md` for `~/.config/azkaban/config`, `containers.md` for the
  socket proxy.
- Never commit secrets; CI runs gitleaks. Keep `.env` out of git.

## Guardrails

- This is a sandbox: changes to the bind lists, the bwrap flags, the Landlock
  ruleset or the docker filter directly change the containment guarantee.
  They are security-sensitive, never routine refactors.
- Prefer stdlib. `go-landlock` and `golang.org/x/sys` are the only two
  dependencies and both are load-bearing.
- The docker filter is deny-by-default on the create endpoints. A request body
  it cannot parse is refused, not waved through.
- Nothing in the jail may be able to write what configures the jail.
- Don't touch generated files or `coverage.out` by hand.
- Ask before large refactors or destructive operations.
