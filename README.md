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

---

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
make build      # -> ./bin/azkaban
```

## Usage

```bash
CGO_ENABLED=0 go build -o azkaban .

cd /path/to/project      # NOT $HOME — azkaban refuses to make $HOME writable
azkaban claude           # or: azkaban -- <any command> [args...]
```

More in [`docs/getting-started.md`](docs/getting-started.md).

## Documentation

| Page | Covers |
|---|---|
| [design.md](docs/design.md) | The five layers in detail, plus the security model and deliberate omissions |
| [configuration.md](docs/configuration.md) | `~/.config/azkaban/config`, credential masking, environment allowlist |
| [containers.md](docs/containers.md) | Docker/podman sockets and the filtering proxy |
| [testing.md](docs/testing.md) | How the suite proves containment without risking a real home |

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
