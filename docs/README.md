# Documentation

- [design.md](design.md) — the five confinement layers, the security model, and
  the deliberate omissions.
- [configuration.md](configuration.md) — `~/.config/azkaban/config`, the
  `--ro`/`--rw` per-run equivalents, credential masking, environment allowlist.
- [containers.md](containers.md) — Docker/podman sockets and the filtering proxy.
- [testing.md](testing.md) — how the suite proves containment without risking a
  real home directory.
