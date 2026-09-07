# Security Policy

## Supported Versions

| Version  | Supported |
| -------- | --------- |
| latest   | ✅        |
| < latest | ❌        |

## Reporting a Vulnerability

**Do not open a public issue for security problems.**

Report privately via [GitHub Security Advisories](https://github.com/fabiocicerchia/azkaban/security/advisories/new).

Please include a description, reproduction steps, and impact. We aim to
acknowledge within 48 hours and to ship a fix or mitigation as soon as
practical, keeping you updated along the way.

## Scope

azkaban confines a tool to a project directory. In scope: anything that lets a
process inside the jail read, write, or destroy a host path outside the project
directory and the `$HOME` allowlist, or that makes writes persist when the
default overlay says they should not.

**Out of scope — documented and deliberate.** The `KNOWN ESCAPE VECTORS` block
at the bottom of `main.go` lists what is intentionally left open, including
`--unfiltered-container-socket`, `--display` (which re-exposes ssh-agent and any rootless
container socket), `--keep-env`, `--persist`, and the absence of a network
namespace by default. Reports that restate those are not vulnerabilities; a
report that one of them is *worse than documented* is.

The filtering proxy in `dockerproxy.go` is a damage limiter, not an
authorization boundary — it blocks host binds outside cwd, `--privileged` and
friends, but the jail can still manipulate your existing containers.
