# Container runtimes

[← README](../README.md)

**Nothing is bound unless you ask.** The socket is the one interface the jail
cannot police from inside — a bind mount requested over it is performed by the
*daemon*, on the host, outside bwrap and Landlock — so it is opt-in per run:

```bash
azkaban --bind-docker claude    # docker, behind the filtering proxy
azkaban --bind-podman claude    # podman's REST socket, same proxy

# unfiltered — no proxy in the path
azkaban --bind-docker --unfiltered-container-socket claude
azkaban --bind-podman --unfiltered-container-socket claude
```

`--unfiltered-container-socket` selects the *filtering*, not the runtime, so one
of the `--bind-*` flags is required alongside it. It deliberately does not imply
a runtime: handing over an unfiltered socket — quite possibly the rootful one —
should not be the thing that happens when you never named a runtime at all.

| Runtime | Status |
|---|---|
| docker (rootless) | supported, filtered |
| docker (rootful) | supported, filtered, warns loudly — the daemon is host root |
| podman | supported via its **Docker-compatible** API; the native `libpod` API is refused |
| containerd / nerdctl | **not offered** — gRPC, which this HTTP proxy cannot inspect |
| kubernetes | out of scope; `~/.kube` is not on any allowlist, keep it that way |

## Two layers of defence

The raw `/var/run/docker.sock` is host-root-equivalent: `docker run --privileged
-v /:/host` inside the jail is an instant escape.

**1. Run Docker rootless** so the daemon runs as your user — the socket→host-root
escalation becomes structurally impossible:

```bash
dockerd-rootless-setuptool.sh install
systemctl --user enable --now docker   # socket at /run/user/$UID/docker.sock
```

azkaban prefers the rootless socket automatically, and warns loudly if it has to
fall back to the rootful one.

**2. A filtering proxy** (`dockerproxy.go`) sits in front of the socket whenever
one is bound. Rootless alone does not close `-v /:/host`, which still reaches
your files as *your* user. The proxy is deny-by-default in three ways:

- **Endpoint allowlist.** `/swarm`, `/services`, `/plugins`, `/secrets` and
  friends are refused outright, because their bodies can carry host mounts the
  create-filter never sees.
- **Body filter** on container and volume create: rejects a host bind outside the
  project dir, `--privileged`, `--device`, dangerous `--cap-add`, relaxed
  `--security-opt`, and host `net`/`pid`/`ipc`/`userns`. It also catches the
  bind-in-disguise — a `local`-driver volume with a `device` option.
- **Destructive-call block.** `/prune` on any resource and `DELETE /volumes/…`
  are refused: a named volume has no git history and no trash behind it, and
  prune deletes in bulk across resources at once. `docker rm` and `rmi` stay
  allowed — containers and images are rebuildable, and blocking them would break
  `--rm` cleanup and every ordinary workflow.

It is **not** an authorization boundary for the rest of the API. The jail can
still start, `exec` into, and `rm` your **pre-existing** containers — including
any you created earlier with dangerous mounts.

## Why libpod is refused

Podman's native `/libpod/…` API is deliberately refused rather than merely
unimplemented. libpod's create schema puts mounts at the top level instead of
under `HostConfig`, so a libpod body deserialises into the filter's struct as "no
host config, nothing to check" and a request mounting `/` would be **allowed**.
The endpoint allowlist is what stops it. Adding `libpod` to that allowlist to
"support podman properly" would open a total bypass — `TestDockerFilter_LibpodAPIIsRefused`
pins this.

## The weak spot

Refusal here is only a missing bind mount, not a blocked syscall: a socket that
reaches the jail by some other route still works. `--display` binds the whole of
`$XDG_RUNTIME_DIR`, which is exactly where a rootless daemon puts its socket — so
do not combine `--display` with a rootless container daemon.
