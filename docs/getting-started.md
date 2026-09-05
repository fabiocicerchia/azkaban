# Getting Started

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

```text
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
--ssh-agent    forward the agent + known_hosts so `git push` works, through a
               proxy that allows only "list keys" and "sign this". The keys stay
               on the host; the jail gets a signing oracle and nothing else. OFF
               by default, and ~/.ssh itself is still never bound.
               (--ssh-agent-confirm prompts per signature; --ssh-agent-raw binds
               the real socket unfiltered.)
--unix-socket PATH
               bind one unix socket and nothing around it (repeatable).
               --unix-socket-dir DIR for names generated at runtime.
--elevate      approve a denied READ on the terminal instead of losing the run.
               Landlock stays the floor; writes are never elevated.
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
