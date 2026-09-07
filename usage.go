package main

import "fmt"

// usage - Prints the flag reference. Hand-written rather than generated from
// the FlagSet: the defaults are the security model, and each one needs a
// sentence saying what it costs to change it.
func usage() {
	fmt.Print(`azkaban [flags] [--] <command> [args...]

  --no-gpu       do not bind GPU devices (/dev/nvidia*, /dev/dri)
  --persist      let writes to $HOME allowlist dirs really land on disk. Default
                 is a throwaway overlay: the tool sees them writable, but writes
                 and deletes evaporate on exit and cannot destroy real data.
  --bind-docker  bind the docker socket behind the filtering proxy (OFF by
                 default; containerd is not offered — gRPC, which the proxy
                 cannot inspect)
  --bind-podman  same, for podman's Docker-compatible REST socket
  --unfiltered-container-socket
                 bind the socket with NO filtering at all. Says how to bind, not
                 which — pair it with --bind-docker or --bind-podman.
  --display      pass through X11/wayland/XAUTHORITY + the wayland/pulse sockets
                 from /run/user (OFF by default; ssh-agent, gpg-agent, dbus and
                 any rootless container socket in there stay hidden)
  --ssh-agent    forward the agent (+ known_hosts read-only) so git push over ssh
                 works. The jail talks to a FILTERING PROXY in the outer process
                 that forwards only "list keys" and "sign this" and refuses add,
                 remove, lock and extensions — so a tool inside can no longer
                 delete the keys you loaded or lock your host agent. The keys
                 stay on the host either way; the jail gets a signing oracle,
                 and that oracle still authenticates as you to every host they
                 open. OFF by default; ~/.ssh itself is never bound.
  --ssh-agent-confirm
                 ...and ask on the terminal before every signature. This is
                 "ssh-add -c" for a jail that cannot reach the host's prompt.
  --ssh-agent-raw
                 ...bind the REAL agent socket with no filter, the pre-proxy
                 behaviour. Anything in the jail can then add, remove or lock
                 your keys as well as sign with them.
  --unix-socket PATH
                 bind ONE unix socket, and nothing around it. For "this tool may
                 reach Postgres at /tmp/.s.PGSQL.5432" without granting /tmp.
                 Repeatable; connect and bind are not distinguished. For every
                 run, use "unix-socket" lines in the config.
  --unix-socket-dir DIR
                 same, for a directory whose socket names are generated at
                 runtime (PID-suffixed paths). Wider by exactly one directory,
                 which is why both exist. Repeatable.
  --allow-userns permit nested user namespaces (needed by Chrome/Electron tools)
  --no-net       isolate the network in a new namespace (breaks internet access)
  --net-ports L  allow outbound TCP only to these ports (comma-separated), enforced
                 by landlock. Blocks localhost services and LAN scanning. UDP and
                 therefore DNS are unaffected. Needs the landlock stage.
  --net-host H   allow outbound traffic only to this host, through a CONNECT
                 proxy in the outer process. Repeatable; "*.example.com" covers
                 subdomains but not the bare domain. TLS is NOT intercepted —
                 the target is checked and raw bytes relayed. Sets HTTPS_PROXY
                 in the jail and narrows --net-ports to the proxy, so a client
                 that ignores the variable is refused by the kernel rather than
                 connecting directly. Needs the landlock stage. For every run,
                 use "net <host>" lines in the config.
  --keep-env     inherit the whole host environment (default: clear it and pass
                 only HOME/PATH/TERM/LANG/...; add more with "env NAME" in
                 ~/.config/azkaban/config)
  --mem-max SIZE cap total memory with a cgroup (e.g. 8G). The overlay writes to
                 tmpfs, i.e. RAM, and this is the only thing that bounds it. Off
                 by default: a cap also disables swap for the jail, so a workload
                 that would have paged out is killed instead.
  --no-rlimits   do not cap file size / process count (default caps them; the
                 overlay writes to RAM, so a runaway write can OOM the host)
  --no-landlock  skip the landlock stage
  --ro PATH      bind one extra path read-only, this run only. Repeatable.
  --rw PATH      same, writable (still overlaid unless --persist). Repeatable.
                 $HOME-relative; / and $HOME are refused; un-masks any credential
                 store named. For every run, use "ro"/"rw" lines in the config.
  --persist-path PATH
                 exempt ONE path from the throwaway overlay: writes to it land on
                 the host, everything else still evaporates. For the file a tool
                 must keep across runs (a login token) without --persist making
                 the whole allowlist destroyable. Repeatable; name the file, not
                 its directory. For every run, use "persist" lines in the config.
  --credential P allow the jail to use a host credential WITHOUT giving it the
                 secret: it talks plain HTTP to a loopback broker, which attaches
                 the real token and makes the TLS connection itself. "github" is
                 the only provider so far; add " write" to permit push, which the
                 default read-only policy refuses. Repeatable. For every run, use
                 "credential <provider>" lines in the config.
  --rollback     snapshot the writable $HOME roots either side of the run and
                 let writes land FOR REAL, so destruction becomes a diff to
                 review rather than a loss. An alternative to the default
                 throwaway overlay, not a layer on it. Review and undo with
                 "azkaban rollback show|restore".
  --elevate      let a denied READ be approved on the terminal instead of ending
                 the run. A seccomp supervisor in the outer process traps opens,
                 asks you about any path outside the allowlist, and hands back a
                 read-only descriptor it opened itself — so a grant is bounded by
                 your own permissions and cannot exceed them. Landlock stays the
                 floor: anything the supervisor does not answer is denied by the
                 kernel as usual. Writes are never elevated. OFF by default, and
                 rate-limited to 10 prompts/s so a tool in a loop cannot wear you
                 down. Needs the landlock stage.
  --dry-run      print the bwrap command instead of running it
  --no-guidance  do not describe the jail to the tool inside it. By default
                 /run/azkaban holds a read-only policy.json, a README, a Claude
                 Code PostToolUse hook and this binary, so a confused agent can
                 run "azkaban why --self" instead of guessing at an error.
  --no-audit     do not record this run. Every run is otherwise written as JSONL
                 to $XDG_STATE_HOME/azkaban/audit/ — the resolved policy, the
                 mode flags, every degradation, every docker-filter decision and
                 the exit code. "audit off" in the config turns it off for good.
  -h, --help     this help

  azkaban why    explain what the jail would do with one path, host or port,
                 without starting one. "azkaban why -h" for its flags.
  azkaban rollback  list, review and undo what a --rollback run changed.
`)
}
