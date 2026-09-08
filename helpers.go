package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

// Helpers.

// --------------------------------------------------------------------------- //
// Helpers.
// --------------------------------------------------------------------------- //

// writeHosts - Copies /etc/hosts and makes sure the jail's own hostname
// resolves, since --unshare-uts + --hostname would otherwise leave it
// unresolvable.
func writeHosts() string {
	data, err := os.ReadFile("/etc/hosts")
	if err != nil {
		// The jail gets a hosts file with its own name and nothing else, which
		// is survivable -- but it is not what the caller's /etc/hosts says.
		fmt.Fprintln(os.Stderr, "azkaban: warning: cannot read /etc/hosts ("+err.Error()+
			"); the jail gets only its own hostname")
	}
	out := string(data)
	if !strings.Contains(out, " "+jailHostname) && !strings.Contains(out, "\t"+jailHostname) {
		out += "\n127.0.0.1 " + jailHostname
	}
	return tempWith("azkaban-hosts-", out)
}

// writeResolv - Copies the REAL resolv.conf. /run is an empty tmpfs inside the
// jail, which breaks the usual /etc/resolv.conf -> /run/.../stub-resolv.conf
// symlink, so a concrete copy has to be re-provided.
func writeResolv() string {
	real, err := filepath.EvalSymlinks("/etc/resolv.conf")
	if err != nil {
		real = "/etc/resolv.conf"
	}
	data, err := os.ReadFile(real)
	if err != nil {
		// An empty resolv.conf inside the jail reads as "the network is
		// broken" rather than "azkaban could not copy your resolver".
		fmt.Fprintln(os.Stderr, "azkaban: warning: cannot read "+real+" ("+err.Error()+
			"); the jail will have no resolver")
	}
	return tempWith("azkaban-resolv-", string(data))
}

// warnTIOCSTI - Flags the terminal-injection vector when the kernel permits it.
// Kernels >= 6.2 gate TIOCSTI behind dev.tty.legacy_tiocsti (default 0); on
// older kernels the knob is absent and the ioctl always works.
func warnTIOCSTI() {
	b, err := os.ReadFile("/proc/sys/dev/tty/legacy_tiocsti")
	if err == nil && strings.TrimSpace(string(b)) == "0" {
		return
	}
	if fi, err := os.Stdin.Stat(); err != nil || fi.Mode()&os.ModeCharDevice == 0 {
		return // not on a terminal, nothing to inject into
	}
	auditLog.degraded("tiocsti-permissive",
		"this kernel allows TIOCSTI; the jail shares your terminal and can inject commands your shell runs after it exits. "+
			"Close it host-wide with: sysctl -w dev.tty.legacy_tiocsti=0")
}

// Resource caps. The default overlay puts writes in a tmpfs, i.e. in RAM, which
// turns a runaway write from "fills the disk" into "exhausts memory and the OOM
// killer starts shooting". A confused agent in a write loop is precisely the
// threat this tool exists for, so cap what one process can produce.
//
// KNOWN LIMITATION: RLIMIT_FSIZE is per-FILE. A loop creating many small files
// still fills the overlay. bwrap's --size applies only to --tmpfs, not
// --tmp-overlay, so there is no clean total cap; this raises the bar, it does
// not close the hole. --persist avoids it entirely by writing to real disk.
const (
	maxFileSize = 4 << 30 // 4 GiB — big enough for build artifacts and images
	maxProcs    = 4096    // forkbomb guard; per-UID, so keep it generous
	maxFiles    = 8192    // fd exhaustion, incl. flooding the docker proxy
)

// applyRlimits - Sets the per-process caps above on this process, so bwrap and
// everything it spawns inherit them. An existing hard limit that is already
// lower wins: raising it would be a privilege the caller did not ask for.
func applyRlimits() {
	for _, l := range []struct {
		res  int
		cur  uint64
		name string
	}{
		{unix.RLIMIT_FSIZE, maxFileSize, "RLIMIT_FSIZE"},
		{unix.RLIMIT_NPROC, maxProcs, "RLIMIT_NPROC"},
		{unix.RLIMIT_CORE, 0, "RLIMIT_CORE"}, // core dumps would fill the overlay
		{unix.RLIMIT_NOFILE, maxFiles, "RLIMIT_NOFILE"},
	} {
		var old unix.Rlimit
		if unix.Getrlimit(l.res, &old) == nil && old.Max != 0 && old.Max < l.cur {
			continue // an existing lower hard limit is already stricter; leave it
		}
		rl := unix.Rlimit{Cur: l.cur, Max: l.cur}
		if err := unix.Setrlimit(l.res, &rl); err != nil {
			fmt.Fprintln(os.Stderr, "azkaban: warning: could not set "+l.name+": "+err.Error())
		}
	}
}
