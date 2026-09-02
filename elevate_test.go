package main

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// The BPF filter is the part with no second chance: it is loaded once, in a
// process that is about to become the user's tool, and a wrong jump offset
// either traps everything (deadlock) or nothing (silently no feature). These
// walk it the way the kernel does.

// runFilter - Interprets the program against one seccomp_data, returning the
// action. Twenty lines of interpreter is cheaper than trusting the offsets.
func runFilter(prog []sockFilter, arch, nr uint32) uint32 {
	var a uint32
	for pc := 0; pc < len(prog); {
		in := prog[pc]
		switch in.code {
		case 0x20: // ld [k]
			if in.k == 0 {
				a = nr
			} else {
				a = arch
			}
			pc++
		case 0x15: // jeq
			if a == in.k {
				pc += 1 + int(in.jt)
			} else {
				pc += 1 + int(in.jf)
			}
		case 0x35: // jge
			if a >= in.k {
				pc += 1 + int(in.jt)
			} else {
				pc += 1 + int(in.jf)
			}
		case 0x06: // ret
			return in.k
		default:
			panic("unknown opcode")
		}
	}
	panic("fell off the end of the program")
}

func TestFilterTrapsOnlyTheTwoOpenSyscalls(t *testing.T) {
	prog := elevationFilter()
	arch, ok := auditArch()
	if !ok {
		t.Skip("no filter for this GOARCH")
	}
	openat, openat2 := openSyscalls()

	for _, nr := range []uint32{openat, openat2} {
		if got := runFilter(prog, arch, nr); got != seccompRetUserNotif {
			t.Errorf("syscall %d: got %#x, want a trap", nr, got)
		}
	}
	// Everything else has to pass, including the neighbours of openat: a filter
	// that traps read() or close() deadlocks the jail against its supervisor.
	for _, nr := range []uint32{0, 1, 2, 3, 59, 257 - 1, 257 + 1, 436, 438, 999} {
		if nr == openat || nr == openat2 {
			continue
		}
		if got := runFilter(prog, arch, nr); got != seccompRetAllow {
			t.Errorf("syscall %d: got %#x, want ALLOW", nr, got)
		}
	}
}

func TestFilterIgnoresAForeignArchitecture(t *testing.T) {
	prog := elevationFilter()
	openat, _ := openSyscalls()
	// A 32-bit caller's openat is a different number in the same slot. Trapping
	// it would supervise the wrong syscall entirely; Landlock still covers it.
	if got := runFilter(prog, 0x40000003 /* AUDIT_ARCH_I386 */, openat); got != seccompRetAllow {
		t.Errorf("i386 openat: got %#x, want ALLOW", got)
	}
}

func TestFilterIgnoresTheX32ABI(t *testing.T) {
	arch, _ := auditArch()
	if arch != 0xc000003e {
		t.Skip("x32 is an x86_64 concern")
	}
	openat, _ := openSyscalls()
	if got := runFilter(elevationFilter(), arch, openat|0x40000000); got != seccompRetAllow {
		t.Errorf("x32 openat: got %#x, want ALLOW", got)
	}
}

// ---- What counts as a write ----

func TestOnlyAPlainReadIsEverElevated(t *testing.T) {
	cases := []struct {
		name  string
		flags uint64
		write bool
	}{
		{"O_RDONLY", 0, false},
		{"O_RDONLY|O_CLOEXEC", 0x80000, false},
		{"O_WRONLY", 1, true},
		{"O_RDWR", 2, true},
		{"O_RDONLY|O_CREAT", 0x40, true},
		{"O_RDONLY|O_TRUNC", 0x200, true},
		{"O_RDONLY|O_APPEND", 0x400, true},
		{"O_TMPFILE", 0x410000, true},
	}
	for _, c := range cases {
		if got := wantsWrite(c.flags); got != c.write {
			t.Errorf("%s: wantsWrite=%v want %v", c.name, got, c.write)
		}
	}
}

// ---- Allowlist matching ----

func TestAllowlistMatchesOnPathComponents(t *testing.T) {
	e := newElevator(-1, []string{"/home/u/project", "/usr/lib/"}, nil)
	yes := []string{"/home/u/project", "/home/u/project/go.mod", "/usr/lib/x/y"}
	no := []string{"/home/u/project-secrets", "/home/u", "/usr/libexec/x", "/etc/shadow"}
	for _, p := range yes {
		if !e.underAllowlist(p) {
			t.Errorf("%s should be inside the policy", p)
		}
	}
	for _, p := range no {
		// A sibling directory whose name merely starts the same way is the
		// classic prefix-match bug, and here it would silence a prompt.
		if e.underAllowlist(p) {
			t.Errorf("%s should not be inside the policy", p)
		}
	}
}

// ---- The approval backend ----

type fixedApprover struct {
	say   bool
	asked []request
}

func (f *fixedApprover) approve(r request) bool { f.asked = append(f.asked, r); return f.say }
func (f *fixedApprover) name() string           { return "test" }

func TestTheRateLimiterDeniesRatherThanQueues(t *testing.T) {
	now := time.Unix(0, 0)
	a := &terminalApprover{
		tokens: approvalBurst, rate: approvalRate, burst: approvalBurst,
		nowFn: func() time.Time { return now },
	}
	a.filled = now
	for i := range approvalBurst {
		if !a.take() {
			t.Fatalf("burst token %d refused", i)
		}
	}
	if a.take() {
		t.Fatal("the bucket handed out more than its burst")
	}
	// A tenth of a second is one token back at 10/s.
	now = now.Add(110 * time.Millisecond)
	if !a.take() {
		t.Fatal("the bucket did not refill")
	}
}

func TestWithoutATerminalEveryRequestIsDenied(t *testing.T) {
	a := &terminalApprover{blocked: true}
	if a.approve(request{Path: "/etc/shadow"}) {
		t.Fatal("a headless run must not be able to approve anything")
	}
}

// ---- The decision cache ----

func TestOnePathIsOnlyEverAskedAboutOnce(t *testing.T) {
	ap := &fixedApprover{say: false}
	e := newElevator(-1, nil, ap)
	for range 50 {
		granted, seen := e.recall("/etc/shadow")
		if !seen {
			granted = ap.approve(request{Path: "/etc/shadow"})
			e.remember("/etc/shadow", granted)
		}
		if granted {
			t.Fatal("a denial came back as a grant")
		}
	}
	if len(ap.asked) != 1 {
		t.Fatalf("asked %d times; a tool in a loop would make this a prompt storm", len(ap.asked))
	}
}

func TestTheDecisionCacheIsBounded(t *testing.T) {
	e := newElevator(-1, nil, nil)
	for i := range decidedMax + 10 {
		e.remember(fmt.Sprintf("/p/%d", i), false)
	}
	if len(e.decided) > decidedMax {
		t.Fatalf("cache grew to %d, past its %d bound", len(e.decided), decidedMax)
	}
}

// ---- Opening on the jail's behalf ----

func TestAnApprovedOpenIsReadOnlyAndRefusesASymlink(t *testing.T) {
	dir := t.TempDir()
	real := filepath.Join(dir, "real")
	if err := os.WriteFile(real, []byte("secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	fd, err := openForJail(real)
	if err != nil {
		t.Fatalf("open the real path: %v", err)
	}
	defer unix.Close(fd)
	if _, err := unix.Write(fd, []byte("x")); err == nil {
		t.Fatal("the descriptor handed to the jail was writable")
	}

	// The path a human approved has to be the path that is opened. A symlink
	// swapped in between the prompt and the open is how that stops being true.
	link := filepath.Join(dir, "link")
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}
	if fd, err := openForJail(link); err == nil {
		unix.Close(fd)
		t.Fatal("a symlinked path was opened; RESOLVE_NO_SYMLINKS is not in effect")
	}
}

func TestAnApprovedOpenNeverCreatesTheFile(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "not-there")
	if fd, err := openForJail(missing); err == nil {
		unix.Close(fd)
		t.Fatal("opening a missing path succeeded, so O_CREAT leaked in")
	}
	if _, err := os.Stat(missing); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("the file exists now; the supervisor created it")
	}
}

// ---- Resolution ----

func TestARelativePathAgainstARealDirfdIsLeftToLandlock(t *testing.T) {
	e := newElevator(-1, nil, nil)
	if _, ok := e.resolve(uint32(os.Getpid()), 7, "config"); ok {
		t.Fatal("resolved against a dirfd we never fetched")
	}
	if p, ok := e.resolve(uint32(os.Getpid()), unix.AT_FDCWD, "go.mod"); !ok {
		t.Fatal("AT_FDCWD did not resolve")
	} else if !strings.HasSuffix(p, "/go.mod") {
		t.Fatalf("resolved to %q", p)
	}
	if p, _ := e.resolve(0, 0, "/etc/../etc/hosts"); p != "/etc/hosts" {
		t.Fatalf("absolute path not cleaned: %q", p)
	}
}

// ---- End to end, against this kernel ----

// The whole mechanism, minus bwrap and Landlock: a child installs the filter,
// sends the listener over a socketpair, and opens a path. The supervisor in
// this process decides. This is the test that would have caught a wrong ioctl
// number, a wrong struct size or a filter that traps the wrong syscall.
//
// Re-executes the test binary with AZKABAN_TEST_TRAPPED set, which is why
// there is a helper test below rather than a helper binary.
func TestTheJailReceivesADescriptorItCouldNotHaveOpened(t *testing.T) {
	requireUserNotif(t)

	secret := filepath.Join(t.TempDir(), "outside-the-allowlist")
	if err := os.WriteFile(secret, []byte("granted"), 0o600); err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct {
		name   string
		say    bool
		expect string
	}{
		{"approved", true, "granted"},
		{"denied", false, "operation not permitted"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ap := &fixedApprover{say: tc.say}
			out, err := runTrappedChild(t, secret, ap)
			if !strings.Contains(out, tc.expect) {
				t.Fatalf("child said %q (err %v), want %q", out, err, tc.expect)
			}
			if len(ap.asked) != 1 {
				t.Fatalf("supervisor was asked %d times, want 1", len(ap.asked))
			}
			if ap.asked[0].Path != secret {
				t.Fatalf("asked about %q, want %q", ap.asked[0].Path, secret)
			}
		})
	}
}

// TestAPathInsideThePolicyIsNeverPromptedAbout proves the CONTINUE path: the
// syscall is re-entered normally and nobody is asked. It is the common case by
// several orders of magnitude, and a bug here would make the feature unusable
// rather than unsafe.
func TestAPathInsideThePolicyIsNeverPromptedAbout(t *testing.T) {
	requireUserNotif(t)

	dir := t.TempDir()
	inside := filepath.Join(dir, "in-policy")
	if err := os.WriteFile(inside, []byte("ordinary"), 0o600); err != nil {
		t.Fatal(err)
	}
	ap := &fixedApprover{say: false}
	out, err := runTrappedChild(t, inside, ap, dir)
	if !strings.Contains(out, "ordinary") {
		t.Fatalf("child said %q (err %v); an in-policy read was interfered with", out, err)
	}
	if len(ap.asked) != 0 {
		t.Fatalf("prompted %d times for a path already in the allowlist", len(ap.asked))
	}
}

// runTrappedChild - Re-executes this test binary as the "inner stage", supervises
// it, and returns what it printed.
func runTrappedChild(t *testing.T, path string, ap approver, allow ...string) (string, error) {
	t.Helper()
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM, 0)
	if err != nil {
		t.Fatal(err)
	}
	parent := os.NewFile(uintptr(fds[0]), "sup")
	child := os.NewFile(uintptr(fds[1]), "jail")
	defer parent.Close()

	c := exec.Command(os.Args[0], "-test.run=TestHelperTrappedChild", "-test.v=false")
	c.Env = append(os.Environ(), "AZKABAN_TEST_TRAPPED="+path, elevateFDEnv+"=3")
	c.ExtraFiles = []*os.File{child}
	out, errPipe := c.StdoutPipe()
	if errPipe != nil {
		t.Fatal(errPipe)
	}
	c.Stderr = os.Stderr
	if err := c.Start(); err != nil {
		t.Fatal(err)
	}
	child.Close()

	listener, err := recvListener(int(parent.Fd()))
	if err != nil {
		_ = c.Process.Kill()
		t.Fatalf("no listener came back: %v", err)
	}
	e := newElevator(listener, allow, ap)
	done := make(chan struct{})
	go func() { e.serve(); close(done) }()

	buf := make([]byte, 4096)
	n, _ := out.Read(buf)
	runErr := c.Wait()
	e.close()
	<-done
	return strings.TrimSpace(string(buf[:n])), runErr
}

// TestHelperTrappedChild is the inner stage. It is a test only so it can be
// re-executed from the test binary; it does nothing unless the environment
// says it is the child.
func TestHelperTrappedChild(t *testing.T) {
	path := os.Getenv("AZKABAN_TEST_TRAPPED")
	if path == "" {
		t.Skip("helper; runs only as a child of the end-to-end test")
	}
	listener, err := installElevationFilter()
	if err != nil {
		fmt.Println("filter:", err)
		os.Exit(0)
	}
	if err := sendListener(3, listener); err != nil {
		fmt.Println("send:", err)
		os.Exit(0)
	}
	unix.Close(listener) // the supervisor holds the only copy from here on

	// From this point every open in this process goes through the supervisor.
	data, err := os.ReadFile(path)
	if err != nil {
		fmt.Println(err)
		os.Exit(0)
	}
	fmt.Println(string(data))
	os.Exit(0)
}

func requireUserNotif(t *testing.T) {
	t.Helper()
	if os.Getenv("AZKABAN_TEST_TRAPPED") != "" {
		t.Skip("already the child")
	}
	// Cheapest possible probe: try to install the filter in a throwaway child.
	// Containers, WSL2 and old kernels all fail here, and none of them is a
	// reason to fail the suite.
	c := exec.Command(os.Args[0], "-test.run=TestHelperProbe")
	c.Env = append(os.Environ(), "AZKABAN_TEST_PROBE=1")
	if err := c.Run(); err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) && ee.ExitCode() == 3 {
			t.Skip("seccomp user notification unavailable here")
		}
		t.Skipf("probe failed: %v", err)
	}
}

func TestHelperProbe(t *testing.T) {
	if os.Getenv("AZKABAN_TEST_PROBE") == "" {
		t.Skip("helper; runs only as a probe child")
	}
	fd, err := installElevationFilter()
	if err != nil {
		os.Exit(3)
	}
	unix.Close(fd)
	os.Exit(0)
}

// ---- Responses ----

func TestErrnoIsSentBackNegatedAsTheKernelExpects(t *testing.T) {
	// The kernel takes a NEGATIVE errno in seccomp_notif_resp.error, and a
	// positive one is read as a return VALUE — the difference between "denied"
	// and "open() returned fd 1".
	resp := seccompNotifResp{ID: 1, Error: -int32(syscall.EPERM)}
	if resp.Error >= 0 {
		t.Fatal("errno was not negated")
	}
}
