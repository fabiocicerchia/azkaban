// Runtime capability elevation: approve a denied path instead of losing the run.
//
// Landlock is applied once and is irreversible, which is what makes it worth
// trusting and also what makes every denial terminal. The only recovery from
// "the tool needed one path nobody anticipated" was to kill the run, widen the
// allowlist and start over — which pushes people towards pre-emptively wide
// allowlists, the opposite of the point.
//
// This is a seccomp user-notification layer ABOVE the Landlock floor, off
// unless --elevate is passed. A BPF filter traps openat/openat2 with
// SECCOMP_RET_USER_NOTIF; the trusted OUTER process reads the notification,
// and either lets the syscall fall through to Landlock or — with a human's
// answer on the terminal — opens the file itself and injects the descriptor.
//
// TWO PROPERTIES MAKE THIS A GATE RATHER THAN A HOLE:
//
//   - ORDERING. seccomp runs at syscall entry, before the LSM hooks Landlock
//     installs. If this supervisor has a bug and fails to inject, the syscall
//     falls through and Landlock denies it. The static floor catches the
//     dynamic layer's failures, never the other way round.
//   - BOUNDED GRANT. The supervisor opens the file as the user who ran
//     azkaban, under ordinary Unix permissions. It cannot hand the jail
//     anything the user could not already read.
//
// SECCOMP_USER_NOTIF_FLAG_CONTINUE IS NEVER USED TO AUTHORIZE. Continuing a
// syscall after checking a path is a textbook TOCTOU: the path is resolved
// twice and the second resolution is the one that counts. It is used here for
// the opposite purpose — "I am not elevating this, let the floor decide" — for
// which it is exactly right, because the decision is then made by Landlock on
// the path the kernel itself resolves. Every actual grant goes through
// SECCOMP_IOCTL_NOTIF_ADDFD, where the descriptor the jail receives is one the
// supervisor opened and can name.
//
// DELIBERATE NARROWING: read-only. An approval yields an O_RDONLY descriptor
// and a write intent is never elevated. A supervisor-opened write descriptor
// would bypass not only Landlock but the overlay, so --elevate plus a mistyped
// path would write to the real file on the host — which is the accident this
// whole tool exists to prevent. Reads are also what the restart loop is
// actually about: a config file, a CA bundle, a toolchain under a path nobody
// listed.
package main

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

// ---- Constants the kernel headers have and x/sys does not ----

const (
	// SECCOMP_FILTER_FLAG_NEW_LISTENER makes seccomp(2) return a listener fd
	// instead of 0. That fd is this whole mechanism.
	seccompSetModeFilter = 1
	seccompFilterNewList = 8
	seccompRetUserNotif  = 0x7fc00000
	seccompRetAllow      = 0x7fff0000
	seccompNotifContinue = 1 // SECCOMP_USER_NOTIF_FLAG_CONTINUE
	seccompAddfdSend     = 2 // answer the notification in the same ioctl

	// _IOWR('!', 0, struct seccomp_notif) and friends. Spelled out rather than
	// computed: the sizes are ABI, and a wrong one is a silent EINVAL.
	ioctlNotifRecv    = 0xc0502100
	ioctlNotifSend    = 0xc0182101
	ioctlNotifIDValid = 0x40082102
	ioctlNotifAddfd   = 0x40182103
)

// elevateFDEnv names the descriptor the inner stage sends its listener back
// on. Set by the outer stage as a bwrap --setenv like every other channel
// between the two roles, so --dry-run prints it.
const elevateFDEnv = "AZKABAN_ELEVATE_FD"

// elevateSockFD is where bwrap's fd 4 lands: fd 3 is already the --args file,
// and ExtraFiles is appended to in the same order.
const elevateSockFD = 4

// ---- The filter ----

type sockFilter struct {
	code uint16
	jt   uint8
	jf   uint8
	k    uint32
}

type sockFprog struct {
	length uint16
	_      [6]byte
	filter *sockFilter
}

// auditArch - AUDIT_ARCH_* for the architecture this binary was built for. A
// notification carries the caller's arch, and a filter that ignored it would
// be comparing syscall numbers against a different table.
func auditArch() (uint32, bool) {
	switch runtime.GOARCH {
	case "amd64":
		return 0xc000003e, true // AUDIT_ARCH_X86_64
	case "arm64":
		return 0xc00000b7, true // AUDIT_ARCH_AARCH64
	}
	return 0, false
}

// openSyscalls - The two numbers this traps, per architecture. openat2 is 437
// everywhere; openat is not.
func openSyscalls() (uint32, uint32) {
	if runtime.GOARCH == "arm64" {
		return 56, 437
	}
	return 257, 437
}

// elevationFilter - The BPF program. Ten instructions, and the shape matters:
// every path that is not one of the two open syscalls on this exact
// architecture returns ALLOW, so a filter that cannot understand what it is
// looking at gets out of the way and leaves the decision to Landlock.
func elevationFilter() []sockFilter {
	arch, _ := auditArch()
	openat, openat2 := openSyscalls()
	const (
		ld  = 0x20 // BPF_LD|BPF_W|BPF_ABS
		jeq = 0x15 // BPF_JMP|BPF_JEQ|BPF_K
		jge = 0x35 // BPF_JMP|BPF_JGE|BPF_K
		ret = 0x06 // BPF_RET|BPF_K
	)
	return []sockFilter{
		{ld, 0, 0, 4},                    // 0: A = arch
		{jeq, 1, 0, arch},                // 1: ours -> 3, else -> 2
		{ret, 0, 0, seccompRetAllow},     // 2: foreign arch, not ours to police
		{ld, 0, 0, 0},                    // 3: A = syscall nr
		{jge, 0, 1, 0x40000000},          // 4: x32 ABI -> 5, else -> 6
		{ret, 0, 0, seccompRetAllow},     // 5:
		{jeq, 2, 0, openat},              // 6: -> 9
		{jeq, 1, 0, openat2},             // 7: -> 9
		{ret, 0, 0, seccompRetAllow},     // 8: everything else
		{ret, 0, 0, seccompRetUserNotif}, // 9: trap
	}
}

// installElevationFilter - Installs the filter and returns the listener.
// Called from the INNER stage, immediately before Landlock: the ordering is
// the safety property, so where this is called from is part of the design and
// not an implementation detail.
func installElevationFilter() (int, error) {
	if _, ok := auditArch(); !ok {
		return -1, fmt.Errorf("no seccomp filter for GOARCH=%s", runtime.GOARCH)
	}
	// Required to install a filter without CAP_SYS_ADMIN, and required anyway:
	// it is what stops a setuid binary inside the jail escaping the filter.
	if err := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
		return -1, fmt.Errorf("no_new_privs: %w", err)
	}
	prog := elevationFilter()
	fp := sockFprog{length: uint16(len(prog)), filter: &prog[0]}
	fd, _, errno := unix.Syscall(unix.SYS_SECCOMP,
		seccompSetModeFilter, seccompFilterNewList, uintptr(unsafe.Pointer(&fp)))
	runtime.KeepAlive(prog)
	if errno != 0 {
		// EBUSY is WSL2, which reports the syscall and then refuses a listener.
		return -1, fmt.Errorf("seccomp: %w", errno)
	}
	return int(fd), nil
}

// ---- Passing the listener out of the jail ----

// sendListener - Hands the listener to the outer stage over the socketpair end
// bwrap inherited. SCM_RIGHTS is the only way out: the inner stage is in its
// own pid namespace, so the supervisor cannot go and fetch it.
func sendListener(sockFD, listener int) error {
	// One byte of payload: a zero-length message is not guaranteed to carry
	// the ancillary data through.
	return unix.Sendmsg(sockFD, []byte{'L'}, unix.UnixRights(listener), nil, 0)
}

// recvListener - The outer half. Blocks until the inner stage has installed
// its filter, which is also the signal that the jail is up.
func recvListener(sockFD int) (int, error) {
	buf := make([]byte, 1)
	oob := make([]byte, unix.CmsgSpace(4))
	_, oobn, _, _, err := unix.Recvmsg(sockFD, buf, oob, 0)
	if err != nil {
		return -1, err
	}
	msgs, err := unix.ParseSocketControlMessage(oob[:oobn])
	if err != nil || len(msgs) == 0 {
		return -1, fmt.Errorf("no listener in message: %v", err)
	}
	fds, err := unix.ParseUnixRights(&msgs[0])
	if err != nil || len(fds) == 0 {
		return -1, fmt.Errorf("no listener in message: %v", err)
	}
	return fds[0], nil
}

// ---- Notifications ----

// seccompData mirrors struct seccomp_data. Field order is ABI.
type seccompData struct {
	NR                 int32
	Arch               uint32
	InstructionPointer uint64
	Args               [6]uint64
}

type seccompNotif struct {
	ID    uint64
	Pid   uint32
	Flags uint32
	Data  seccompData
}

type seccompNotifResp struct {
	ID    uint64
	Val   int64
	Error int32
	Flags uint32
}

type seccompNotifAddfd struct {
	ID         uint64
	Flags      uint32
	SrcFD      uint32
	NewFD      uint32
	NewFDFlags uint32
}

func notifIoctl(fd int, req uintptr, arg unsafe.Pointer) error {
	_, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(fd), req, uintptr(arg))
	if errno != 0 {
		return errno
	}
	return nil
}

func recvNotif(listener int) (*seccompNotif, error) {
	for {
		// Zeroed before every RECV: the kernel checks that the reserved bytes
		// are clear and returns EINVAL if they are not.
		n := seccompNotif{}
		err := notifIoctl(listener, ioctlNotifRecv, unsafe.Pointer(&n))
		if errors.Is(err, unix.EINTR) {
			continue
		}
		if err != nil {
			return nil, err
		}
		return &n, nil
	}
}

// notifStillValid - Whether the traced process is still waiting on this
// notification. Every read of another process's memory has to be followed by
// this: a pid can be recycled between the notification and the read, and this
// is the only way to learn that the answer came out of the wrong process.
func notifStillValid(listener int, id uint64) bool {
	return notifIoctl(listener, ioctlNotifIDValid, unsafe.Pointer(&id)) == nil
}

func respondError(listener int, id uint64, errno syscall.Errno) error {
	resp := seccompNotifResp{ID: id, Error: -int32(errno)}
	return notifIoctl(listener, ioctlNotifSend, unsafe.Pointer(&resp))
}

// respondContinue - "Not elevating this one." The kernel re-enters the syscall
// normally, so Landlock makes the decision, on the path the kernel itself
// resolves. This is the safe use of CONTINUE and the only one here; see the
// file header for why it is never used the other way.
func respondContinue(listener int, id uint64) error {
	resp := seccompNotifResp{ID: id, Flags: seccompNotifContinue}
	return notifIoctl(listener, ioctlNotifSend, unsafe.Pointer(&resp))
}

// injectFD - The grant. ADDFD with FLAG_SEND installs the descriptor in the
// target and answers the notification in one ioctl, so there is no window in
// which the fd exists and the syscall has not yet returned it.
func injectFD(listener int, id uint64, src int) error {
	a := seccompNotifAddfd{ID: id, Flags: seccompAddfdSend, SrcFD: uint32(src)}
	return notifIoctl(listener, ioctlNotifAddfd, unsafe.Pointer(&a))
}

// ---- Reading the request ----

const maxPathLen = 4096

// readPath - Reads a NUL-terminated path out of the target's address space.
// /proc/<pid>/mem rather than process_vm_readv only because the short read at
// the end of a mapping is easier to get right with a file.
func readPath(pid uint32, addr uint64) (string, error) {
	f, err := os.Open(fmt.Sprintf("/proc/%d/mem", pid))
	if err != nil {
		return "", err
	}
	defer f.Close()
	buf := make([]byte, maxPathLen)
	n, err := f.ReadAt(buf, int64(addr))
	if n == 0 && err != nil {
		return "", err
	}
	if i := bytes.IndexByte(buf[:n], 0); i >= 0 {
		return string(buf[:i]), nil
	}
	return "", errors.New("path is not NUL-terminated within 4096 bytes")
}

// openHow mirrors struct open_how, the argument openat2 takes by pointer.
type openHow struct {
	Flags   uint64
	Mode    uint64
	Resolve uint64
}

// readOpenHow - openat2 passes its flags indirectly and versions the struct by
// size, so a short one is normal and means "the rest is zero".
func readOpenHow(pid uint32, addr uint64, size uint64) (openHow, error) {
	var how openHow
	if size < 8 {
		return how, errors.New("open_how too small to carry flags")
	}
	f, err := os.Open(fmt.Sprintf("/proc/%d/mem", pid))
	if err != nil {
		return how, err
	}
	defer f.Close()
	buf := make([]byte, 24)
	if size < 24 {
		buf = buf[:size]
	}
	if n, err := f.ReadAt(buf, int64(addr)); n < 8 && err != nil {
		return how, err
	}
	return openHow{Flags: le64(buf, 0), Mode: le64(buf, 8), Resolve: le64(buf, 16)}, nil
}

func le64(b []byte, off int) uint64 {
	if off+8 > len(b) {
		return 0
	}
	var v uint64
	for i := 7; i >= 0; i-- {
		v = v<<8 | uint64(b[off+i])
	}
	return v
}

// wantsWrite - Whether an open could change anything. Deliberately generous:
// O_RDONLY with no creation flags is the only shape this will elevate, and
// anything it cannot classify counts as a write.
func wantsWrite(flags uint64) bool {
	const (
		accMode = 0x3
		rdOnly  = 0
		create  = 0x40
		trunc   = 0x200
		appnd   = 0x400
		tmpfile = 0x410000
	)
	if flags&accMode != rdOnly {
		return true
	}
	return flags&(create|trunc|appnd|tmpfile) != 0
}

// ---- Approval ----

// request - What the human is being asked about. Carries the pid so a prompt
// can name the process, and the raw argument so a path that resolved somewhere
// surprising is visible as such.
type request struct {
	Pid  uint32
	Raw  string
	Path string
}

// approver - Where a decision comes from. An interface because the terminal is
// the only backend today and obviously not the last one: a webhook, a policy
// file and a "deny everything and log it" backend are all this shape.
type approver interface {
	approve(request) bool
	// name is what the audit log records as the source of a decision.
	name() string
}

// terminalApprover - Asks on /dev/tty, not on stdin. stdin belongs to the tool
// in the jail: a prompt reading from it would eat the agent's input, and one
// reading from a piped stdin would answer itself.
type terminalApprover struct {
	tty     *os.File
	mu      sync.Mutex
	tokens  float64
	filled  time.Time
	nowFn   func() time.Time
	rate    float64 // tokens per second
	burst   float64
	blocked bool // no tty: every request is denied, and said once
	said    bool
}

// Rate limit taken from nono's. A tool in a loop can generate thousands of
// denied opens a second, and a prompt storm is both unusable and a way to get
// a human to approve something by exhausting them.
const (
	approvalRate  = 10
	approvalBurst = 5
)

func newTerminalApprover() *terminalApprover {
	a := &terminalApprover{
		tokens: approvalBurst, rate: approvalRate, burst: approvalBurst,
		nowFn: time.Now,
	}
	a.filled = a.nowFn()
	tty, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
	if err != nil {
		a.blocked = true
		return a
	}
	a.tty = tty
	return a
}

func (a *terminalApprover) name() string { return "terminal" }

// take - Token bucket. Returns false when the caller is asking too fast, and
// that is answered as a denial rather than a wait: a tool opening the same
// missing file in a loop must not be able to stall the jail behind a queue of
// prompts nobody will ever read.
func (a *terminalApprover) take() bool {
	now := a.nowFn()
	a.tokens += now.Sub(a.filled).Seconds() * a.rate
	if a.tokens > a.burst {
		a.tokens = a.burst
	}
	a.filled = now
	if a.tokens < 1 {
		return false
	}
	a.tokens--
	return true
}

func (a *terminalApprover) approve(r request) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.blocked {
		if !a.said {
			a.said = true
			fmt.Fprintln(os.Stderr,
				"azkaban: --elevate needs a terminal to ask on; denying every request")
		}
		return false
	}
	if !a.take() {
		fmt.Fprintf(a.tty, "azkaban: too many requests, denying %s\n", r.Path)
		return false
	}
	fmt.Fprintf(a.tty, "\nazkaban: the jail (pid %d) asked to READ a path outside the allowlist:\n"+
		"    %s\n", r.Pid, r.Path)
	if r.Raw != r.Path {
		fmt.Fprintf(a.tty, "  asked for: %s\n", r.Raw)
	}
	fmt.Fprint(a.tty, "  allow reads of this path? [y/N] ")
	answer := make([]byte, 8)
	n, err := a.tty.Read(answer)
	if err != nil || n == 0 {
		fmt.Fprintln(a.tty, "no answer, denied")
		return false
	}
	return answer[0] == 'y' || answer[0] == 'Y'
}

// ---- The supervisor ----

// elevator - The trusted half. It lives in the outer process for the whole
// run, because the kernel turns every trapped syscall into ENOSYS the moment
// the last listener is closed: a supervisor that exits early does not fail
// open, it breaks every open in the jail.
type elevator struct {
	listener int
	allow    []string // the static allowlist, for suppressing pointless prompts
	approver approver
	audit    auditSink

	mu       sync.Mutex
	decided  map[string]bool // path -> granted, so a loop asks once
	stopped  bool
	grants   int
	denials  int
	passthru int
}

// auditSink is the one method this needs from the run log, named so the
// elevator can be tested without one.
type auditSink interface {
	event(string, map[string]any)
}

// decidedMax bounds the decision cache. A tool in a loop asking for one path
// is the case this exists for; ten thousand distinct paths is a different
// problem, and must not become a memory leak in the trusted process.
const decidedMax = 1024

func newElevator(listener int, allow []string, ap approver) *elevator {
	return &elevator{
		listener: listener, allow: allow, approver: ap,
		decided: map[string]bool{},
	}
}

// underAllowlist - Whether the path is already inside the static policy.
//
// Getting this wrong is not a security bug in either direction, which is why
// it is allowed to be this simple: a false positive means CONTINUE and
// Landlock decides, a false negative means one prompt too many.
func (e *elevator) underAllowlist(p string) bool {
	for _, a := range e.allow {
		if a == "" {
			continue
		}
		if p == a || strings.HasPrefix(p, strings.TrimSuffix(a, "/")+"/") {
			return true
		}
	}
	return false
}

// serve - The notification loop. Runs until the listener is closed, which
// happens when the jail has exited.
func (e *elevator) serve() {
	for {
		n, err := recvNotif(e.listener)
		if err != nil {
			return // ENOENT/EBADF: the jail is gone
		}
		e.handle(n)
	}
}

// handle - One trapped open. Every branch that is not a grant answers
// CONTINUE, so the failure mode of this function is "azkaban behaves as if
// --elevate had not been passed".
func (e *elevator) handle(n *seccompNotif) {
	openat, _ := openSyscalls()
	dirfd := int32(n.Data.Args[0])

	raw, err := readPath(n.Pid, n.Data.Args[1])
	flags := n.Data.Args[2]
	if err == nil && uint32(n.Data.NR) != openat { // openat2 passes flags by pointer
		var how openHow
		how, err = readOpenHow(n.Pid, n.Data.Args[2], n.Data.Args[3])
		flags = how.Flags
	}
	// Read first, validate after: between the notification and the read the
	// process could have died and its pid been reused, and the answer would
	// then be about somebody else's memory.
	if err != nil || !notifStillValid(e.listener, n.ID) {
		e.pass(n.ID)
		return
	}

	path, ok := e.resolve(n.Pid, dirfd, raw)
	switch {
	case !ok, e.underAllowlist(path):
		// Either we cannot say where this points, or it is inside the policy
		// already. Both are the floor's business.
		e.pass(n.ID)
		return
	case wantsWrite(flags):
		// Never asked, never granted: a supervisor-opened write descriptor
		// would bypass the overlay as well as Landlock. Continued rather than
		// refused, so the outcome is whatever the floor would have said.
		e.pass(n.ID)
		return
	}

	granted, seen := e.recall(path)
	if !seen {
		granted = e.approver.approve(request{Pid: n.Pid, Raw: raw, Path: path})
		e.remember(path, granted)
		if e.audit != nil {
			e.audit.event("elevation", map[string]any{
				"path": path, "granted": granted, "pid": n.Pid,
				"source": e.approver.name(),
			})
		}
	}
	if !granted {
		_ = respondError(e.listener, n.ID, unix.EPERM)
		e.count(&e.denials)
		return
	}

	fd, err := openForJail(path)
	if err != nil {
		// Approved, but the supervisor cannot open it either. EACCES rather
		// than EPERM so the difference between "refused" and "not yours to
		// give" survives into the jail's error message.
		_ = respondError(e.listener, n.ID, unix.EACCES)
		e.count(&e.denials)
		return
	}
	defer unix.Close(fd)
	if err := injectFD(e.listener, n.ID, fd); err != nil {
		_ = respondError(e.listener, n.ID, unix.EPERM)
		e.count(&e.denials)
		return
	}
	e.count(&e.grants)
}

func (e *elevator) pass(id uint64) {
	_ = respondContinue(e.listener, id)
	e.count(&e.passthru)
}

// resolve - Where the target meant. AT_FDCWD resolves through /proc/<pid>/cwd;
// a relative path against a real dirfd does NOT resolve, and returns false so
// the floor decides. Fetching another process's descriptor to resolve against
// is a whole mechanism — pidfd_getfd, and the races that come with it — for a
// case that is almost always the project directory, which is in the allowlist
// already.
func (e *elevator) resolve(pid uint32, dirfd int32, raw string) (string, bool) {
	if strings.HasPrefix(raw, "/") {
		return filepath.Clean(raw), true
	}
	if dirfd != unix.AT_FDCWD {
		return "", false
	}
	cwd, err := os.Readlink(fmt.Sprintf("/proc/%d/cwd", pid))
	if err != nil {
		return "", false
	}
	return filepath.Clean(filepath.Join(cwd, raw)), true
}

// openForJail - Opens the approved path, as the user, read-only.
//
// RESOLVE_NO_SYMLINKS is what makes the prompt honest: the path a human
// approved has to be the path that is opened, and a symlink swapped in between
// the prompt and the open is the classic way to make it not be. It costs the
// ability to approve a path that legitimately runs through a symlink, which is
// the right way round for a security prompt. RESOLVE_NO_MAGICLINKS
// additionally refuses /proc/<pid>/fd/N, which would otherwise be a way to ask
// for one name and receive something else entirely. O_CREAT and O_TRUNC are
// never passed, so this can only ever hand back something that already exists.
func openForJail(path string) (int, error) {
	how := unix.OpenHow{
		Flags:   uint64(unix.O_RDONLY | unix.O_CLOEXEC),
		Resolve: unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS,
	}
	return unix.Openat2(unix.AT_FDCWD, path, &how)
}

func (e *elevator) recall(p string) (bool, bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	v, ok := e.decided[p]
	return v, ok
}

func (e *elevator) remember(p string, granted bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if len(e.decided) >= decidedMax {
		// Dropped whole rather than one entry: an LRU here would be more code
		// than the thing it protects, and re-asking is a correct if annoying
		// outcome.
		e.decided = map[string]bool{}
	}
	e.decided[p] = granted
}

func (e *elevator) count(n *int) {
	e.mu.Lock()
	*n++
	e.mu.Unlock()
}

// stats - What the run log records when the jail exits. A dynamic layer whose
// decisions were not written down is not auditable, which is the one thing the
// static lists have going for them.
func (e *elevator) stats() map[string]any {
	e.mu.Lock()
	defer e.mu.Unlock()
	return map[string]any{
		"granted": e.grants, "denied": e.denials, "passed_to_landlock": e.passthru,
	}
}

// close - Drops the listener. Called only once the jail has exited: doing it
// earlier turns every open inside into ENOSYS.
func (e *elevator) close() {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.stopped {
		return
	}
	e.stopped = true
	unix.Close(e.listener)
}
