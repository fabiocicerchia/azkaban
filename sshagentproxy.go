// sshagentproxy.go — a signing oracle with a policy, instead of one without.
//
// WHY THIS EXISTS: --ssh-agent binds $SSH_AUTH_SOCK straight into the jail, so
// ANYTHING inside can sign as you for the life of the run. Escape vector 10
// states it plainly and ends "there is no in-jail equivalent of `ssh-add -c`".
// This is that equivalent.
//
// The jail no longer sees the real agent. It gets a socket to a proxy in the
// outer process, which speaks the agent protocol (RFC 4251 framing, RFC 4252
// agent messages), forwards the two requests a git push actually needs, and
// refuses the rest:
//
//	REQUEST_IDENTITIES (11)  list the public keys — forwarded
//	SIGN_REQUEST       (13)  sign this blob      — forwarded, optionally confirmed
//	everything else          add, remove, lock, extensions — refused
//
// The refusals are the point. A bound agent socket lets the jail ADD a key it
// generated, REMOVE the ones you loaded, or LOCK the agent so your host shell
// stops working — none of which is anything a build needs, and all of which
// are reachable today with one `ssh-add` inside the jail.
//
// This is the same shape as dockerproxy.go and credentialbroker.go, and for
// the same reason: the kernel cannot see inside a unix socket, so a filter
// there has to be a process that speaks the protocol.
//
// WHAT IT IS NOT: a boundary against a determined attacker who already has
// code running as your user. Signing is still delegated, so a jail that is
// allowed one signature can use it for anything that signature authorizes.
// It narrows the grant from "everything an agent can do, unattended" to "the
// two operations git needs, optionally one prompt each", which is the
// difference the issue is about.
package main

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"
)

// Agent protocol message numbers. Only the ones this file names are ever
// forwarded; the list is deliberately an allowlist, so a message type added to
// the protocol after this was written is refused rather than relayed.
const (
	agentFailure           = 5
	agentRequestIdentities = 11
	agentSignRequest       = 13
)

// agentMaxMessage bounds one message. The protocol's own limit is 256 KiB and
// nothing legitimate comes close; an unbounded read here would let the jail
// make the outer process allocate whatever it liked.
const agentMaxMessage = 256 * 1024

// sshAgentProxy - The filtering agent, living in the outer process for the
// life of the run. With `confirm` set it asks on /dev/tty once per signature,
// which is `ssh-add -c` for a jail that cannot reach the host's own prompt.
type sshAgentProxy struct {
	upstream string // the real $SSH_AUTH_SOCK
	path     string // the socket the jail sees
	confirm  bool
	tty      *os.File

	mu       sync.Mutex
	listener net.Listener
	Signs    atomic.Int64
	Lists    atomic.Int64
	Refused  atomic.Int64
}

// newSSHAgentProxy - Binds the jail-facing socket. The directory is 0700 and
// the socket is created before the jail starts, so there is no window in which
// the path exists and is not ours.
func newSSHAgentProxy(upstream, dir string, confirm bool) (*sshAgentProxy, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	// Chmod as well as MkdirAll: MkdirAll leaves an existing directory's mode
	// alone, and a 0755 parent is a socket anyone on the box can connect to —
	// which is a signing oracle handed to every other user.
	if err := os.Chmod(dir, 0o700); err != nil {
		return nil, err
	}
	p := &sshAgentProxy{
		upstream: upstream,
		path:     filepath.Join(dir, "agent.sock"),
		confirm:  confirm,
	}
	_ = os.Remove(p.path)
	ln, err := net.Listen("unix", p.path)
	if err != nil {
		return nil, err
	}
	if err := os.Chmod(p.path, 0o600); err != nil {
		ln.Close()
		return nil, err
	}
	p.listener = ln
	if confirm {
		// Opened once, up front: discovering there is no tty at the moment of
		// the first signature would mean either hanging or silently allowing.
		if tty, err := os.OpenFile("/dev/tty", os.O_RDWR, 0); err == nil {
			p.tty = tty
		} else {
			ln.Close()
			return nil, errors.New("--ssh-agent-confirm needs a terminal to ask on")
		}
	}
	return p, nil
}

// serve - Accepts until the listener is closed. One goroutine per connection:
// ssh opens a fresh one per operation and closes it, so there is no long-lived
// multiplexing to get wrong.
func (p *sshAgentProxy) serve() {
	// Read once under the lock and used unlocked from there on: close() must be
	// able to run while this is blocked in Accept(), and it cannot do that if
	// the loop keeps reaching back into the struct.
	p.mu.Lock()
	ln := p.listener
	p.mu.Unlock()
	if ln == nil {
		return
	}
	for {
		conn, err := ln.Accept()
		if err != nil {
			return // closed, which is how the run ends
		}
		go p.handle(conn)
	}
}

// close - Ends the proxy and takes the socket with it. Idempotent: it runs from
// a defer and from the exit path.
func (p *sshAgentProxy) close() {
	p.mu.Lock()
	ln := p.listener
	p.listener = nil
	p.mu.Unlock()
	if ln != nil {
		ln.Close()
	}
	_ = os.Remove(p.path)
}

func (p *sshAgentProxy) stats() map[string]any {
	return map[string]any{
		"signatures": p.Signs.Load(),
		"listings":   p.Lists.Load(),
		"refused":    p.Refused.Load(),
	}
}

// handle - One connection from the jail. Each message is read whole, classified
// and either relayed to the real agent or answered with SSH_AGENT_FAILURE.
func (p *sshAgentProxy) handle(jail net.Conn) {
	defer jail.Close()
	// A tool that opens the socket and says nothing must not hold a goroutine
	// and an upstream connection for the life of the run.
	_ = jail.SetDeadline(time.Now().Add(2 * time.Minute))

	up, err := net.DialTimeout("unix", p.upstream, 5*time.Second)
	if err != nil {
		return
	}
	defer up.Close()

	for {
		msg, err := readAgentMessage(jail)
		if err != nil {
			return
		}
		if len(msg) == 0 {
			continue
		}
		allowed, kind := p.classify(msg)
		if !allowed {
			p.Refused.Add(1)
			if err := writeAgentMessage(jail, []byte{agentFailure}); err != nil {
				return
			}
			continue
		}
		switch kind {
		case agentSignRequest:
			p.Signs.Add(1)
		case agentRequestIdentities:
			p.Lists.Add(1)
		}
		_ = up.SetDeadline(time.Now().Add(2 * time.Minute))
		if err := writeAgentMessage(up, msg); err != nil {
			return
		}
		reply, err := readAgentMessage(up)
		if err != nil {
			return
		}
		if err := writeAgentMessage(jail, reply); err != nil {
			return
		}
	}
}

// classify - Whether this message is one of the two the jail may send, and
// which. Everything unrecognised is refused: an allowlist is the only shape
// that stays correct when the protocol grows a message this code has not read.
func (p *sshAgentProxy) classify(msg []byte) (bool, byte) {
	kind := msg[0]
	switch kind {
	case agentRequestIdentities:
		return true, kind
	case agentSignRequest:
		if p.confirm && !p.ask(msg) {
			return false, kind
		}
		return true, kind
	}
	return false, kind
}

// ask - One confirmation per signature, on /dev/tty. This is `ssh-add -c` for
// a jail that has no way to reach the host's own prompt.
//
// The key blob is shown truncated rather than the data being signed: the data
// is an opaque session identifier that means nothing to a human, and printing
// it would train people to skip the prompt.
func (p *sshAgentProxy) ask(msg []byte) bool {
	blob, _ := agentString(msg[1:])
	fmt.Fprintf(p.tty, "\nazkaban: the jail asked to SIGN with your ssh key (%s)\n"+
		"  allow this one signature? [y/N] ", fingerprintish(blob))
	answer := make([]byte, 8)
	n, err := p.tty.Read(answer)
	if err != nil || n == 0 {
		fmt.Fprintln(p.tty, "no answer, denied")
		return false
	}
	return answer[0] == 'y' || answer[0] == 'Y'
}

// fingerprintish - Enough of the key blob to tell two keys apart in a prompt.
// Deliberately not called a fingerprint: computing the real one means hashing
// the blob the way ssh-keygen does, and a wrong "SHA256:..." is worse than an
// honest prefix.
func fingerprintish(blob []byte) string {
	if len(blob) == 0 {
		return "unknown key"
	}
	kind, _ := agentString(blob) // the blob opens with its own key type string
	tail := blob
	if len(tail) > 8 {
		tail = tail[len(tail)-8:]
	}
	return fmt.Sprintf("%s …%x", string(kind), tail)
}

// ---- Framing ----

// readAgentMessage - One length-prefixed message. The length is a 32-bit
// big-endian count that does NOT include itself.
func readAgentMessage(r io.Reader) ([]byte, error) {
	var hdr [4]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, err
	}
	n := binary.BigEndian.Uint32(hdr[:])
	if n == 0 {
		return nil, nil
	}
	if n > agentMaxMessage {
		return nil, fmt.Errorf("agent message of %d bytes exceeds the %d limit", n, agentMaxMessage)
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(r, buf); err != nil {
		return nil, err
	}
	return buf, nil
}

func writeAgentMessage(w io.Writer, msg []byte) error {
	var hdr [4]byte
	binary.BigEndian.PutUint32(hdr[:], uint32(len(msg)))
	if _, err := w.Write(hdr[:]); err != nil {
		return err
	}
	_, err := w.Write(msg)
	return err
}

// agentString - The protocol's string type: a 32-bit length then that many
// bytes. Returns the contents and whatever follows, and an empty pair rather
// than an error on a short buffer — every caller here is producing a display
// string, and a malformed message is refused on its type byte anyway.
func agentString(b []byte) ([]byte, []byte) {
	if len(b) < 4 {
		return nil, nil
	}
	n := binary.BigEndian.Uint32(b[:4])
	if uint64(n) > uint64(len(b)-4) {
		return nil, nil
	}
	return b[4 : 4+n], b[4+n:]
}
