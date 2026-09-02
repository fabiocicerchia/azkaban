package main

import (
	"encoding/binary"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// fakeAgent - A stand-in for ssh-agent that records what actually reached it.
// The point of the proxy is that some messages never do, and only an upstream
// that counts can prove that.
type fakeAgent struct {
	path string
	ln   net.Listener
	seen chan byte
}

func startFakeAgent(t *testing.T) *fakeAgent {
	t.Helper()
	dir := t.TempDir()
	a := &fakeAgent{path: filepath.Join(dir, "upstream.sock"), seen: make(chan byte, 32)}
	ln, err := net.Listen("unix", a.path)
	if err != nil {
		t.Fatal(err)
	}
	a.ln = ln
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				for {
					msg, err := readAgentMessage(c)
					if err != nil || len(msg) == 0 {
						return
					}
					a.seen <- msg[0]
					// 12 is SSH_AGENT_IDENTITIES_ANSWER; any non-failure reply
					// is enough to prove the round trip.
					_ = writeAgentMessage(c, []byte{12, 0, 0, 0, 0})
				}
			}()
		}
	}()
	return a
}

func startProxy(t *testing.T, upstream string, confirm bool) *sshAgentProxy {
	t.Helper()
	p, err := newSSHAgentProxy(upstream, t.TempDir(), confirm)
	if err != nil {
		t.Fatal(err)
	}
	go p.serve()
	t.Cleanup(p.close)
	return p
}

// agentAsk sends one message through the proxy and returns the first byte of the
// reply, which is the message type.
func agentAsk(t *testing.T, p *sshAgentProxy, msg []byte) byte {
	t.Helper()
	c, err := net.DialTimeout("unix", p.path, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(2 * time.Second))
	if err := writeAgentMessage(c, msg); err != nil {
		t.Fatal(err)
	}
	reply, err := readAgentMessage(c)
	if err != nil {
		t.Fatal(err)
	}
	if len(reply) == 0 {
		t.Fatal("empty reply")
	}
	return reply[0]
}

// ---- What the jail may do ----

func TestListingAndSigningReachTheRealAgent(t *testing.T) {
	up := startFakeAgent(t)
	p := startProxy(t, up.path, false)

	for _, kind := range []byte{agentRequestIdentities, agentSignRequest} {
		if got := agentAsk(t, p, []byte{kind}); got == agentFailure {
			t.Fatalf("message %d was refused; git cannot work without it", kind)
		}
		select {
		case saw := <-up.seen:
			if saw != kind {
				t.Fatalf("upstream saw %d, want %d", saw, kind)
			}
		case <-time.After(2 * time.Second):
			t.Fatalf("message %d never reached the agent", kind)
		}
	}
	if p.Lists.Load() != 1 || p.Signs.Load() != 1 {
		t.Fatalf("counted %d listings and %d signatures, want 1 each",
			p.Lists.Load(), p.Signs.Load())
	}
}

// ---- What it may not ----

func TestTheJailCannotAddRemoveOrLockYourKeys(t *testing.T) {
	up := startFakeAgent(t)
	p := startProxy(t, up.path, false)

	// 17 ADD_IDENTITY, 18 REMOVE_IDENTITY, 19 REMOVE_ALL_IDENTITIES,
	// 22 LOCK, 23 UNLOCK, 27 EXTENSION. Every one of these is reachable today
	// with one `ssh-add` inside a jail that has the socket bound.
	for _, kind := range []byte{17, 18, 19, 22, 23, 27, 25, 0, 255} {
		if got := agentAsk(t, p, []byte{kind}); got != agentFailure {
			t.Errorf("message %d got %d, want SSH_AGENT_FAILURE", kind, got)
		}
	}
	select {
	case saw := <-up.seen:
		t.Fatalf("message %d reached the real agent", saw)
	case <-time.After(200 * time.Millisecond):
	}
	if p.Refused.Load() != 9 {
		t.Fatalf("counted %d refusals, want 9", p.Refused.Load())
	}
}

func TestAnUnknownMessageIsRefusedRatherThanRelayed(t *testing.T) {
	up := startFakeAgent(t)
	p := startProxy(t, up.path, false)
	// The list is an allowlist so that a message type added to the protocol
	// after this was written is refused, not waved through.
	if got := agentAsk(t, p, []byte{200, 1, 2, 3}); got != agentFailure {
		t.Fatalf("a message this code has never heard of got %d, want failure", got)
	}
}

// ---- Framing ----

func TestAnOversizedMessageIsRefusedBeforeItIsAllocated(t *testing.T) {
	p := startProxy(t, "/nonexistent", false)
	c, err := net.DialTimeout("unix", p.path, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	// A 4 GiB length prefix with no body: an unbounded reader would try to
	// allocate it in the OUTER process, which is the trusted one.
	var hdr [4]byte
	binary.BigEndian.PutUint32(hdr[:], 0xffffffff)
	if _, err := c.Write(hdr[:]); err != nil {
		t.Fatal(err)
	}
	_ = c.SetDeadline(time.Now().Add(2 * time.Second))
	if _, err := readAgentMessage(c); err == nil {
		t.Fatal("the proxy answered an unbounded message")
	}
}

func TestFramingRoundTrips(t *testing.T) {
	up := startFakeAgent(t)
	c, err := net.Dial("unix", up.path)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	payload := append([]byte{agentRequestIdentities}, make([]byte, 5000)...)
	if err := writeAgentMessage(c, payload); err != nil {
		t.Fatal(err)
	}
	if _, err := readAgentMessage(c); err != nil {
		t.Fatalf("a 5 KB message did not survive the framing: %v", err)
	}
}

// ---- The socket itself ----

func TestTheJailFacingSocketIsNotReadableByOtherUsers(t *testing.T) {
	up := startFakeAgent(t)
	p := startProxy(t, up.path, false)
	fi, err := os.Stat(p.path)
	if err != nil {
		t.Fatal(err)
	}
	if mode := fi.Mode().Perm(); mode&0o077 != 0 {
		t.Fatalf("socket mode %o lets somebody else sign as you", mode)
	}
	dir, err := os.Stat(filepath.Dir(p.path))
	if err != nil {
		t.Fatal(err)
	}
	if mode := dir.Mode().Perm(); mode&0o077 != 0 {
		t.Fatalf("socket directory mode %o", mode)
	}
}

func TestClosingRemovesTheSocketPath(t *testing.T) {
	up := startFakeAgent(t)
	p := startProxy(t, up.path, false)
	p.close()
	if _, err := os.Stat(p.path); err == nil {
		t.Fatal("the socket outlived the run")
	}
	// Idempotent: close runs from a defer and from the exit path.
	p.close()
}

// ---- The prompt ----

func TestTheKeyLabelSurvivesAMalformedRequest(t *testing.T) {
	// The prompt is built from jail-controlled bytes, so it has to cope with a
	// truncated or lying length prefix rather than panicking in the trusted
	// process.
	for _, blob := range [][]byte{
		nil,
		{0, 0, 0, 99}, // says 99 bytes follow, nothing does
		{0, 0, 0, 7, 's', 's', 'h', '-', 'r', 's', 'a'},
		{0xff, 0xff, 0xff, 0xff},
	} {
		if got := fingerprintish(blob); got == "" {
			t.Errorf("blob %v produced an empty label", blob)
		}
	}
}

func TestAgentStringRefusesALyingLengthPrefix(t *testing.T) {
	if s, _ := agentString([]byte{0, 0, 0, 10, 'a', 'b'}); s != nil {
		t.Fatalf("read %q past the end of the buffer", s)
	}
}
