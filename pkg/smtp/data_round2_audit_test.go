package smtp

import (
	"bytes"
	"errors"
	"io"
	"net"
	"runtime"
	"strings"
	"testing"

	"github.com/emersion/go-smtp"
)

// C3: a body read error (the client stalled past the block timeout, or the
// upload ran into the session deadline) was returned raw. go-smtp maps any
// non-SMTPError to a permanent "554 Error: transaction failed: <err>", so the
// sending MTA bounced a message it should have retried, and the reply leaked
// the socket error text. The connection also stayed open with the stream
// position unknown: whatever body the client sent next would be read as SMTP
// commands.
func TestAudit_BodyReadErrorIsTemporaryAndClosesTheConnection(t *testing.T) {
	s := newAuthReplySession(t, "https://unused.invalid")
	s.commandState = stateRcpt
	server, client := net.Pipe()
	defer client.Close()
	s.netConn = server

	readErr := errors.New("read tcp 10.0.0.1:25->203.0.113.9:4444: i/o timeout")
	body := io.MultiReader(strings.NewReader("From: a@b.test\r\n\r\npartial"), errReader{readErr})

	_, err := s.readMessageData(body)

	var se *smtp.SMTPError
	if !errors.As(err, &se) {
		t.Fatalf("got %T (%v), want an *smtp.SMTPError so go-smtp does not answer 554", err, err)
	}
	if se.Code < 400 || se.Code > 499 {
		t.Errorf("reply code %d, want a temporary 4xx", se.Code)
	}
	if strings.Contains(se.Message, "10.0.0.1") || strings.Contains(se.Message, "read tcp") {
		t.Errorf("reply leaks the socket error: %q", se.Message)
	}
	if _, werr := server.Write([]byte("x")); !errors.Is(werr, io.ErrClosedPipe) {
		t.Errorf("connection still open after a body read error (write err = %v)", werr)
	}
}

// Deliberate replies from the reader (552 too large) and a BDAT transfer
// aborted by RSET must pass through untouched, on a connection left open.
func TestAudit_BodyReadSMTPErrorAndResetPassThrough(t *testing.T) {
	for _, want := range []error{smtp.ErrDataTooLarge, smtp.ErrDataReset} {
		s := newAuthReplySession(t, "https://unused.invalid")
		s.commandState = stateRcpt
		server, client := net.Pipe()
		s.netConn = server
		go func() { _, _ = io.Copy(io.Discard, client) }()

		_, err := s.readMessageData(io.MultiReader(bytes.NewReader([]byte("x")), errReader{want}))
		if err != want {
			t.Errorf("got %v, want %v returned as-is", err, want)
		}
		if _, werr := server.Write([]byte("x")); werr != nil {
			t.Errorf("%v: connection was closed (write err = %v)", want, werr)
		}
		client.Close()
	}
}

type errReader struct{ err error }

func (e errReader) Read([]byte) (int, error) { return 0, e.err }

// C10: the message was read into a bytes.Buffer on the session, and
// Buffer.Reset keeps the capacity. One large message - even one refused with
// 552 - left its buffer pinned for as long as the client kept the connection
// open: connection limit x largest message, held by idle sessions.
func TestAudit_SessionDoesNotRetainTheMessageBuffer(t *testing.T) {
	s := newAuthReplySession(t, "https://unused.invalid")
	s.commandState = stateRcpt

	heap := func() uint64 {
		var m runtime.MemStats
		runtime.GC()
		runtime.GC()
		runtime.ReadMemStats(&m)
		return m.HeapAlloc
	}

	const size = 16 << 20
	before := heap()
	msg, err := s.readMessageData(io.MultiReader(
		strings.NewReader("From: a@b.test\r\n\r\n"),
		io.LimitReader(zeroReader{}, size)))
	if err != nil || len(msg) < size {
		t.Fatalf("read %d bytes, err %v", len(msg), err)
	}
	msg = ""
	s.Reset()
	after := heap()

	if after > before && after-before > 1<<20 {
		t.Fatalf("idle session retains %d MiB after a %d MiB message", (after-before)>>20, size>>20)
	}
	runtime.KeepAlive(s)
	_ = msg
}

type zeroReader struct{}

func (zeroReader) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = 'x'
	}
	return len(p), nil
}
