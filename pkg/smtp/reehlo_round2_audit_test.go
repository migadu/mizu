package smtp

import (
	"bufio"
	"context"
	"encoding/base64"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/emersion/go-sasl"
	gosmtp "github.com/emersion/go-smtp"
)

// reehloSession is the smallest session that requires AUTH before MAIL, the
// way a submission server does.
type reehloSession struct{ authed bool }

func (s *reehloSession) AuthMechanisms() []string { return []string{sasl.Plain} }
func (s *reehloSession) Auth(string) (sasl.Server, error) {
	return sasl.NewPlainServer(func(_, _, _ string) error { s.authed = true; return nil }), nil
}
func (s *reehloSession) Mail(context.Context, string, *gosmtp.MailOptions) error {
	if !s.authed {
		return &gosmtp.SMTPError{Code: 530, EnhancedCode: gosmtp.EnhancedCode{5, 7, 0}, Message: "authentication required"}
	}
	return nil
}
func (s *reehloSession) Rcpt(context.Context, string, *gosmtp.RcptOptions) error { return nil }
func (s *reehloSession) Data(context.Context, io.Reader) error                   { return nil }
func (s *reehloSession) Reset()                                                  {}
func (s *reehloSession) Logout() error                                           { return nil }

type reehloBackend struct{}

func (reehloBackend) NewSession(*gosmtp.Conn) (gosmtp.Session, error) { return &reehloSession{}, nil }

// C15: a second EHLO after AUTH replaced the backend session with a fresh,
// unauthenticated one while go-smtp kept its own "already authenticated"
// flag. MAIL then got 530 and AUTH got 503: the client had to reconnect.
// A client is allowed to greet again at any time (RFC 5321 section 4.1.4), and
// some do after AUTH. This pins the go-smtp fork behaviour Mizu depends on.
func TestAudit_ReEHLOAfterAuthDoesNotLockTheSessionOut(t *testing.T) {
	srv := gosmtp.NewServer(reehloBackend{})
	srv.Domain = "mx.example.com"
	srv.AllowInsecureAuth = true
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = srv.Serve(l) }()
	defer srv.Close()

	c, err := net.Dial("tcp", l.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(10 * time.Second))
	r := bufio.NewReader(c)

	// reply reads one (possibly multi-line) reply and returns its last line.
	reply := func() string {
		for {
			line, err := r.ReadString('\n')
			if err != nil {
				t.Fatalf("read: %v", err)
			}
			if len(line) >= 4 && line[3] == ' ' {
				return strings.TrimSpace(line)
			}
		}
	}
	send := func(cmd string) string {
		if _, err := c.Write([]byte(cmd + "\r\n")); err != nil {
			t.Fatalf("write %q: %v", cmd, err)
		}
		return reply()
	}

	reply() // banner
	send("EHLO client.example.org")
	creds := base64.StdEncoding.EncodeToString([]byte("\x00user@example.com\x00secret"))
	if got := send("AUTH PLAIN " + creds); !strings.HasPrefix(got, "235") {
		t.Fatalf("AUTH: %s", got)
	}
	if got := send("EHLO client.example.org"); !strings.HasPrefix(got, "250") {
		t.Fatalf("second EHLO: %s", got)
	}
	if got := send("MAIL FROM:<user@example.com>"); !strings.HasPrefix(got, "250") {
		t.Fatalf("MAIL after EHLO, AUTH, EHLO: %s - the session lost its login and cannot log in again", got)
	}
}
