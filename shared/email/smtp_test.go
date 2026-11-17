package email

import (
	"errors"
	"net"
	"net/textproto"
	"strconv"
	"strings"
	"testing"
	"time"
)

// A CR or LF in any header value would let a caller-controlled string
// (the portal contact form puts the visitor's name in the subject) add headers
// or start the body early. Send and SendHTML must refuse before dialling.
func TestSendRejectsHeaderInjection(t *testing.T) {
	cfg := Config{Host: "127.0.0.1", Port: 1, From: "noreply@example.com"}
	cases := []struct {
		name, to, subject string
		cfg               Config
	}{
		{"subject CRLF", "a@example.com", "hi\r\nBcc: victim@example.com", cfg},
		{"subject LF", "a@example.com", "hi\nBcc: victim@example.com", cfg},
		{"subject CR", "a@example.com", "hi\rBcc: victim@example.com", cfg},
		{"to CRLF", "a@example.com\r\nBcc: victim@example.com", "hi", cfg},
		{"from CRLF", "a@example.com", "hi", Config{Host: "127.0.0.1", Port: 1, From: "x@example.com\r\nBcc: v@example.com"}},
		{"subject NUL", "a@example.com", "hi\x00there", cfg},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := Send(tc.cfg, tc.to, tc.subject, "body"); !errors.Is(err, ErrHeaderInjection) {
				t.Fatalf("Send err = %v, want ErrHeaderInjection", err)
			}
			if err := SendHTML(tc.cfg, tc.to, tc.subject, "<p>body</p>"); !errors.Is(err, ErrHeaderInjection) {
				t.Fatalf("SendHTML err = %v, want ErrHeaderInjection", err)
			}
			if err := SendText(tc.cfg, tc.to, tc.subject, "body"); !errors.Is(err, ErrHeaderInjection) {
				t.Fatalf("SendText err = %v, want ErrHeaderInjection", err)
			}
			if err := SendMail(tc.cfg.Host, tc.cfg.Port, "", "", tc.cfg.From, tc.to, tc.subject, "body", false); !errors.Is(err, ErrHeaderInjection) {
				t.Fatalf("SendMail err = %v, want ErrHeaderInjection", err)
			}
		})
	}
}

func TestValidateHeaderValue(t *testing.T) {
	if err := ValidateHeaderValue("[WAFio Sales] General Inquiry — Jane Doe"); err != nil {
		t.Fatalf("plain subject rejected: %v", err)
	}
	for _, bad := range []string{"a\rb", "a\nb", "a\r\nb", "a\x00b"} {
		if err := ValidateHeaderValue(bad); !errors.Is(err, ErrHeaderInjection) {
			t.Fatalf("ValidateHeaderValue(%q) = %v, want ErrHeaderInjection", bad, err)
		}
	}
}

// Body newlines are legitimate and must not trip the header check.
func TestBuildMessageKeepsBodyNewlines(t *testing.T) {
	msg, err := buildMessage("from@example.com", "to@example.com", "subj", "text/plain", "line1\r\nline2\n", false)
	if err != nil {
		t.Fatalf("buildMessage: %v", err)
	}
	want := "To: to@example.com\r\nSubject: subj\r\nContent-Type: text/plain; charset=UTF-8\r\n\r\nline1\r\nline2\n"
	if string(msg) != want {
		t.Fatalf("message = %q, want %q", msg, want)
	}
}

// A mail server that accepts the connection and never answers used to hold
// the sender forever (no deadline on dial or conversation). Every delivery
// now ends within Config.Timeout.
func TestSendTimesOutOnSilentServer(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	held := make(chan net.Conn, 4)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			held <- c // never written to
		}
	}()
	defer func() {
		for len(held) > 0 {
			(<-held).Close()
		}
	}()
	port := ln.Addr().(*net.TCPAddr).Port
	start := time.Now()
	err = SendText(Config{Host: "127.0.0.1", Port: port, From: "noreply@example.test", Mode: "none", Timeout: 300 * time.Millisecond}, "a@example.test", "hi", "body")
	if err == nil {
		t.Fatal("send to a silent server succeeded")
	}
	if took := time.Since(start); took > 5*time.Second {
		t.Fatalf("send took %v, want about the 300ms timeout", took)
	}
}

// fakeSMTP is a minimal SMTP server without STARTTLS or AUTH. It records the
// envelope and the message of the first transaction.
type fakeSMTP struct {
	addr string
	got  chan fakeMail
}

type fakeMail struct{ from, to, data string }

func newFakeSMTP(t *testing.T) *fakeSMTP {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	f := &fakeSMTP{addr: ln.Addr().String(), got: make(chan fakeMail, 1)}
	go f.serve(ln)
	return f
}

func (f *fakeSMTP) serve(ln net.Listener) {
	c, err := ln.Accept()
	if err != nil {
		return
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(10 * time.Second))
	tp := textproto.NewConn(c)
	var m fakeMail
	_ = tp.PrintfLine("220 fake ESMTP")
	for {
		line, err := tp.ReadLine()
		if err != nil {
			return
		}
		cmd := strings.ToUpper(line)
		switch {
		case strings.HasPrefix(cmd, "EHLO"), strings.HasPrefix(cmd, "HELO"):
			_ = tp.PrintfLine("250 fake")
		case strings.HasPrefix(cmd, "MAIL FROM:"):
			m.from = line[len("MAIL FROM:"):]
			_ = tp.PrintfLine("250 ok")
		case strings.HasPrefix(cmd, "RCPT TO:"):
			m.to = line[len("RCPT TO:"):]
			_ = tp.PrintfLine("250 ok")
		case cmd == "DATA":
			_ = tp.PrintfLine("354 go on")
			data, err := tp.ReadDotBytes()
			if err != nil {
				return
			}
			m.data = string(data)
			_ = tp.PrintfLine("250 queued")
			f.got <- m
		case cmd == "QUIT":
			_ = tp.PrintfLine("221 bye")
			return
		default:
			_ = tp.PrintfLine("502 no")
		}
	}
}

// SendText writes From, Date and MIME headers; the envelope sender is the
// bare address even when From carries a display name.
func TestSendTextDelivers(t *testing.T) {
	f := newFakeSMTP(t)
	host, portStr, _ := net.SplitHostPort(f.addr)
	port, _ := strconv.Atoi(portStr)
	cfg := Config{Host: host, Port: port, From: "Wafio <noreply@example.test>", Mode: "none"}
	if err := (Mailer{Config: cfg}).Send("user@example.test", "Reset your Wafio password", "line one\nline two\n"); err != nil {
		t.Fatalf("send: %v", err)
	}
	m := <-f.got
	if m.from != "<noreply@example.test>" || m.to != "<user@example.test>" {
		t.Fatalf("envelope from=%q to=%q", m.from, m.to)
	}
	for _, want := range []string{"From: Wafio <noreply@example.test>\n", "To: user@example.test\n", "Subject: Reset your Wafio password\n", "Date: ", "MIME-Version: 1.0\n", "Content-Type: text/plain; charset=UTF-8\n", "\nline one\nline two\n"} {
		if !strings.Contains(m.data, want) {
			t.Fatalf("message lacks %q:\n%s", want, m.data)
		}
	}
}

func TestResolveMode(t *testing.T) {
	cases := []struct {
		cfg  Config
		want string
	}{
		{Config{Port: 465}, "ssl"},
		{Config{Port: 465, Mode: "auto"}, "ssl"},
		{Config{Port: 587, Mode: "AUTO"}, "starttls"},
		{Config{Port: 2525}, "starttls"},
		{Config{Port: 25}, "none"},
		{Config{Port: 25, UseTLS: true}, "starttls"},
		{Config{Port: 25, Mode: "plain"}, "none"},
		{Config{Port: 587, Mode: "none"}, "none"},
		{Config{Port: 25, Mode: "smtps"}, "ssl"},
		{Config{Port: 25, Mode: "tls"}, "ssl"},
		{Config{Port: 25, Mode: "starttls"}, "starttls"},
		{Config{Port: 25, Mode: "bogus"}, "bogus"},
	}
	for _, tc := range cases {
		if got := resolveMode(tc.cfg); got != tc.want {
			t.Errorf("resolveMode(%+v) = %q, want %q", tc.cfg, got, tc.want)
		}
	}
	// An unknown mode is refused before any connection.
	if err := deliver(Config{Host: "127.0.0.1", Port: 1, Mode: "bogus"}, "bogus", nil, "a@example.test", "b@example.test", nil); err == nil || !strings.Contains(err.Error(), "invalid SMTP mode") {
		t.Fatalf("bogus mode: %v", err)
	}
}

func TestEnvelopeAddress(t *testing.T) {
	for in, want := range map[string]string{
		"Wafio <noreply@example.test>": "noreply@example.test",
		"noreply@example.test":         "noreply@example.test",
		"not an address":               "not an address",
	} {
		if got := envelopeAddress(in); got != want {
			t.Errorf("envelopeAddress(%q) = %q, want %q", in, got, want)
		}
	}
}
