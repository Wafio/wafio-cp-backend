package handlers

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/wafio/wafio-cp-backend/internal/application"
	wemail "github.com/wafio/wafio-cp-backend/shared/email"
)

type fakeInviteMail struct {
	state application.MailState
	sent  chan string
}

func (f *fakeInviteMail) Current(context.Context) (application.MailState, error) { return f.state, nil }

func (f *fakeInviteMail) SendHTML(_ context.Context, to, _, body string) error {
	f.sent <- to + "\n" + body
	return nil
}

// An invitation email carries an absolute link or is not sent: without a
// dashboard base URL the link is relative and would lead nowhere from a mail
// client.
func TestMailInviteNeedsAbsoluteLink(t *testing.T) {
	cases := []struct {
		name string
		link string
		send bool
	}{
		{"relative project link", "/invite/abc", false},
		{"relative sign-up link", "/register?token=abc", false},
		{"base without scheme", "demo.example.com/invite/abc", false},
		{"https", "https://demo.example.com/invite/abc", true},
		{"http", "http://10.0.0.5:9087/invite/abc", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			mail := &fakeInviteMail{state: application.MailState{Server: wemail.Config{Host: "smtp.example.com"}}, sent: make(chan string, 1)}
			h := &InviteHandler{Mail: mail}
			h.mailInvite(context.Background(), "user@example.com", "subject", tc.link, time.Now().Add(time.Hour))
			select {
			case got := <-mail.sent:
				if !tc.send {
					t.Fatalf("sent an email with link %q", tc.link)
				}
				if want := `href="` + tc.link + `"`; !strings.Contains(got, want) {
					t.Fatalf("email does not carry %s", want)
				}
			case <-time.After(200 * time.Millisecond):
				if tc.send {
					t.Fatalf("no email sent for link %q", tc.link)
				}
			}
		})
	}
}

// Without a mail server nothing is sent, whatever the link.
func TestMailInviteWithoutServer(t *testing.T) {
	mail := &fakeInviteMail{sent: make(chan string, 1)}
	h := &InviteHandler{Mail: mail}
	h.mailInvite(context.Background(), "user@example.com", "subject", "https://demo.example.com/invite/abc", time.Now().Add(time.Hour))
	select {
	case <-mail.sent:
		t.Fatal("sent without a mail server")
	case <-time.After(100 * time.Millisecond):
	}
}
