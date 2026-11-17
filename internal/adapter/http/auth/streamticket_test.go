package auth

import (
	"errors"
	"strings"
	"testing"
	"time"
)

const ticketSecret = "stream-ticket-test-secret-32-chars!!"

func newTestTickets(now *time.Time) *StreamTickets {
	s := NewStreamTickets(ticketSecret)
	s.now = func() time.Time { return *now }
	return s
}

func TestStreamTicketRedeemsOnceForItsScope(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	s := newTestTickets(&now)
	ticket, exp, err := s.Issue("user-1", "u@example.test", "user", "project-1", "host")
	if err != nil {
		t.Fatal(err)
	}
	if got := exp.Sub(now); got != StreamTicketTTL {
		t.Fatalf("expiry = now+%v, want now+%v", got, StreamTicketTTL)
	}
	if !strings.HasPrefix(ticket, "st1.") || strings.Count(ticket, ".") != 2 {
		t.Fatalf("ticket shape %q", ticket)
	}
	claims, err := s.Redeem(ticket, "project-1", "host")
	if err != nil {
		t.Fatalf("first redeem: %v", err)
	}
	if claims.UserID != "user-1" || claims.Email != "u@example.test" || claims.Role != "user" {
		t.Fatalf("claims = %+v", claims)
	}
	if _, err := s.Redeem(ticket, "project-1", "host"); !errors.Is(err, ErrTicketReused) {
		t.Fatalf("second redeem err = %v, want ErrTicketReused", err)
	}
}

func TestStreamTicketBoundToProjectAndStream(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	s := newTestTickets(&now)
	ticket, _, err := s.Issue("user-1", "", "user", "project-1", "waf")
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ project, stream string }{
		{"project-2", "waf"},
		{"project-1", "host"},
		{"project-1", "agent-decisions"},
	} {
		if _, err := s.Redeem(ticket, tc.project, tc.stream); !errors.Is(err, ErrTicketScope) {
			t.Errorf("redeem for %s/%s err = %v, want ErrTicketScope", tc.project, tc.stream, err)
		}
	}
	// A refused scope does not spend the ticket.
	if _, err := s.Redeem(ticket, "project-1", "waf"); err != nil {
		t.Fatalf("redeem for the issued scope after refusals: %v", err)
	}
}

func TestStreamTicketExpires(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	s := newTestTickets(&now)
	ticket, _, err := s.Issue("user-1", "", "user", "p", "host")
	if err != nil {
		t.Fatal(err)
	}
	now = now.Add(StreamTicketTTL)
	if _, err := s.Redeem(ticket, "p", "host"); !errors.Is(err, ErrTicketExpired) {
		t.Fatalf("err = %v, want ErrTicketExpired", err)
	}
}

func TestStreamTicketRejectsTamperingAndForeignKeys(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	s := newTestTickets(&now)
	ticket, _, err := s.Issue("user-1", "", "user", "p", "host")
	if err != nil {
		t.Fatal(err)
	}
	body, sig, _ := strings.Cut(strings.TrimPrefix(ticket, "st1."), ".")

	other := NewStreamTickets("a-different-jwt-secret-32-chars-long!")
	other.now = s.now
	if _, err := other.Redeem(ticket, "p", "host"); !errors.Is(err, ErrTicketSignature) {
		t.Errorf("ticket from another secret: err = %v, want ErrTicketSignature", err)
	}
	forged, _, _ := other.Issue("user-1", "", "admin", "p", "host")
	if _, err := s.Redeem(forged, "p", "host"); !errors.Is(err, ErrTicketSignature) {
		t.Errorf("forged ticket: err = %v, want ErrTicketSignature", err)
	}
	flipped := "st1." + body[:len(body)-1] + string(body[len(body)-1]^1) + "." + sig
	if _, err := s.Redeem(flipped, "p", "host"); err == nil {
		t.Error("a modified payload was accepted")
	}
	for _, bad := range []string{"", "st1.", "st1.abc", "eyJhbGciOiJIUzI1NiJ9.e30.sig", "st1..", strings.Repeat("x", 2048)} {
		if _, err := s.Redeem(bad, "p", "host"); err == nil {
			t.Errorf("malformed ticket %q accepted", bad)
		}
	}
}

func TestStreamTicketIssueRequiresKnownStream(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	s := newTestTickets(&now)
	for _, stream := range []string{"", "events", "host/stream", "../waf"} {
		if _, _, err := s.Issue("user-1", "", "user", "p", stream); err == nil {
			t.Errorf("Issue accepted stream %q", stream)
		}
	}
	if _, _, err := s.Issue("", "", "user", "p", "host"); err == nil {
		t.Error("Issue accepted an empty user")
	}
	for _, stream := range []string{"host", "waf", "agent-decisions"} {
		if !ValidStreamName(stream) {
			t.Errorf("ValidStreamName(%q) = false", stream)
		}
	}
}

// A ticket is not a JWT and a JWT is not a ticket: different key, shape.
func TestStreamTicketIsNotAJWT(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	s := newTestTickets(&now)
	jwt, err := SignJWT("user-1", "", "user", ticketSecret, 1)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Redeem(jwt, "p", "host"); err == nil {
		t.Fatal("a JWT was redeemed as a stream ticket")
	}
	ticket, _, _ := s.Issue("user-1", "", "user", "p", "host")
	if _, err := ParseJWT(ticket, ticketSecret); err == nil {
		t.Fatal("a stream ticket parsed as a JWT")
	}
}
