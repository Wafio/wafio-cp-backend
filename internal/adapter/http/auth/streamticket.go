package auth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"time"
)

// Stream tickets carry SSE authentication in a URL without putting a JWT
// there.
//
// EventSource cannot send an Authorization header, so an SSE URL has to carry
// the credential in its query string, where access logs, proxy logs and the
// browser history keep it. A JWT is a poor thing to leave there: it is valid
// for days and for every endpoint. A stream ticket is valid for one stream of
// one project for one user, for StreamTicketTTL, and can be redeemed once.
//
// A ticket is "st1." + base64url(payload) + "." + base64url(HMAC-SHA256).
// The HMAC key is derived from the JWT signing secret with a fixed label, so
// every control-plane instance sharing the secret verifies every ticket, and
// a ticket can never be confused with a JWT (different key, different shape).
// Single use is enforced in memory per instance: a ticket redeemed on one
// instance is refused there for the rest of its lifetime.

// StreamTicketTTL is how long an issued ticket may be redeemed.
const StreamTicketTTL = 60 * time.Second

// maxUsedTickets bounds the replay set. Tickets expire after StreamTicketTTL
// and issuance is rate limited per user, so a full set means abuse; new
// redemptions are refused until entries expire rather than growing without
// bound.
const maxUsedTickets = 200_000

const ticketPrefix = "st1."

// Stream names a ticket may be bound to. Each is the path segment(s) between
// /api/projects/:id/ and /stream.
var streamNames = map[string]bool{
	"host":            true,
	"waf":             true,
	"agent-decisions": true,
}

// ValidStreamName reports whether name is a stream a ticket can be issued for.
func ValidStreamName(name string) bool { return streamNames[name] }

// Errors returned by Redeem. The caller answers every one of them with the
// same 401; they are distinct only for logging and tests.
var (
	ErrTicketMalformed = errors.New("stream ticket malformed")
	ErrTicketSignature = errors.New("stream ticket signature invalid")
	ErrTicketExpired   = errors.New("stream ticket expired")
	ErrTicketScope     = errors.New("stream ticket not valid for this stream")
	ErrTicketReused    = errors.New("stream ticket already used")
)

// StreamTicketClaims is what a redeemed ticket vouches for.
type StreamTicketClaims struct {
	UserID    string `json:"u"`
	Email     string `json:"e"`
	Role      string `json:"r"`
	ProjectID string `json:"p"`
	Stream    string `json:"s"`
	ExpiresAt int64  `json:"x"`
	Nonce     string `json:"n"`
	// TokenVersion is the tv of the JWT the ticket was issued to; a ticket
	// minted before a revocation is refused at redemption.
	TokenVersion int `json:"v,omitempty"`
}

// StreamTickets issues and redeems stream tickets.
type StreamTickets struct {
	key []byte
	now func() time.Time

	mu        sync.Mutex
	used      map[string]time.Time // nonce → expiry
	lastPrune time.Time
}

// NewStreamTickets derives the ticket key from the JWT signing secret.
func NewStreamTickets(jwtSecret string) *StreamTickets {
	mac := hmac.New(sha256.New, []byte(jwtSecret))
	mac.Write([]byte("wafio stream ticket v1"))
	return &StreamTickets{
		key:  mac.Sum(nil),
		now:  time.Now,
		used: make(map[string]time.Time),
	}
}

// Issue signs a ticket for one stream of one project, for a token of version 0.
func (s *StreamTickets) Issue(userID, email, role, projectID, stream string) (string, time.Time, error) {
	return s.IssueVersion(userID, email, role, 0, projectID, stream)
}

// IssueVersion signs a ticket for one stream of one project and records the
// token version of the JWT that asked for it.
func (s *StreamTickets) IssueVersion(userID, email, role string, tokenVersion int, projectID, stream string) (string, time.Time, error) {
	if userID == "" || projectID == "" || !ValidStreamName(stream) {
		return "", time.Time{}, ErrTicketScope
	}
	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		return "", time.Time{}, err
	}
	exp := s.now().Add(StreamTicketTTL)
	payload, err := json.Marshal(StreamTicketClaims{
		UserID: userID, Email: email, Role: role,
		ProjectID: projectID, Stream: stream,
		ExpiresAt: exp.Unix(), Nonce: hex.EncodeToString(nonce),
		TokenVersion: tokenVersion,
	})
	if err != nil {
		return "", time.Time{}, err
	}
	body := base64.RawURLEncoding.EncodeToString(payload)
	return ticketPrefix + body + "." + base64.RawURLEncoding.EncodeToString(s.sign(body)), exp, nil
}

func (s *StreamTickets) sign(body string) []byte {
	mac := hmac.New(sha256.New, s.key)
	mac.Write([]byte(ticketPrefix + body))
	return mac.Sum(nil)
}

// Redeem verifies a ticket for projectID's stream and marks it used.
func (s *StreamTickets) Redeem(ticket, projectID, stream string) (*StreamTicketClaims, error) {
	if !strings.HasPrefix(ticket, ticketPrefix) || len(ticket) > 1024 {
		return nil, ErrTicketMalformed
	}
	body, sig, ok := strings.Cut(strings.TrimPrefix(ticket, ticketPrefix), ".")
	if !ok || body == "" || sig == "" {
		return nil, ErrTicketMalformed
	}
	gotSig, err := base64.RawURLEncoding.DecodeString(sig)
	if err != nil {
		return nil, ErrTicketMalformed
	}
	if !hmac.Equal(gotSig, s.sign(body)) {
		return nil, ErrTicketSignature
	}
	payload, err := base64.RawURLEncoding.DecodeString(body)
	if err != nil {
		return nil, ErrTicketMalformed
	}
	var claims StreamTicketClaims
	if err := json.Unmarshal(payload, &claims); err != nil || claims.Nonce == "" || claims.UserID == "" {
		return nil, ErrTicketMalformed
	}
	now := s.now()
	expiresAt := time.Unix(claims.ExpiresAt, 0)
	if !now.Before(expiresAt) {
		return nil, ErrTicketExpired
	}
	if claims.ProjectID != projectID || claims.Stream != stream {
		return nil, ErrTicketScope
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if now.Sub(s.lastPrune) >= time.Second {
		for nonce, exp := range s.used {
			if !now.Before(exp) {
				delete(s.used, nonce)
			}
		}
		s.lastPrune = now
	}
	if _, seen := s.used[claims.Nonce]; seen {
		return nil, ErrTicketReused
	}
	if len(s.used) >= maxUsedTickets {
		return nil, ErrTicketReused
	}
	s.used[claims.Nonce] = expiresAt
	return &claims, nil
}
