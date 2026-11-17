package auth

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const testSecret = "test-secret-at-least-32-characters-long!"

func TestParseJWTAcceptsValidToken(t *testing.T) {
	tok, err := SignJWT("user-1", "a@b.co", "admin", testSecret, 1)
	if err != nil {
		t.Fatal(err)
	}
	claims, err := ParseJWT(tok, testSecret)
	if err != nil {
		t.Fatalf("valid token rejected: %v", err)
	}
	if claims.UserID != "user-1" || claims.Email != "a@b.co" || claims.Role != "admin" {
		t.Errorf("claims round-tripped wrong: %+v", claims)
	}
}

func TestParseJWTRejectsWrongSecret(t *testing.T) {
	tok, err := SignJWT("user-1", "a@b.co", "user", testSecret, 1)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParseJWT(tok, "a-completely-different-secret-value!!"); err == nil {
		t.Fatal("token signed with another secret was accepted")
	}
}

func TestParseJWTReportsExpiry(t *testing.T) {
	claims := Claims{
		UserID: "user-1",
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(-time.Hour)),
			IssuedAt:  jwt.NewNumericDate(time.Now().Add(-2 * time.Hour)),
		},
	}
	tok, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString([]byte(testSecret))
	if err != nil {
		t.Fatal(err)
	}
	_, err = ParseJWT(tok, testSecret)
	if !errors.Is(err, ErrTokenExpired) {
		t.Fatalf("expired token: got %v, want ErrTokenExpired", err)
	}
}

// A token whose header claims alg:none must never be accepted. Accepting it
// would let anyone mint an admin session with no secret at all.
func TestParseJWTRejectsAlgNone(t *testing.T) {
	enc := func(v any) string {
		b, _ := json.Marshal(v)
		return base64.RawURLEncoding.EncodeToString(b)
	}
	header := enc(map[string]string{"alg": "none", "typ": "JWT"})
	payload := enc(map[string]any{
		"user_id": "attacker",
		"role":    "admin",
		"exp":     time.Now().Add(time.Hour).Unix(),
	})
	unsigned := header + "." + payload + "."

	if _, err := ParseJWT(unsigned, testSecret); err == nil {
		t.Fatal("alg:none token was accepted — any caller could forge an admin session")
	}
}

// HS256 is the only accepted algorithm; an RS256 header must be refused rather
// than sent down a different verification path.
func TestParseJWTRejectsAlgSwap(t *testing.T) {
	enc := func(v any) string {
		b, _ := json.Marshal(v)
		return base64.RawURLEncoding.EncodeToString(b)
	}
	header := enc(map[string]string{"alg": "RS256", "typ": "JWT"})
	payload := enc(map[string]any{
		"user_id": "attacker",
		"role":    "admin",
		"exp":     time.Now().Add(time.Hour).Unix(),
	})
	if _, err := ParseJWT(header+"."+payload+".signature", testSecret); err == nil {
		t.Fatal("RS256 token was accepted by an HS256-only verifier")
	}
}

func TestParseJWTRejectsMalformed(t *testing.T) {
	for name, tok := range map[string]string{
		"empty":       "",
		"not a jwt":   "hello",
		"two parts":   "aaa.bbb",
		"garbage b64": "!!!.???.###",
	} {
		if _, err := ParseJWT(tok, testSecret); err == nil {
			t.Errorf("%s: malformed token was accepted", name)
		}
	}
}

// The parser tolerates a quoted token because some clients send the raw JSON
// string. That leniency must not extend to accepting an invalid signature.
func TestParseJWTTolerantOfQuotesButNotOfForgery(t *testing.T) {
	tok, err := SignJWT("user-1", "a@b.co", "user", testSecret, 1)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParseJWT(`"`+tok+`"`, testSecret); err != nil {
		t.Errorf("quoted valid token rejected: %v", err)
	}
	forged := strings.TrimSuffix(tok, tok[len(tok)-4:]) + "AAAA"
	if _, err := ParseJWT(`"`+forged+`"`, testSecret); err == nil {
		t.Error("quoted token with tampered signature was accepted")
	}
}

// A pre-auth token is issued between password and TOTP. It carries PreAuth so
// callers can refuse it where a fully authenticated session is required.
func TestPreAuthTokenIsDistinguishable(t *testing.T) {
	tok, err := SignPreAuthJWT("user-1", "a@b.co", "user", 0, testSecret)
	if err != nil {
		t.Fatal(err)
	}
	claims, err := ParseJWT(tok, testSecret)
	if err != nil {
		t.Fatal(err)
	}
	if !claims.PreAuth {
		t.Error("pre-auth token did not carry PreAuth=true")
	}

	full, _ := SignJWT("user-1", "a@b.co", "user", testSecret, 1)
	fullClaims, _ := ParseJWT(full, testSecret)
	if fullClaims.PreAuth {
		t.Error("fully authenticated token carried PreAuth=true")
	}
}

// legacySignJWT signs a token the way the control plane did before token revocation: the
// same claims without "tv".
func legacySignJWT(t *testing.T, userID, role string) string {
	t.Helper()
	tok, err := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"user_id": userID,
		"email":   "a@b.co",
		"role":    role,
		"exp":     time.Now().Add(time.Hour).Unix(),
		"iat":     time.Now().Unix(),
	}).SignedString([]byte(testSecret))
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

// The tv claim round-trips, and a token issued before it existed
// reads as version 0 (so the deploy logs nobody out).
func TestTokenVersionClaim(t *testing.T) {
	tok, err := SignJWTVersion("user-1", "a@b.co", "user", 7, testSecret, 1)
	if err != nil {
		t.Fatal(err)
	}
	c, err := ParseJWT(tok, testSecret)
	if err != nil || c.TokenVersion != 7 {
		t.Fatalf("tv round trip: %+v %v", c, err)
	}
	payload, _ := base64.RawURLEncoding.DecodeString(strings.Split(tok, ".")[1])
	if !strings.Contains(string(payload), `"tv":7`) {
		t.Fatalf("payload has no tv claim: %s", payload)
	}

	legacy, err := ParseJWT(legacySignJWT(t, "user-1", "admin"), testSecret)
	if err != nil || legacy.TokenVersion != 0 || legacy.PreAuth {
		t.Fatalf("legacy token: %+v %v", legacy, err)
	}
}

// Every pre-auth token has its own jti (so it can be spent once), an
// expiry of PreAuthTTL and the user's token version.
func TestPreAuthTokenHasJTI(t *testing.T) {
	a, _ := SignPreAuthJWT("user-1", "a@b.co", "user", 3, testSecret)
	b, _ := SignPreAuthJWT("user-1", "a@b.co", "user", 3, testSecret)
	ca, err := ParseJWT(a, testSecret)
	if err != nil {
		t.Fatal(err)
	}
	cb, err := ParseJWT(b, testSecret)
	if err != nil {
		t.Fatal(err)
	}
	if len(ca.ID) != 32 || ca.ID == cb.ID {
		t.Fatalf("jti %q / %q: want distinct 128-bit ids", ca.ID, cb.ID)
	}
	if ca.TokenVersion != 3 || !ca.PreAuth {
		t.Fatalf("claims: %+v", ca)
	}
	if ttl := time.Until(ca.ExpiresAt.Time); ttl > PreAuthTTL || ttl < PreAuthTTL-time.Minute {
		t.Fatalf("pre-auth ttl %v, want ~%v", ttl, PreAuthTTL)
	}
}
