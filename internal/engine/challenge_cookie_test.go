package engine

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"strconv"
	"testing"
	"time"
)

const cookieTestSecret = "cookie-secret-0123456789abcdef"

// The challenge pass-cookie must validate purely on HMAC + expiry — NOT on the
// client IP. Hard-binding to the exact IP looped legitimate users whose IP
// changes between issue and use (dual-stack IPv4/IPv6, mobile/CGNAT, LB).
func TestChallengeCookieValidatesWithoutIP(t *testing.T) {
	c := GenerateChallengeCookieWithTTL(cookieTestSecret, "", time.Hour)
	if !ValidateChallengeCookie(cookieTestSecret, "", c) {
		t.Fatalf("freshly issued cookie should validate")
	}
}

func TestChallengeCookieRejectsExpired(t *testing.T) {
	c := GenerateChallengeCookieWithTTL(cookieTestSecret, "", -time.Minute) // already expired
	if ValidateChallengeCookie(cookieTestSecret, "", c) {
		t.Fatalf("expired cookie must be rejected")
	}
}

func TestChallengeCookieRejectsTamperedAndWrongSecret(t *testing.T) {
	c := GenerateChallengeCookieWithTTL(cookieTestSecret, "", time.Hour)
	if ValidateChallengeCookie("a-different-secret-value-000000", "", c) {
		t.Fatalf("cookie signed with another secret must be rejected")
	}
	if ValidateChallengeCookie(cookieTestSecret, "", c+"x") {
		t.Fatalf("tampered cookie must be rejected")
	}
	if ValidateChallengeCookie(cookieTestSecret, "", "not-a-cookie") {
		t.Fatalf("malformed cookie must be rejected")
	}
}

// Legacy 3-part cookies (expiry:ip:hmac) issued before this change must simply
// fail validation (one re-challenge), never validate by accident.
func TestChallengeCookieRejectsLegacyFormat(t *testing.T) {
	legacy := "9999999999:1.2.3.4:deadbeef"
	if ValidateChallengeCookie(cookieTestSecret, "", legacy) {
		t.Fatalf("legacy IP-bound cookie format must not validate")
	}
}

func TestChallengeCookieRoundTrip(t *testing.T) {
	for _, secret := range []string{cookieTestSecret, ""} {
		c := GenerateChallengeCookieWithTTL(secret, "", time.Hour)
		id, exp, ok := ParseChallengeCookie(secret, "", c)
		if !ok || len(id) != 16 || exp <= time.Now().Unix() {
			t.Fatalf("secret %q: round trip failed: id=%q exp=%d ok=%v", secret, id, exp, ok)
		}
		if c2 := GenerateChallengeCookieWithTTL(secret, "", time.Hour); c2 == c {
			t.Fatalf("two cookies minted in the same second must differ")
		}
	}
}

// The key used to be SHA-256("wafio-challenge-v1:") for every config without a
// provider secret: a public constant. Cookies signed with it must not validate.
func TestChallengeCookieRejectsOldPublicKeyAndTwoPartForm(t *testing.T) {
	exp := strconv.FormatInt(time.Now().Add(time.Hour).Unix(), 10)
	pub := sha256.Sum256([]byte("wafio-challenge-v1:"))
	sign := func(msg string) string {
		m := hmac.New(sha256.New, pub[:])
		m.Write([]byte(msg))
		return hex.EncodeToString(m.Sum(nil))
	}
	cases := map[string]string{
		"old 2-part, public key": exp + ":" + sign(exp),
		"3-part, public key":     exp + ":0123456789abcdef:" + sign(exp+":0123456789abcdef:"),
		"bad id (uppercase)":     exp + ":0123456789ABCDEF:" + signHMAC(deriveChallengeHMACKey(""), exp+":0123456789ABCDEF:"),
		"bad id (short)":         exp + ":0123:" + signHMAC(deriveChallengeHMACKey(""), exp+":0123:"),
		"2-part, instance key":   exp + ":" + signHMAC(deriveChallengeHMACKey(""), exp),
	}
	for name, c := range cases {
		if ValidateChallengeCookie("", "", c) {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestChallengeInstanceSecret(t *testing.T) {
	saved := challengeInstanceSecret.Load()
	t.Cleanup(func() { challengeInstanceSecret.Store(saved) })

	var inst [32]byte
	for i := range inst {
		inst[i] = byte(i + 1)
	}
	SetChallengeInstanceSecret(inst)
	m := hmac.New(sha256.New, inst[:])
	m.Write([]byte("wafio-challenge-v1:instance"))
	if got := deriveChallengeHMACKey(""); !hmac.Equal(got, m.Sum(nil)) {
		t.Fatalf("key without secret_key is not HMAC(instance, label)")
	}
	pub := sha256.Sum256([]byte("wafio-challenge-v1:"))
	if hmac.Equal(deriveChallengeHMACKey(""), pub[:]) {
		t.Fatalf("public constant key in use")
	}
	want := sha256.Sum256([]byte("wafio-challenge-v1:abc"))
	if !hmac.Equal(deriveChallengeHMACKey("abc"), want[:]) {
		t.Fatalf("provider-secret key changed")
	}

	// Unset: random per process, never the constant, stable once generated.
	challengeInstanceSecret.Store(nil)
	k1 := deriveChallengeHMACKey("")
	if hmac.Equal(k1, pub[:]) || !hmac.Equal(k1, deriveChallengeHMACKey("")) {
		t.Fatalf("unset secret: constant key or unstable")
	}
	challengeInstanceSecret.Store(nil)
	if hmac.Equal(k1, deriveChallengeHMACKey("")) {
		t.Fatalf("two unset secrets produced the same key")
	}
}
