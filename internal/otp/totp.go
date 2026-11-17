package otp

import (
	"time"

	potp "github.com/pquerna/otp"
	"github.com/pquerna/otp/hotp"
)

// TOTP parameters: the defaults of totp.Generate / totp.Validate, which is
// what every enrolled authenticator was set up with (RFC 6238, SHA-1, 6
// digits, 30 s steps, one step of clock skew either way).
const (
	TOTPPeriod = 30
	totpSkew   = 1
)

// TOTPStep returns the RFC 6238 time step (counter) for t.
func TOTPStep(t time.Time) int64 {
	return t.Unix() / TOTPPeriod
}

// MatchTOTP checks code against secret at time now and returns the time step
// it matched. It accepts exactly what totp.Validate accepts (current step and
// one either side), but tells the caller which step was used so the step can
// be recorded and a second use of it refused (RFC 6238 §5.2).
// Comparison is constant time (hotp.ValidateCustom).
func MatchTOTP(code, secret string, now time.Time) (step int64, ok bool) {
	if secret == "" {
		return 0, false
	}
	cur := TOTPStep(now)
	opts := hotp.ValidateOpts{Digits: potp.DigitsSix, Algorithm: potp.AlgorithmSHA1}
	// Same order as totp.ValidateCustom: current, then +1/-1.
	for _, s := range []int64{cur, cur + totpSkew, cur - totpSkew} {
		if s < 0 {
			continue
		}
		valid, err := hotp.ValidateCustom(code, uint64(s), secret, opts)
		if err != nil {
			return 0, false
		}
		if valid {
			return s, true
		}
	}
	return 0, false
}
