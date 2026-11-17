package otp

import (
	"testing"
	"time"

	"github.com/pquerna/otp/totp"
)

const testTOTPSecret = "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP"

// MatchTOTP accepts exactly the codes totp.Validate accepts (current step
// and one either side) and reports the step each one belongs to.
func TestMatchTOTPReportsStep(t *testing.T) {
	now := time.Unix(1_800_000_015, 0)
	cur := TOTPStep(now)
	for offset := int64(-3); offset <= 3; offset++ {
		at := now.Add(time.Duration(offset*TOTPPeriod) * time.Second)
		code, err := totp.GenerateCode(testTOTPSecret, at)
		if err != nil {
			t.Fatal(err)
		}
		step, ok := MatchTOTP(code, testTOTPSecret, now)
		wantOK := offset >= -1 && offset <= 1
		if ok != wantOK {
			t.Fatalf("offset %d: ok=%v, want %v", offset, ok, wantOK)
		}
		if ok && step != cur+offset {
			t.Fatalf("offset %d: step %d, want %d", offset, step, cur+offset)
		}
		if lib, _ := totp.ValidateCustom(code, testTOTPSecret, now, totp.ValidateOpts{Period: 30, Skew: 1, Digits: 6}); lib != ok {
			t.Fatalf("offset %d: MatchTOTP=%v but totp.ValidateCustom=%v", offset, ok, lib)
		}
	}
}

func TestMatchTOTPRejectsJunk(t *testing.T) {
	now := time.Now()
	code, _ := totp.GenerateCode(testTOTPSecret, now)
	for name, tc := range map[string]struct{ code, secret string }{
		"empty code":     {"", testTOTPSecret},
		"short code":     {code[:5], testTOTPSecret},
		"long code":      {code + "0", testTOTPSecret},
		"empty secret":   {code, ""},
		"wrong secret":   {code, "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"},
		"bad secret b32": {code, "!!!!"},
	} {
		if _, ok := MatchTOTP(tc.code, tc.secret, now); ok {
			t.Errorf("%s: accepted", name)
		}
	}
}
