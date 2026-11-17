package engine

import (
	"encoding/base64"
	"encoding/json"
	"strconv"
	"testing"
	"time"
)

const testSecret = "wafio-secret-key-1234567890abcdef"

func TestPoWTokenGenerationAndValidation(t *testing.T) {
	// 1. Generate PoW token with 12 difficulty bits
	token, err := GeneratePoWToken(testSecret, "", 12)
	if err != nil {
		t.Fatalf("GeneratePoWToken: %v", err)
	}

	salt, diff, ok := ValidatePoWToken(testSecret, "", token)
	if !ok {
		t.Fatalf("ValidatePoWToken failed on fresh valid token")
	}
	if salt == "" {
		t.Errorf("expected non-empty salt")
	}
	if diff != 12 {
		t.Errorf("expected difficulty 12, got %d", diff)
	}

	// 2. Tampered token should fail
	_, _, ok = ValidatePoWToken(testSecret, "", token+"tampered")
	if ok {
		t.Errorf("expected tampered token to fail validation")
	}

	// 3. Wrong secret key should fail
	_, _, ok = ValidatePoWToken("different-secret-key", "", token)
	if ok {
		t.Errorf("expected wrong secret key to fail validation")
	}
}

func TestPoWSolverAndValidator(t *testing.T) {
	salt := "test-challenge-salt-42"
	difficulty := 12

	// Solve PoW in Go (same algorithm as browser)
	var solution int64 = -1
	for n := int64(0); n < 100000; n++ {
		if ValidatePoW(salt, n, difficulty) {
			solution = n
			break
		}
	}

	if solution == -1 {
		t.Fatalf("failed to find PoW solution within 100,000 iterations for difficulty %d", difficulty)
	}

	// Validate correct solution passes
	if !ValidatePoW(salt, solution, difficulty) {
		t.Errorf("ValidatePoW returned false for valid solution %d", solution)
	}

	// Higher difficulty must be stricter
	if ValidatePoW(salt, solution, 28) {
		t.Errorf("solution for diff 12 should almost certainly not satisfy diff 28")
	}
}

func TestEvaluateTelemetry(t *testing.T) {
	// Clean legitimate visitor
	clean := &BrowserTelemetry{
		Webdriver:          false,
		NoLanguages:        false,
		ScreenInvalid:      false,
		AutomationVars:     false,
		CDPDetected:        false,
		PrototypeTampered:  false,
		WorkerMismatch:     false,
		WorkerWebdriver:    false,
		PermissionsAnomaly: false,
		SoftwareRenderer:   false,
		NoChromeObject:     false,
		CanvasFailed:       false,
		AudioZero:          false,
		DurationMs:         250,
		UserAgent:          "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36",
		Renderer:           "Apple M2 Pro",
	}

	score, isBot, reasons := EvaluateTelemetry(clean)
	if isBot {
		t.Errorf("clean browser should not be flagged as bot, got score=%d, reasons=%v", score, reasons)
	}
	if score != 0 {
		t.Errorf("expected clean score 0, got %d", score)
	}

	// Puppeteer Stealth / CDP evasion visitor
	stealth := &BrowserTelemetry{
		Webdriver:          false, // Faked to false by stealth plugin
		CDPDetected:        true,  // Caught window.cdc_
		PrototypeTampered:  true,  // Caught Object.defineProperty on navigator.webdriver
		WorkerWebdriver:    true,  // Caught unmasked worker realm
		SoftwareRenderer:   true,  // SwiftShader / llvmpipe on Linux VPS
		PermissionsAnomaly: true,  // Notification.permission mismatch
		AudioZero:          true,  // No sound hardware
		DurationMs:         45,
	}

	score, isBot, reasons = EvaluateTelemetry(stealth)
	if !isBot {
		t.Errorf("stealth browser should be flagged as bot")
	}
	if score < 100 {
		t.Errorf("expected stealth score >= 100, got %d", score)
	}
	if len(reasons) < 3 {
		t.Errorf("expected multiple detection reasons, got %v", reasons)
	}
}

func TestValidateChallengeSubmission(t *testing.T) {
	token, err := GeneratePoWToken(testSecret, "", 12)
	if err != nil {
		t.Fatalf("token: %v", err)
	}

	salt, diff, ok := ValidatePoWToken(testSecret, "", token)
	if !ok {
		t.Fatalf("token invalid")
	}

	// Solve PoW
	var solution int64 = -1
	for n := int64(0); n < 100000; n++ {
		if ValidatePoW(salt, n, diff) {
			solution = n
			break
		}
	}

	// 1. Valid PoW + clean telemetry
	cleanTel := BrowserTelemetry{DurationMs: 200, UserAgent: "Mozilla/5.0"}
	telBytes, _ := json.Marshal(cleanTel)
	telB64 := base64.StdEncoding.EncodeToString(telBytes)

	verified, isBot, _, reasons := ValidateChallengeSubmission(testSecret, "", token, strconv.FormatInt(solution, 10), telB64, "0")
	if !verified {
		t.Errorf("expected submission to be verified, reasons=%v", reasons)
	}
	if isBot {
		t.Errorf("expected clean submission not to be bot, reasons=%v", reasons)
	}

	// 2. Wrong PoW solution must fail verification
	verified, _, _, _ = ValidateChallengeSubmission(testSecret, "", token, "999999999", telB64, "0")
	if verified {
		t.Errorf("expected wrong PoW solution to fail verification")
	}

	// 3. Valid PoW + CDP/Tampering detected must be verified=true but isBot=true (triggers escalation)
	tamperedTel := BrowserTelemetry{CDPDetected: true, PrototypeTampered: true, DurationMs: 150}
	tBytes, _ := json.Marshal(tamperedTel)
	tB64 := base64.StdEncoding.EncodeToString(tBytes)

	verified, isBot, score, reasons := ValidateChallengeSubmission(testSecret, "", token, strconv.FormatInt(solution, 10), tB64, "0")
	if !verified {
		t.Errorf("expected PoW to be valid, but got verified=false")
	}
	if !isBot {
		t.Errorf("expected isBot=true for CDP/tampered telemetry, score=%d", score)
	}
	if len(reasons) == 0 {
		t.Errorf("expected reasons to be populated")
	}
}

// A 3-part nonce (what turnstile/hcaptcha pages embed) is not a PoW token:
// it must never verify, with or without telemetry.
func TestSubmissionRejectsNonPoWTokens(t *testing.T) {
	nonce, err := GenerateChallengeNonce(testSecret)
	if err != nil {
		t.Fatalf("nonce: %v", err)
	}
	pow0 := "salt:" + strconv.FormatInt(time.Now().Add(time.Minute).Unix(), 10) + ":0"
	for name, tok := range map[string]string{
		"3-part nonce":        nonce,
		"nonce with proof":    nonce + "|x",
		"empty":               "",
		"difficulty 0 signed": pow0 + ":" + signHMAC(deriveChallengeHMACKey(testSecret), pow0+":"),
	} {
		for _, tel := range []string{"", "e30="} {
			if ok, _, _, reasons := ValidateChallengeSubmission(testSecret, "", tok, "", tel, "0"); ok {
				t.Errorf("%s (telemetry %q) verified; reasons=%v", name, tel, reasons)
			}
		}
	}
}
