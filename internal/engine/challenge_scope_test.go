package engine

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	mathrand "math/rand"
	"strings"
	"testing"
	"time"
)

const scopeTestSecret = "scope-secret-0123456789abcdef"

// A token or cookie minted for one app must not open another app of the same
// agent, with or without a provider secret_key.
func TestChallengeMACsAreBoundToScope(t *testing.T) {
	for _, secret := range []string{"", scopeTestSecret} {
		c := GenerateChallengeCookieWithTTL(secret, "app-a", time.Hour)
		if !ValidateChallengeCookie(secret, "app-a", c) {
			t.Fatalf("secret %q: cookie invalid in its own scope", secret)
		}
		for _, other := range []string{"app-b", ""} {
			if ValidateChallengeCookie(secret, other, c) {
				t.Errorf("secret %q: cookie of app-a accepted in scope %q", secret, other)
			}
		}

		pow, err := GeneratePoWToken(secret, "app-a", 4)
		if err != nil {
			t.Fatal(err)
		}
		if _, _, ok := ValidatePoWToken(secret, "app-a", pow); !ok {
			t.Fatalf("secret %q: PoW token invalid in its own scope", secret)
		}
		if _, _, ok := ValidatePoWToken(secret, "app-b", pow); ok {
			t.Errorf("secret %q: PoW token of app-a accepted in app-b", secret)
		}

		tok, sig, _, _, err := GenerateClickPuzzleToken(secret, "app-a")
		if err != nil {
			t.Fatal(err)
		}
		csv := puzzleAnswer(t, secret, "app-a", tok, sig)
		if _, ok := ClickPuzzleTokenExpiry(secret, "app-b", tok); ok {
			t.Errorf("secret %q: puzzle token of app-a accepted in app-b", secret)
		}
		if ValidateClickPuzzleToken(secret, "app-b", tok, sig, csv) {
			t.Errorf("secret %q: puzzle answer of app-a accepted in app-b", secret)
		}
	}
}

// puzzleAnswer finds the clicked-cell CSV the sig commits to by trying every mask.
func puzzleAnswer(t *testing.T, secret, scope, token, sig string) string {
	t.Helper()
	var found []string
	for mask := 0; mask < 512; mask++ {
		var idx []string
		for i := 0; i < 9; i++ {
			if mask&(1<<uint(i)) != 0 {
				idx = append(idx, fmt.Sprint(i))
			}
		}
		csv := strings.Join(idx, ",")
		if ValidateClickPuzzleToken(secret, scope, token, sig, csv) {
			found = append(found, csv)
		}
	}
	if len(found) != 1 {
		t.Fatalf("want exactly one accepted mask, got %v", found)
	}
	return found[0]
}

// The puzzle token no longer carries the answer mask; its own MAC (tmac)
// covers seed, color, shape and expiry, the sig commits to the answer.
func TestClickPuzzleTokenCarriesNoAnswer(t *testing.T) {
	for i := 0; i < 50; i++ {
		tok, sig, _, _, err := GenerateClickPuzzleToken(scopeTestSecret, "app")
		if err != nil {
			t.Fatal(err)
		}
		parts := strings.Split(tok, "|")
		if len(parts) != 5 || len(parts[0]) != 32 || len(parts[4]) != 64 {
			t.Fatalf("token shape: %q", tok)
		}
		csv := puzzleAnswer(t, scopeTestSecret, "app", tok, sig)
		if csv == "" {
			t.Fatal("answer must click at least one cell")
		}
		// Same cells in another order or with duplicates are the same mask.
		if !ValidateClickPuzzleToken(scopeTestSecret, "app", tok, sig, csv+","+csv) {
			t.Errorf("duplicate indices of the right cells rejected")
		}
		// Invalid indices fail whatever else is clicked.
		for _, bad := range []string{csv + ",9", csv + ",-1", csv + ",x", strings.Repeat("1,", 100)} {
			if ValidateClickPuzzleToken(scopeTestSecret, "app", tok, sig, bad) {
				t.Errorf("clicked %q accepted", bad)
			}
		}
		// tmac covers the expiry and the color: a tampered token is not authentic.
		parts[3] = "ffffffffff"
		if _, ok := ClickPuzzleTokenExpiry(scopeTestSecret, "app", strings.Join(parts, "|")); ok {
			t.Errorf("tampered expiry accepted")
		}
	}
	tok, sig, _, _, _ := GenerateClickPuzzleToken(scopeTestSecret, "")
	tok2, _, _, _, _ := GenerateClickPuzzleToken(scopeTestSecret, "")
	if ValidateClickPuzzleToken(scopeTestSecret, "", tok2, sig, puzzleAnswer(t, scopeTestSecret, "", tok, sig)) {
		t.Errorf("sig of one token validated another")
	}
}

func TestClickPuzzleTokenExpiryRejectsExpiredAndMalformed(t *testing.T) {
	tok, _, _, _, _ := GenerateClickPuzzleToken(scopeTestSecret, "")
	if exp, ok := ClickPuzzleTokenExpiry(scopeTestSecret, "", tok); !ok || exp <= time.Now().Unix() {
		t.Fatalf("fresh token: exp=%d ok=%v", exp, ok)
	}
	for name, bad := range map[string]string{
		"empty":      "",
		"4 fields":   strings.Join(strings.Split(tok, "|")[:4], "|"),
		"6 fields":   tok + "|x",
		"no tmac":    tok[:strings.LastIndexByte(tok, '|')+1],
		"old format": "00112233445566778899aabbccddeeff|red|star|01ff|ffffffff",
	} {
		if _, ok := ClickPuzzleTokenExpiry(scopeTestSecret, "", bad); ok {
			t.Errorf("%s accepted", name)
		}
	}
}

// Oversized values are refused before any split or MAC: no allocation grows
// with the input.
func TestChallengeParsersRejectHugeInputsWithoutAllocating(t *testing.T) {
	hugeToken := strings.Repeat("a:", 4<<20)  // 8 MiB
	hugeCookie := strings.Repeat("a:", 8<<10) // 16 KiB
	hugePuzzle := strings.Repeat("a|", 4<<20)

	if _, _, ok := ValidatePoWToken(scopeTestSecret, "", hugeToken); ok {
		t.Fatal("8 MiB PoW token accepted")
	}
	if _, _, ok := ParseChallengeCookie(scopeTestSecret, "", hugeCookie); ok {
		t.Fatal("16 KiB cookie accepted")
	}
	if _, ok := ClickPuzzleTokenExpiry(scopeTestSecret, "", hugePuzzle); ok {
		t.Fatal("8 MiB puzzle token accepted")
	}
	for name, fn := range map[string]func(){
		"pow":    func() { ValidatePoWToken(scopeTestSecret, "", hugeToken) },
		"cookie": func() { ParseChallengeCookie(scopeTestSecret, "", hugeCookie) },
		"puzzle": func() { ClickPuzzleTokenExpiry(scopeTestSecret, "", hugePuzzle) },
	} {
		if n := testing.AllocsPerRun(5, fn); n != 0 {
			t.Errorf("%s: %v allocations for an oversized input, want 0", name, n)
		}
	}

	// A valid token with an 8 MiB answer list costs no more than a normal wrong answer.
	tok, sig, _, _, _ := GenerateClickPuzzleToken(scopeTestSecret, "")
	hugeCSV := strings.Repeat("1,", 4<<20)
	normal := testing.AllocsPerRun(5, func() { ValidateClickPuzzleToken(scopeTestSecret, "", tok, sig, "1,2,3") })
	huge := testing.AllocsPerRun(5, func() { ValidateClickPuzzleToken(scopeTestSecret, "", tok, sig, hugeCSV) })
	if huge > normal {
		t.Errorf("8 MiB answer list: %v allocations, a normal answer takes %v", huge, normal)
	}
	if ValidateClickPuzzleToken(scopeTestSecret, "", tok, sig, hugeCSV) {
		t.Error("8 MiB answer list accepted")
	}
}

func TestPoWTokenRejectsExtraColonsAndOldMACInput(t *testing.T) {
	tok, err := GeneratePoWToken(scopeTestSecret, "app", 4)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, ok := ValidatePoWToken(scopeTestSecret, "app", tok+":x"); ok {
		t.Error("5-part token accepted")
	}
	// A MAC computed without the scope suffix (the previous input) is not valid.
	p := strings.Split(tok, ":")
	old := p[0] + ":" + p[1] + ":" + p[2] + ":" + signHMAC(deriveChallengeHMACKey(scopeTestSecret), p[0]+":"+p[1]+":"+p[2])
	if _, _, ok := ValidatePoWToken(scopeTestSecret, "app", old); ok {
		t.Error("token MAC without scope accepted")
	}
}

// The seed in a puzzle token must not rebuild the grid: the cells come from an
// HMAC-keyed seed, so a client holding only the token cannot derive the answer.
func TestClickPuzzleGridNeedsTheKeyNotJustTheSeed(t *testing.T) {
	key := deriveChallengeHMACKey(scopeTestSecret)
	for i := 0; i < 20; i++ {
		token, _, _, cells, err := GenerateClickPuzzleToken(scopeTestSecret, "app-a")
		if err != nil {
			t.Fatal(err)
		}
		seedHex, _, _ := strings.Cut(token, "|")
		raw, err := hex.DecodeString(seedHex)
		if err != nil || len(raw) != 16 {
			t.Fatalf("token seed %q", seedHex)
		}
		// Old derivation: the raw token seed. It must no longer give the shown cells.
		_, _, naive, _ := buildClickGrid(mathrand.New(mathrand.NewSource(int64(binary.BigEndian.Uint64(raw[:8])))))
		if fmt.Sprint(naive) == fmt.Sprint(cells) {
			t.Fatalf("grid rebuilt from the token seed alone: %v", cells)
		}
		// Documented derivation: first 8 bytes of HMAC-SHA256(key, "cpgrid:<scope>:<seedHex>").
		m := hmac.New(sha256.New, key)
		m.Write([]byte("cpgrid:app-a:" + seedHex))
		want := int64(binary.BigEndian.Uint64(m.Sum(nil)[:8]))
		_, _, keyed, _ := buildClickGrid(mathrand.New(mathrand.NewSource(want)))
		if fmt.Sprint(keyed) != fmt.Sprint(cells) {
			t.Fatalf("grid does not follow the HMAC-derived seed: got %v want %v", cells, keyed)
		}
	}
}

// A challenge type that is none of the known values is the JS challenge.
func TestChallengeTypeNormalisedToJS(t *testing.T) {
	for typ, want := range map[string]string{
		"": ChallengeTypeJS, "js": ChallengeTypeJS, "JS_CHALLENGE": ChallengeTypeJS, "nonsense": ChallengeTypeJS,
		ChallengeTypeJS: ChallengeTypeJS, ChallengeTypeTurnstile: ChallengeTypeTurnstile,
		ChallengeTypeHCaptcha: ChallengeTypeHCaptcha, ChallengeTypeClickPuzzle: ChallengeTypeClickPuzzle,
		ChallengeTypeAdaptive: ChallengeTypeAdaptive,
	} {
		res, err := LoadRuleMapFromJSON([]byte(`{"challenge":{"enabled":true,"type":"` + typ + `"}}`))
		if err != nil || res.Challenge == nil {
			t.Fatalf("type %q: err=%v challenge=%v", typ, err, res != nil && res.Challenge != nil)
		}
		if res.Challenge.Type != want {
			t.Errorf("type %q: got %q, want %q", typ, res.Challenge.Type, want)
		}
	}
}
