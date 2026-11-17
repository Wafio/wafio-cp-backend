package otp

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"math/big"
	"strings"
)

// backupAlphabet excludes ambiguous chars (0/O/1/I).
const backupAlphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"

// HashBackupCode normalizes a code (uppercase, strip non-alphanumerics) then
// returns its SHA-256 hex. Used for both storing and verifying so display
// formatting (hyphens, spaces, case) never affects matching.
func HashBackupCode(code string) string {
	var b strings.Builder
	for _, r := range strings.ToUpper(code) {
		if (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
		}
	}
	sum := sha256.Sum256([]byte(b.String()))
	return hex.EncodeToString(sum[:])
}

// GenerateBackupCodes returns n random codes formatted "XXXXX-XXXXX" plus
// their hashes (hashes[i] == HashBackupCode(plain[i])).
func GenerateBackupCodes(n int) (plain []string, hashes []string, err error) {
	plain = make([]string, 0, n)
	hashes = make([]string, 0, n)
	max := big.NewInt(int64(len(backupAlphabet)))
	for i := 0; i < n; i++ {
		var raw [10]byte
		for j := range raw {
			idx, e := rand.Int(rand.Reader, max)
			if e != nil {
				return nil, nil, e
			}
			raw[j] = backupAlphabet[idx.Int64()]
		}
		code := string(raw[:5]) + "-" + string(raw[5:])
		plain = append(plain, code)
		hashes = append(hashes, HashBackupCode(code))
	}
	return plain, hashes, nil
}
