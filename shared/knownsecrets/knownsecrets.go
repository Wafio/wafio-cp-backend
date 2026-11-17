// Package knownsecrets recognises signing secrets that were once published in
// this repository's history. Anyone with a clone can forge tokens for
// an instance still configured with one of them, so boot-time validation of the
// control plane and the portal API refuses them.
//
// Only SHA-256 digests are kept here, never the values themselves.
package knownsecrets

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
)

// publishedSHA256 holds hex SHA-256 digests of secrets that appeared in a
// commit. Add an entry whenever a history scan finds another one.
var publishedSHA256 = map[string]string{
	// jwt.secret shipped in config/config.example.yaml (1ba82173, 8e5d7fa4,
	// HEAD until the secret was refused) and in a committed config backup (ba45c8a3).
	"6caeeded3878b30717074008da2f37c336944f17e5718484e876f6866ffda7bf": "the jwt.secret from config/config.example.yaml",
	// PORTAL_JWT_SECRET from the committed portal-api.env (7ef822f2) and a
	// plan document (873a8a0e).
	"982bfaa28bbbfd068fe95eefb325f599e737d7f071a263ca38a2e9b5a569917b": "the development portal JWT secret",
}

// Published reports whether secret (surrounding whitespace ignored) is a value
// that was published in the repository history, and if so where it came from.
func Published(secret string) (source string, ok bool) {
	sum := sha256.Sum256([]byte(strings.TrimSpace(secret)))
	source, ok = publishedSHA256[hex.EncodeToString(sum[:])]
	return source, ok
}
