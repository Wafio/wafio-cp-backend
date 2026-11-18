package engine

import (
	"crypto/sha256"
	"encoding/hex"
	"testing"
)

// The WAF agent keeps a byte for byte copy of the stock page, and its own test pins the same digest. A
// change to the page has to change both copies and both digests, so the two cannot drift apart unnoticed.
func TestStockMaintenanceHTMLPin(t *testing.T) {
	const want = "19e7dcca79422988cd08f783ffc80b70dc0f4058ba78530afd7bbb06928da633"
	sum := sha256.Sum256([]byte(StockMaintenanceHTML))
	if got := hex.EncodeToString(sum[:]); got != want {
		t.Fatalf("sha256 of StockMaintenanceHTML is %s, want %s; update the copy in the WAF agent (crates/agent-pages/src/maintenance.rs) and its pin", got, want)
	}
}
