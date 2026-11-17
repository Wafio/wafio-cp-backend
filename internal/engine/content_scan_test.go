package engine

import (
	"crypto/sha256"
	"fmt"
	"testing"
)

func TestContentScanConfigRejectsInvalidHashes(t *testing.T) {
	for _, data := range []string{
		`{"content_scan":{"enabled":true,"custom_allowlist_hashes":["bad"]}}`,
		`{"content_scan":{"enabled":"true"}}`,
		`{"content_scan":{"enabled":true,"max_scan_size_bytes":104857601}}`,
	} {
		if err := ValidateRulesJSON([]byte(data)); err == nil {
			t.Fatalf("accepted %s", data)
		}
	}
}

func TestBuiltinEICARProvenance(t *testing.T) {
	payload := []byte("X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*")
	if len(payload) != 68 {
		t.Fatal("invalid EICAR fixture")
	}
	if len(BuiltinMalwareSignatures) != 1 || BuiltinMalwareSignatures[0].SHA256 != fmt.Sprintf("%x", sha256.Sum256(payload)) {
		t.Fatal("builtin signature lacks reproducible fixture")
	}
}
