package handlers

import (
	"os"
	"testing"

	"github.com/wafio/wafio-cp-backend/internal/apicontract"
)

// WAFIO_CONTRACT_REPORT=1 go test lists the spec operations this package's
// tests never validated against api/openapi.yaml.
func TestMain(m *testing.M) {
	os.Exit(apicontract.RunWithReport(m.Run))
}
