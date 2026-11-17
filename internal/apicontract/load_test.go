package apicontract

import (
	"os"
	"testing"
)

var readFile = os.ReadFile

func TestDefaultSpecLoads(t *testing.T) {
	s, err := Default()
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("%d operations in %s", len(s.Operations()), s.Path)
}
