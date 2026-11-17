package handlers

import (
	"encoding/json"
	"testing"
)

// A nil list encodes as [] once passed through orEmpty.
func TestOrEmptyEncodesEmptyArray(t *testing.T) {
	var none []string
	b, err := json.Marshal(map[string]any{"items": orEmpty(none), "kept": orEmpty([]int{1})})
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != `{"items":[],"kept":[1]}` {
		t.Fatalf("got %s", b)
	}
}
