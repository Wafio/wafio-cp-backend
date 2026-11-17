package handlers

import "testing"

func TestFCGIPatch(t *testing.T) {
	s := func(v string) *string { return &v }
	if r, i := fcgiPatch(nil, nil); r != nil || i != nil {
		t.Fatalf("absent fields must stay nil: %v %v", r, i)
	}
	if r, i := fcgiPatch(s("/srv"), nil); r == nil || *r != "/srv" || i != nil {
		t.Fatalf("doc root only: %v %v", r, i)
	}
	if r, i := fcgiPatch(nil, s("")); r != nil || i == nil || *i != defaultFCGIIndex {
		t.Fatalf("empty index: %v %v", r, i)
	}
	if r, i := fcgiPatch(s(""), s("app.php")); r == nil || *r != "" || i == nil || *i != "app.php" {
		t.Fatalf("clear doc root: %v %v", r, i)
	}
}
