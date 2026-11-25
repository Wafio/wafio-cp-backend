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

// The audit entry names fcgi_keep_conn only when the request sent it, and keeps an explicit false.
func TestWithFCGIKeepConn(t *testing.T) {
	on, off := true, false
	if _, ok := withFCGIKeepConn(map[string]any{}, nil)["fcgi_keep_conn"]; ok {
		t.Fatal("an absent field was recorded")
	}
	if v := withFCGIKeepConn(map[string]any{}, &on)["fcgi_keep_conn"]; v != true {
		t.Fatalf("true recorded as %v", v)
	}
	if v, ok := withFCGIKeepConn(map[string]any{}, &off)["fcgi_keep_conn"]; !ok || v != false {
		t.Fatalf("false recorded as %v (present %v)", v, ok)
	}
}
