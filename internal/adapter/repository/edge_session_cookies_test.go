package repository

import (
	"reflect"
	"testing"
)

// The cookie names are saved with the cache, and compression needs them as well, so they are sent while
// either part is on, the cache being off included.
func TestBundleSessionCookies(t *testing.T) {
	const names = `"session_cookies": ["shop_sid", "jwt_login"]`
	want := []string{"shop_sid", "jwt_login"}
	for _, tc := range []struct {
		name, compression, cache string
		want                     []string
	}{
		{"compression on, cache off", `{"enabled": true}`, `{"enabled": false, ` + names + `}`, want},
		{"cache on, compression off", `{}`, `{"enabled": true, ` + names + `}`, want},
		{"both on", `{"enabled": true}`, `{"enabled": true, ` + names + `}`, want},
		{"both off", `{"enabled": false}`, `{"enabled": false, ` + names + `}`, nil},
		{"nothing stored", `{}`, `{}`, nil},
		{"no names", `{"enabled": true}`, `{"enabled": false, "session_cookies": []}`, nil},
		{"names left out", `{"enabled": true}`, `{"enabled": true}`, nil},
		{"a stored object that is no JSON", `{"enabled": true}`, `nope`, nil},
	} {
		if got := BundleSessionCookies([]byte(tc.compression), []byte(tc.cache)); !reflect.DeepEqual(got, tc.want) {
			t.Errorf("%s: got %v, want %v", tc.name, got, tc.want)
		}
	}
}
