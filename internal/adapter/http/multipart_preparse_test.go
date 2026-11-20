package httpadapter

import "testing"

// No handler reads a form or a file, so the server does not parse a multipart body into form values
// before the handler runs: a private key in a part would be copied there and never cleared.
func TestAppDoesNotPreParseMultipartForms(t *testing.T) {
	if !newTestFiberApp(t).Config().DisablePreParseMultipartForm {
		t.Fatal("the server pre-parses multipart bodies")
	}
}
