package apicontract

import (
	"bytes"
	"io"
	"net/http"
	"testing"

	"github.com/gofiber/fiber/v2"
)

// FiberTest is app.Test plus contract validation: it runs req on app (built by
// NewFiberApp, so the real routes answer), finds the documented operation by
// matching the request against the spec's paths, validates the response and
// returns it with a body that can still be read. A request no operation
// documents (removed routes, the frontend, a method the path does not have)
// is returned unvalidated. Errors from app.Test are returned unchanged. A
// body that cannot be read fails t; a stream test that cuts its own stream
// uses FiberTestCutStream.
func FiberTest(t testing.TB, app *fiber.App, req *http.Request, msTimeout ...int) (*http.Response, error) {
	t.Helper()
	s, err := Default()
	if err != nil {
		t.Fatalf("apicontract: %v", err)
	}
	return s.fiberTest(t, app, req, false, msTimeout...)
}

// FiberTestCutStream is FiberTest for a response whose body the test cuts
// short on purpose (an endless stream): what was read is validated, a read
// error is not a failure.
func FiberTestCutStream(t testing.TB, app *fiber.App, req *http.Request, msTimeout ...int) (*http.Response, error) {
	t.Helper()
	s, err := Default()
	if err != nil {
		t.Fatalf("apicontract: %v", err)
	}
	return s.fiberTest(t, app, req, true, msTimeout...)
}

// FiberTest is the package-level FiberTest against s.
func (s *Spec) FiberTest(t testing.TB, app *fiber.App, req *http.Request, msTimeout ...int) (*http.Response, error) {
	t.Helper()
	return s.fiberTest(t, app, req, false, msTimeout...)
}

func (s *Spec) fiberTest(t testing.TB, app *fiber.App, req *http.Request, cutOK bool, msTimeout ...int) (*http.Response, error) {
	t.Helper()
	// Match before running: handlers may consume or rewrite the request.
	key, documented := s.Match(req.Method, req.URL.Path)
	resp, err := app.Test(req, msTimeout...)
	if err != nil {
		return resp, err
	}
	raw, rerr := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	resp.Body = io.NopCloser(bytes.NewReader(raw))
	if rerr != nil && !cutOK {
		t.Errorf("apicontract: %s %s: reading the body: %v", req.Method, req.URL.RequestURI(), rerr)
		return resp, nil
	}
	if documented {
		if err := s.Check(key, resp.StatusCode, resp.Header, raw); err != nil {
			t.Errorf("apicontract: %s %s: %v", req.Method, req.URL.RequestURI(), err)
		}
	}
	return resp, nil
}

// MustMatch returns the operation key for method + path, failing t when the
// spec documents none.
func MustMatch(t testing.TB, method, path string) string {
	t.Helper()
	s, err := Default()
	if err != nil {
		t.Fatalf("apicontract: %v", err)
	}
	key, ok := s.Match(method, path)
	if !ok {
		t.Fatalf("apicontract: no documented operation for %s %s", method, path)
	}
	return key
}

// TestOperation runs req on app and validates the response against the named
// operation ("GET /api/projects/{id}/hosts/fleet"), for handler tests that
// mount a handler at a path of their own. The body stays readable.
func TestOperation(t testing.TB, app *fiber.App, operation string, req *http.Request, msTimeout ...int) (*http.Response, error) {
	t.Helper()
	resp, err := app.Test(req, msTimeout...)
	if err != nil {
		return resp, err
	}
	raw, rerr := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	resp.Body = io.NopCloser(bytes.NewReader(raw))
	if rerr != nil {
		t.Errorf("apicontract: %s: reading the body: %v", operation, rerr)
		return resp, nil
	}
	ValidateResponse(t, operation, resp.StatusCode, resp.Header, raw)
	return resp, nil
}
