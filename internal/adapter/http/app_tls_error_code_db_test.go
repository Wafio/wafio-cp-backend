package httpadapter

import (
	"context"
	"strings"
	"testing"

	"github.com/gofiber/fiber/v2"

	"github.com/wafio/wafio-cp-backend/internal/adapter/repository"
	"github.com/wafio/wafio-cp-backend/internal/domain"
)

// status.error_code names the failure of an uploaded certificate when the stored error is exactly one
// of the control plane's phrases, whoever wrote the row: the control plane after a refusal, or an
// agent that sends the phrase as its own error text.
func TestDBAppTLSStatusErrorCode(t *testing.T) {
	tf := newTLSFixture(t)
	ctx := context.Background()
	tf.bind(t, tf.agentID)
	up := tf.upload(t, "owner", tf.newCert(t, certOpts{}))
	wantStatus(t, "upload", up, fiber.StatusCreated, "")
	certID, _ := up.body["id"].(string)
	wantStatus(t, "gateway", tf.put(t, "owner", gateway("uploaded", "shop.example.com")), fiber.StatusOK, "")

	read := func(what string) map[string]any {
		t.Helper()
		got := tf.get(t, "viewer")
		wantStatus(t, what, got, fiber.StatusOK, "")
		st, _ := got.body["status"].(map[string]any)
		if st == nil {
			t.Fatalf("%s: no status: %s", what, got.raw)
		}
		return st
	}
	agentWrites := func(state, text string) {
		t.Helper()
		rep := repository.TLSStatusReport{ProjectID: tf.project, AgentID: tf.agentID, AppID: tf.appID, Source: "uploaded", State: state,
			CertificateID: certID, LeafSHA256: strings.Repeat("ab", 32), Error: text}
		if ok, err := tf.repo.TLS.UpsertTLSStatus(ctx, rep); err != nil || !ok {
			t.Fatalf("agent status: %v %v", ok, err)
		}
	}

	for _, code := range []string{"bad_pem", "too_large", "key_mismatch", "leaf_mismatch", "unsupported_key", "write_failed", "invalid_ack", "key_unreadable"} {
		text := domain.CertificateFailureText(code)
		if ok, err := tf.repo.TLS.FailTLSStatus(ctx, tf.project, tf.agentID, tf.appID, certID, text); err != nil || !ok {
			t.Fatalf("%s: fail status: %v %v", code, ok, err)
		}
		if st := read(code); st["state"] != "failed" || st["error"] != text || st["error_code"] != code {
			t.Errorf("%s written by the control plane: %v", code, st)
		}
		agentWrites("failed", text)
		if st := read(code + " from the agent"); st["error"] != text || st["error_code"] != code {
			t.Errorf("%s written by the agent: %v", code, st)
		}
	}

	refused := domain.CertificateFailureText("bad_pem")
	for name, text := range map[string]string{
		"no error":     "",
		"a prefix":     "stored: " + refused,
		"a suffix":     refused + " (again)",
		"another case": strings.ToUpper(refused),
		"free text":    "the agent could not bind 0.0.0.0:443",
	} {
		agentWrites("failed", text)
		if st := read(name); st["error_code"] != "" {
			t.Errorf("%s: error_code = %v, want empty: %v", name, st["error_code"], st)
		}
	}
	agentWrites("active", refused)
	if st := read("active"); st["error_code"] != "" {
		t.Errorf("an active status that holds a phrase: %v", st)
	}
}
