package httpadapter

import (
	"context"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/wafio/wafio-cp-backend/internal/adapter/repository"
)

// With the agent offline, update/delete of a trace policy the agent does not
// have is a 404 (no row is created), and a non-numeric id is a 400.
func TestDBTracePolicyOfflineMissingIs404(t *testing.T) {
	f := newDBFixture(t)
	tok := f.tokens["owner"]
	agentID := f.registerAgent(t, "owner", "trace-host", "host")
	ctx := context.Background()
	pid := 7
	if _, err := f.repo.EBPF.UpsertTracePolicy(ctx, &repository.TracePolicyRow{AgentID: agentID, PolicyID: &pid, Name: "watch-shadow", Enabled: true, Action: "alert"}); err != nil {
		t.Fatal(err)
	}
	base := "/api/projects/" + f.project + "/host/trace/policies/"
	q := "?agent_id=" + agentID
	body := map[string]any{"name": "watch-shadow", "action": "alert", "enabled": true}
	count := func() int {
		rows, err := f.repo.EBPF.ListTracePoliciesByAgent(ctx, agentID)
		if err != nil {
			t.Fatal(err)
		}
		return len(rows)
	}

	wantStatus(t, "update missing", call(t, f.app, http.MethodPut, base+"99"+q, tok, body), fiber.StatusNotFound, "NOT_FOUND")
	if n := count(); n != 1 {
		t.Fatalf("update of a missing policy created a row: %d rows", n)
	}
	wantStatus(t, "update non-numeric", call(t, f.app, http.MethodPut, base+"abc"+q, tok, body), fiber.StatusBadRequest, "INVALID_POLICY_ID")
	wantStatus(t, "update zero", call(t, f.app, http.MethodPut, base+"0"+q, tok, body), fiber.StatusBadRequest, "INVALID_POLICY_ID")
	wantStatus(t, "delete missing", call(t, f.app, http.MethodDelete, base+"99"+q, tok, nil), fiber.StatusNotFound, "NOT_FOUND")
	wantStatus(t, "delete non-numeric", call(t, f.app, http.MethodDelete, base+"abc"+q, tok, nil), fiber.StatusBadRequest, "INVALID_POLICY_ID")
	wantStatus(t, "get non-numeric", call(t, f.app, http.MethodGet, base+"abc"+q, tok, nil), fiber.StatusBadRequest, "INVALID_POLICY_ID")
	wantStatus(t, "get missing", call(t, f.app, http.MethodGet, base+"99"+q, tok, nil), fiber.StatusNotFound, "NOT_FOUND")

	updated := call(t, f.app, http.MethodPut, base+"7"+q, tok, body)
	wantStatus(t, "update existing", updated, fiber.StatusOK, "")
	// The offline update answers the stored row (the contract sweep found
	// created_at "" from echoing the request body).
	stored, err := f.repo.EBPF.ListTracePoliciesByAgent(ctx, agentID)
	if err != nil || len(stored) != 1 {
		t.Fatalf("stored rows: %v %v", stored, err)
	}
	if want := stored[0].CreatedAt.UTC().Format(time.RFC3339); updated.body["created_at"] != want || updated.body["id"] != float64(7) {
		t.Fatalf("update response %s, want created_at %s and id 7", updated.raw, want)
	}
	wantStatus(t, "delete existing", call(t, f.app, http.MethodDelete, base+"7"+q, tok, nil), fiber.StatusOK, "")
	if n := count(); n != 0 {
		t.Fatalf("delete left %d rows", n)
	}
}

// Trace policy routes answer the stored rows in the documented shapes. They
// used to pass a host agent's raw HTTP answer through when a callback URL
// existed; agents have had none since migration 000031, so that branch was
// dead and is gone. Every response here is also validated against the spec.
func TestDBTracePolicyRoutesAnswerStoredRows(t *testing.T) {
	f := newDBFixture(t)
	tok := f.tokens["owner"]
	agentID := f.registerAgent(t, "owner", "trace-crud", "host")
	ctx := context.Background()
	base := "/api/projects/" + f.project + "/host/trace/policies"
	q := "?agent_id=" + agentID

	created := call(t, f.app, http.MethodPost, base+q, tok, map[string]any{"name": "watch-nc", "action": "alert", "enabled": true, "match_comm": "nc", "event_types": []string{"execve"}})
	wantStatus(t, "create", created, fiber.StatusCreated, "")
	id, _ := created.body["id"].(float64)
	if id == 0 || created.body["created_at"] == "" || created.body["match_comm_mode"] != "word" {
		t.Fatalf("create response: %s", created.raw)
	}
	pid := strconv.Itoa(int(id))

	got := call(t, f.app, http.MethodGet, base+"/"+pid+q, tok, nil)
	wantStatus(t, "get", got, fiber.StatusOK, "")
	if got.body["created_at"] != created.body["created_at"] || got.body["name"] != "watch-nc" {
		t.Fatalf("get %s, create %s", got.raw, created.raw)
	}
	list := call(t, f.app, http.MethodGet, base+q, tok, nil)
	wantStatus(t, "list", list, fiber.StatusOK, "")
	if !strings.Contains(list.raw, `"name":"watch-nc"`) {
		t.Fatalf("list: %s", list.raw)
	}
	updated := call(t, f.app, http.MethodPut, base+"/"+pid+q, tok, map[string]any{"name": "watch-nc", "action": "alert", "enabled": false, "match_comm": "nc"})
	wantStatus(t, "update", updated, fiber.StatusOK, "")
	if updated.body["enabled"] != false || updated.body["created_at"] != created.body["created_at"] {
		t.Fatalf("update: %s", updated.raw)
	}
	deleted := call(t, f.app, http.MethodDelete, base+"/"+pid+q, tok, nil)
	wantStatus(t, "delete", deleted, fiber.StatusOK, "")
	if deleted.body["status"] != "deleted" || deleted.body["policy_id"] != id {
		t.Fatalf("delete: %s", deleted.raw)
	}
	if rows, err := f.repo.EBPF.ListTracePoliciesByAgent(ctx, agentID); err != nil || len(rows) != 0 {
		t.Fatalf("rows after delete: %v %v", rows, err)
	}
}

// The block action is refused on create and update, enabled or not, with the
// same answer; nothing is stored.
func TestDBTracePolicyBlockActionRefused(t *testing.T) {
	f := newDBFixture(t)
	tok := f.tokens["owner"]
	agentID := f.registerAgent(t, "owner", "trace-block", "host")
	base := "/api/projects/" + f.project + "/host/trace/policies"
	q := "?agent_id=" + agentID

	for name, body := range map[string]map[string]any{
		"enabled on a comm":   {"name": "block-nc", "action": "block", "enabled": true, "match_comm": "nc"},
		"enabled on an ip":    {"name": "block-ip", "action": "block", "enabled": true, "match_dest_ip": "192.0.2.10"},
		"disabled on an ip":   {"name": "block-off", "action": "block", "enabled": false, "match_dest_ip": "192.0.2.10"},
		"upper case on an ip": {"name": "block-up", "action": "BLOCK", "enabled": true, "match_dest_ip": "192.0.2.10"},
	} {
		r := call(t, f.app, http.MethodPost, base+q, tok, body)
		wantStatus(t, name, r, fiber.StatusBadRequest, "BAD_REQUEST")
		if msg, _ := r.body["error"].(string); !strings.Contains(msg, "egress blocklist") || !strings.Contains(msg, "kill") {
			t.Fatalf("%s: message %q does not name the replacements", name, msg)
		}
	}
	ok := call(t, f.app, http.MethodPost, base+q, tok, map[string]any{"name": "watch-ip", "action": "alert", "enabled": true, "match_dest_ip": "192.0.2.10"})
	wantStatus(t, "alert on an ip", ok, fiber.StatusCreated, "")

	pid := strconv.Itoa(int(ok.body["id"].(float64)))
	wantStatus(t, "update to block", call(t, f.app, http.MethodPut, base+"/"+pid+q, tok,
		map[string]any{"name": "watch-ip", "action": "block", "enabled": true, "match_dest_ip": "192.0.2.10"}), fiber.StatusBadRequest, "BAD_REQUEST")

	rows, err := f.repo.EBPF.ListTracePoliciesByAgent(context.Background(), agentID)
	if err != nil || len(rows) != 1 || rows[0].Action != "alert" {
		t.Fatalf("stored policies after the refusals: %+v %v", rows, err)
	}
}
