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

// A block policy the connect blocklist cannot carry is refused enabled on
// create and on update, and stored disabled.
func TestDBTracePolicyBlockMustBeEnforceable(t *testing.T) {
	f := newDBFixture(t)
	tok := f.tokens["owner"]
	agentID := f.registerAgent(t, "owner", "trace-block", "host")
	base := "/api/projects/" + f.project + "/host/trace/policies"
	q := "?agent_id=" + agentID

	wantStatus(t, "enabled block on a comm", call(t, f.app, http.MethodPost, base+q, tok,
		map[string]any{"name": "block-nc", "action": "block", "enabled": true, "match_comm": "nc"}), fiber.StatusBadRequest, "BAD_REQUEST")
	wantStatus(t, "enabled block on an ip", call(t, f.app, http.MethodPost, base+q, tok,
		map[string]any{"name": "block-ip", "action": "block", "enabled": true, "match_dest_ip": "192.0.2.10"}), fiber.StatusCreated, "")
	off := call(t, f.app, http.MethodPost, base+q, tok, map[string]any{"name": "block-nc", "action": "block", "enabled": false, "match_comm": "nc"})
	wantStatus(t, "disabled block on a comm", off, fiber.StatusCreated, "")

	pid := strconv.Itoa(int(off.body["id"].(float64)))
	wantStatus(t, "enable it", call(t, f.app, http.MethodPut, base+"/"+pid+q, tok,
		map[string]any{"name": "block-nc", "action": "block", "enabled": true, "match_comm": "nc"}), fiber.StatusBadRequest, "BAD_REQUEST")
}
