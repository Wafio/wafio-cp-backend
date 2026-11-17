package repository

import (
	"context"
	"fmt"
	"testing"
)

// Event details are stored in system_audit.metadata (migration 000110) and
// read back by ListSystem; an event without details stores NULL.
func TestSystemAuditMetadataStoredAndRead(t *testing.T) {
	ctx := context.Background()
	p := bcTestPool(t)
	t.Cleanup(p.Close) // after the cleanups seedResetUser registers (LIFO)
	uid, _ := seedResetUser(t, p)
	t.Cleanup(func() { _, _ = p.Exec(ctx, `DELETE FROM system_audit WHERE actor_user_id = $1`, uid) })
	repo := &AuditRepo{pool: p}

	meta := map[string]any{"fields": []string{"host", "password"}, "host": "smtp.example.test", "password": "cleared (host changed)"}
	if err := repo.LogSystem(ctx, SystemAuditEvent{
		ActorUserID: uid, Action: "admin.smtp_settings_updated", TargetType: "system_setting", TargetID: "smtp",
		Outcome: "success", HTTPStatus: 200, IP: "192.0.2.1", Metadata: meta,
	}); err != nil {
		t.Fatalf("insert with metadata: %v", err)
	}
	if err := repo.LogSystem(ctx, SystemAuditEvent{
		ActorUserID: uid, Action: "admin.smtp_settings_cleared", TargetType: "system_setting", TargetID: "smtp",
		Outcome: "success", HTTPStatus: 200,
	}); err != nil {
		t.Fatalf("insert without metadata: %v", err)
	}
	var nulls int
	if err := p.QueryRow(ctx, `SELECT count(*) FROM system_audit WHERE actor_user_id = $1 AND metadata IS NULL`, uid).Scan(&nulls); err != nil || nulls != 1 {
		t.Fatalf("rows without details stored as NULL: %d %v", nulls, err)
	}

	events, _, err := repo.ListSystem(ctx, 100, 0)
	if err != nil {
		t.Fatal(err)
	}
	found := 0
	for _, e := range events {
		if e.ActorUserID != uid {
			continue
		}
		found++
		switch e.Action {
		case "admin.smtp_settings_updated":
			if e.Metadata["host"] != "smtp.example.test" || e.Metadata["password"] != "cleared (host changed)" || fmt.Sprint(e.Metadata["fields"]) != "[host password]" {
				t.Fatalf("metadata read back: %v", e.Metadata)
			}
		default:
			if e.Metadata != nil {
				t.Fatalf("event without details read back with %v", e.Metadata)
			}
		}
	}
	if found != 2 {
		t.Fatalf("listed %d of 2 events", found)
	}
}
