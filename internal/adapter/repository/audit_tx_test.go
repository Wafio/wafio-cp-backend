package repository

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

func auditTestRepo(t *testing.T) (*Repository, context.Context) {
	t.Helper()
	dsn := os.Getenv("TEST_DB_URL")
	if dsn == "" {
		t.Skip("TEST_DB_URL not set")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	return FromPool(pool), ctx
}

func auditTestProject(t *testing.T, r *Repository, ctx context.Context) (projectID, ownerID, otherID string) {
	t.Helper()
	owner, err := r.User.Create(ctx, uuid.NewString()+"@audit.test", "x", "owner")
	if err != nil {
		t.Fatal(err)
	}
	other, err := r.User.Create(ctx, uuid.NewString()+"@audit.test", "x", "other")
	if err != nil {
		t.Fatal(err)
	}
	p, err := r.Project.Create(ctx, owner.ID, "audit-tx", "PRJ-"+strings.ReplaceAll(uuid.NewString(), "-", ""), "")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = r.Project.DeleteByID(ctx, p.ID)
		_ = r.User.Delete(ctx, owner.ID)
		_ = r.User.Delete(ctx, other.ID)
	})
	return p.ID, owner.ID, other.ID
}

// A failed audit write is counted, and an audited mutation whose audit
// row cannot be written does not happen.
func TestAuditFailureCountedAndRollsBackMutation(t *testing.T) {
	r, ctx := auditTestRepo(t)
	projectID, _, otherID := auditTestProject(t, r, ctx)

	before := AuditWriteFailures()
	// A project id that does not exist violates agent_audit's foreign key.
	if err := r.Audit.Log(ctx, AuditEvent{ProjectID: uuid.NewString(), Action: "test.orphan", TargetType: "test"}); err == nil {
		t.Fatal("audit row for a missing project was written")
	}
	if got := AuditWriteFailures() - before; got != 1 {
		t.Fatalf("AuditWriteFailures delta = %d, want 1", got)
	}

	bad := AuditEvent{ProjectID: uuid.NewString(), Action: AuditMemberAdded, TargetType: "user"}
	if _, err := r.ProjectMember.AddAudited(ctx, projectID, otherID, "viewer", bad); err == nil {
		t.Fatal("AddAudited succeeded although its audit row failed")
	}
	if role, _ := r.ProjectMember.GetRole(ctx, projectID, otherID); role != "" {
		t.Fatalf("membership committed without its audit row (role %q)", role)
	}
	if got := AuditWriteFailures() - before; got != 2 {
		t.Fatalf("AuditWriteFailures delta = %d, want 2", got)
	}

	good := AuditEvent{ProjectID: projectID, Action: AuditMemberAdded, TargetType: "user", TargetID: otherID}
	if added, err := r.ProjectMember.AddAudited(ctx, projectID, otherID, "viewer", good); err != nil || !added {
		t.Fatalf("AddAudited: added=%v err=%v", added, err)
	}
	var n int
	if err := r.DB.QueryRow(ctx, `SELECT count(*) FROM agent_audit WHERE project_id = $1 AND action = $2`, projectID, AuditMemberAdded).Scan(&n); err != nil || n != 1 {
		t.Fatalf("member.added rows = %d (%v), want 1", n, err)
	}
}

// The last owner cannot be demoted or removed; a non-member is
// ErrMemberNotFound.
func TestMemberOwnerGuards(t *testing.T) {
	r, ctx := auditTestRepo(t)
	projectID, ownerID, otherID := auditTestProject(t, r, ctx)
	ev := AuditEvent{ProjectID: projectID, Action: AuditMemberRoleChanged, TargetType: "user"}
	if err := r.ProjectMember.UpdateRoleAudited(ctx, projectID, ownerID, "member", ev); !errors.Is(err, ErrLastOwner) {
		t.Fatalf("demote last owner: %v, want ErrLastOwner", err)
	}
	if err := r.ProjectMember.RemoveAudited(ctx, projectID, ownerID, ev); !errors.Is(err, ErrLastOwner) {
		t.Fatalf("remove last owner: %v, want ErrLastOwner", err)
	}
	if err := r.ProjectMember.UpdateRoleAudited(ctx, projectID, otherID, "member", ev); !errors.Is(err, ErrMemberNotFound) {
		t.Fatalf("non-member: %v, want ErrMemberNotFound", err)
	}
}

// A removal (credential revoke, member removal
// or demotion, project delete) commits even when its audit write fails; the
// failure is logged and counted. Grants (here: a promotion) still roll back.
func TestRemovalCommitsWhileAuditFails(t *testing.T) {
	r, ctx := auditTestRepo(t)
	projectID, ownerID, otherID := auditTestProject(t, r, ctx)
	broken := func(action string) AuditEvent {
		// A project id that does not exist: the audit insert fails on its FK.
		return AuditEvent{ProjectID: uuid.NewString(), Action: action, TargetType: "test"}
	}

	var credID string
	if err := r.DB.QueryRow(ctx, `INSERT INTO mtls_credentials (project_id, name, client_cert_pem, cert_fingerprint_sha256, purpose)
		VALUES ($1, 'audit-ca', 'pem', $2, 'agent_grpc') RETURNING id::text`, projectID, uuid.NewString()).Scan(&credID); err != nil {
		t.Fatal(err)
	}
	before := AuditWriteFailures()
	deleted, err := r.AgentGRPC.DeleteAgentCredentialAudited(ctx, credID, projectID, broken(AuditCredentialRevoked))
	if err != nil || !deleted {
		t.Fatalf("revoke with failing audit: deleted=%v err=%v, want committed", deleted, err)
	}
	var left int
	if err := r.DB.QueryRow(ctx, `SELECT count(*) FROM mtls_credentials WHERE id = $1`, credID).Scan(&left); err != nil || left != 0 {
		t.Fatalf("credential still present (%d, %v)", left, err)
	}
	if got := AuditWriteFailures() - before; got != 1 {
		t.Fatalf("AuditWriteFailures delta = %d, want 1", got)
	}

	if err := r.ProjectMember.Add(ctx, projectID, otherID, "member"); err != nil {
		t.Fatal(err)
	}
	if err := r.ProjectMember.UpdateRoleAudited(ctx, projectID, otherID, "owner", broken(AuditMemberRoleChanged)); err == nil {
		t.Fatal("promotion committed without its audit row")
	}
	if err := r.ProjectMember.UpdateRoleAudited(ctx, projectID, otherID, "viewer", broken(AuditMemberRoleChanged)); err != nil {
		t.Fatalf("demotion with failing audit: %v", err)
	}
	if role, _ := r.ProjectMember.GetRole(ctx, projectID, otherID); role != "viewer" {
		t.Fatalf("role after demotion = %q, want viewer", role)
	}
	if err := r.ProjectMember.RemoveAudited(ctx, projectID, otherID, broken(AuditMemberRemoved)); err != nil {
		t.Fatalf("removal with failing audit: %v", err)
	}
	if role, _ := r.ProjectMember.GetRole(ctx, projectID, otherID); role != "" {
		t.Fatalf("member still present with role %q", role)
	}

	// Project delete: the system_audit insert fails on an invalid inet.
	deleted, err = r.Project.DeleteAudited(ctx, projectID, SystemAuditEvent{
		ActorUserID: ownerID, Action: AuditProjectDeleted, TargetType: "project", Outcome: "success", IP: "not-an-ip",
	})
	if err != nil || !deleted {
		t.Fatalf("project delete with failing audit: deleted=%v err=%v", deleted, err)
	}
	if got := AuditWriteFailures() - before; got != 5 {
		t.Fatalf("AuditWriteFailures delta = %d, want 5 (revoke, promotion, demotion, removal, delete)", got)
	}
}
