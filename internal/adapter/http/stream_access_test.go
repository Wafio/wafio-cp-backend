package httpadapter

import (
	"context"
	"errors"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/wafio/wafio-cp-backend/internal/adapter/http/auth"
	"github.com/wafio/wafio-cp-backend/internal/adapter/http/handlers"
)

// The guard of open SSE streams repeats the
// checks the opening request passed — the user exists, the stream's token
// version is current, and the user still holds the route's project role
// (system admins pass, as in RequireProjectAccess). Any lookup error ends
// the stream.
func TestStreamAccessRechecksUserAndMembership(t *testing.T) {
	store := newTestUserStore()
	states := store.states()
	roles := map[string]string{}
	var roleErr error
	g := streamAccess{users: states, memberRole: func(_ context.Context, projectID, userID string) (string, error) {
		return roles[projectID+"/"+userID], roleErr
	}}
	sub := func(id string, tv int, min string) handlers.StreamSubject {
		return handlers.StreamSubject{UserID: id, ProjectID: "p1", TokenVersion: tv, MinRole: min}
	}
	ctx := context.Background()

	member := uuid.NewString()
	store.put(member, auth.UserState{Exists: true, Role: "user", TokenVersion: 2})
	roles["p1/"+member] = "member"
	if !g.StillAllowed(ctx, sub(member, 2, "viewer")) {
		t.Fatal("member with current token refused")
	}
	if g.StillAllowed(ctx, sub(member, 1, "viewer")) {
		t.Fatal("stream opened with a revoked token version allowed")
	}
	if g.StillAllowed(ctx, sub(member, 2, "owner")) {
		t.Fatal("member allowed on an owner stream")
	}
	roles["p1/"+member] = "" // removed from the project
	if g.StillAllowed(ctx, sub(member, 2, "viewer")) {
		t.Fatal("removed member allowed")
	}
	roles["p1/"+member] = "viewer"
	roleErr = errors.New("db down")
	if g.StillAllowed(ctx, sub(member, 2, "viewer")) {
		t.Fatal("membership lookup error allowed the stream")
	}
	roleErr = nil

	store.put(member, auth.UserState{Exists: false})
	states.Invalidate(member)
	if g.StillAllowed(ctx, sub(member, 2, "viewer")) {
		t.Fatal("deleted user allowed")
	}

	admin := uuid.NewString() // no membership row
	store.put(admin, auth.UserState{Exists: true, Role: "admin"})
	if !g.StillAllowed(ctx, sub(admin, 0, "viewer")) {
		t.Fatal("system admin refused")
	}

	down := newTestUserStore()
	down.err = errors.New("db down")
	if (streamAccess{users: down.states(), memberRole: g.memberRole}).StillAllowed(ctx, sub(admin, 0, "viewer")) {
		t.Fatal("user-state error allowed the stream")
	}
}

// NewFiberApp wires the guard into the SSE handlers: without one they
// answer 503, so a stream that opens proves it is re-checked.
func TestStreamGuardWiredInNewFiberApp(t *testing.T) {
	app := newTestFiberApp(t)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = app.Listener(ln) }()
	t.Cleanup(func() { _ = app.ShutdownWithTimeout(time.Second) })

	req, err := http.NewRequest(http.MethodGet, "http://"+ln.Addr().String()+"/api/projects/"+uuid.NewString()+"/waf/stream", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+adminToken(t))
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	resp, err := http.DefaultClient.Do(req.WithContext(ctx))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK || !strings.HasPrefix(resp.Header.Get("Content-Type"), "text/event-stream") {
		t.Fatalf("waf stream: %d %s, want an open event stream", resp.StatusCode, resp.Header.Get("Content-Type"))
	}
}
