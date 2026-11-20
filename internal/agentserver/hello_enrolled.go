package agentserver

import (
	"context"
	"errors"
	"log"
	"net"
	"strings"
	"time"

	"github.com/wafio/wafio-cp-backend/internal/adapter/repository"
	"github.com/wafio/wafio-cp-backend/internal/lru"
	agentv1 "github.com/wafio/wafio-cp-backend/shared/agentpb"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
)

// Hello of a host-bound credential (host-key enrollment, migration 000108). A project-wide credential may register or resume
// any agent name of its project (validateHello). A credential enrolled with
// a host key was issued for one agent -- kind and name -- on one host, and
// Hello holds it to exactly that:
//
//   - agent_name must be the enrolled name and the kind hint the enrolled
//     kind;
//   - the host must not be revoked (a revoke deletes the credential too;
//     this is the second line);
//   - a presented host_key must verify and belong to that host;
//   - the agent row is the one of that name and kind on the host, or a new
//     one there; any other agent of that name in the project (another host,
//     no host, the other kind) is refused -- nothing is adopted.
//
// So an enrolled credential cannot reconnect under another name, as another
// kind, or for another host, whatever hostname it reports. Refusals are
// audited (agent.rejected), at most once per credential and reason every
// boundRefusalAuditEvery: a bound credential presenting another identity is
// a compromise signal.

// credentialBinding is the agent identity a host-bound credential carries.
type credentialBinding struct {
	hostID string
	kind   string // "host" | "waf"
	name   string
}

func withBinding(ctx context.Context, b credentialBinding) context.Context {
	return context.WithValue(ctx, ctxKeyBinding, b)
}

func bindingFrom(ctx context.Context) (credentialBinding, bool) {
	b, ok := ctx.Value(ctxKeyBinding).(credentialBinding)
	return b, ok && b.hostID != ""
}

// helloKind normalises the Hello kind hint: "waf" is a WAF agent; "host",
// the legacy "ebpf" and anything else (validateHello's default) a host agent.
func helloKind(hint string) string {
	if strings.TrimSpace(hint) == "waf" {
		return "waf"
	}
	return "host"
}

// boundRefusalAuditEvery rate-limits the audit row of refused bound Hellos
// per (credential, reason): an agent retrying with a wrong name would
// otherwise write one row per reconnect.
const boundRefusalAuditEvery = 10 * time.Minute

var boundRefusalSeen = lru.New[time.Time](4096)

func (s *Server) validateBoundHello(ctx context.Context, projectID string, hello *agentv1.Hello, b credentialBinding) (agentKind, agentID, hostID string, err error) {
	name := strings.TrimSpace(hello.GetAgentName())
	if name == "" {
		name = hello.GetHostname() + "@ebpf" // validateHello's fallback
	}
	if name != b.name {
		s.auditBoundRefusal(ctx, projectID, b, hello, "agent_name")
		return "", "", "", status.Errorf(codes.PermissionDenied,
			"credential is enrolled for agent %q; agent_name %q refused", b.name, name)
	}
	if kind := helloKind(hello.GetAgentKind()); kind != b.kind {
		s.auditBoundRefusal(ctx, projectID, b, hello, "agent_kind")
		return "", "", "", status.Errorf(codes.PermissionDenied,
			"credential is enrolled for a %s agent; a %s agent is refused", b.kind, kind)
	}
	if s.Repo.Host == nil || s.Repo.EBPF == nil {
		return "", "", "", status.Error(codes.Internal, "server not initialized")
	}

	keyCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()

	// The host first: an enrolled credential is only as good as its host.
	// Unlike a project-wide credential's best-effort check, a failed lookup
	// refuses (Unavailable, the agent retries): the identity rests on it.
	revoked, rerr := s.Repo.Host.HostRevoked(keyCtx, projectID, b.hostID)
	if rerr != nil {
		log.Printf("[agentserver] enrolled hello host check failed project=%s host=%s: %v", projectID, b.hostID, rerr)
		return "", "", "", status.Error(codes.Unavailable, "host check unavailable; retry")
	}
	if revoked {
		s.auditBoundRefusal(ctx, projectID, b, hello, "host_revoked")
		return "", "", "", errHelloHostRevoked
	}

	if hostKey := strings.TrimSpace(hello.GetHostKey()); hostKey != "" {
		host, herr := s.Repo.Host.VerifyKey(keyCtx, hostKey)
		switch {
		case errors.Is(herr, repository.ErrHostKeyInvalid):
			s.auditBoundRefusal(ctx, projectID, b, hello, "host_key_invalid")
			return "", "", "", status.Error(codes.PermissionDenied, "invalid host_key")
		case herr != nil:
			log.Printf("[agentserver] host_key check failed project=%s: %v", projectID, herr)
			return "", "", "", status.Error(codes.Unavailable, "host_key check unavailable; retry")
		case host.ProjectID != projectID || host.ID != b.hostID:
			s.auditBoundRefusal(ctx, projectID, b, hello, "host_key_other_host")
			return "", "", "", status.Error(codes.PermissionDenied, "host_key belongs to another host than the credential")
		}
	}

	aid, aerr := s.Repo.EBPF.BindEnrolledAgent(keyCtx, projectID, b.hostID, b.kind, name)
	switch {
	case errors.Is(aerr, repository.ErrAgentNameConflict):
		s.auditBoundRefusal(ctx, projectID, b, hello, "agent_name_conflict")
		return "", "", "", status.Errorf(codes.PermissionDenied,
			"agent name %q is used by another agent of the project (another host, no host or the other kind)", name)
	case errors.Is(aerr, repository.ErrHostKeyInvalid):
		return "", "", "", errHelloHostRevoked
	case aerr != nil:
		return "", "", "", registerErr("register enrolled agent", aerr)
	}
	s.agentIDMu.Lock()
	s.agentIDCache[projectID+"|"+name] = aid
	s.agentIDMu.Unlock()
	if b.kind == "waf" {
		return "waf", "", b.hostID, nil
	}
	return "host", aid, b.hostID, nil
}

// peerIP is the address the transport saw for the stream of ctx, "" when it has none.
func peerIP(ctx context.Context) string {
	if p, ok := peer.FromContext(ctx); ok && p != nil && p.Addr != nil {
		if h, _, err := net.SplitHostPort(p.Addr.String()); err == nil {
			return h
		}
	}
	return ""
}

// auditBoundRefusal writes an agent.rejected audit row for a refused Hello
// of a host-bound credential, at most once per credential and reason every
// boundRefusalAuditEvery, in the background (best effort).
func (s *Server) auditBoundRefusal(ctx context.Context, projectID string, b credentialBinding, hello *agentv1.Hello, reason string) {
	if s.Repo == nil || s.Repo.Audit == nil {
		return
	}
	credID := credentialIDFrom(ctx)
	now := time.Now()
	due := false
	boundRefusalSeen.Update(credID+"|"+reason, func(v *time.Time, created bool) {
		if created || now.Sub(*v) >= boundRefusalAuditEvery {
			*v, due = now, true
		}
	})
	if !due {
		return
	}
	ip := peerIP(ctx)
	clip := func(v string) string {
		if len(v) > 128 {
			return v[:128]
		}
		return v
	}
	ev := repository.AuditEvent{
		ProjectID: projectID, Action: repository.AuditAgentRejected,
		TargetType: "credential", TargetID: credID, TargetName: b.name,
		IP: ip,
		MetadataJSON: map[string]any{
			"reason": reason, "credential_id": credID, "host_id": b.hostID,
			"agent_kind": b.kind, "agent_name": b.name,
			"presented_name":     clip(strings.TrimSpace(hello.GetAgentName())),
			"presented_kind":     clip(strings.TrimSpace(hello.GetAgentKind())),
			"presented_hostname": clip(hello.GetHostname()),
		},
	}
	go func() { //nolint:gosec // G118: best-effort audit must outlive the Hello request context
		defer recoverPanic("audit-bound-refusal")
		actx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		if err := s.Repo.Audit.Log(actx, ev); err != nil {
			log.Printf("[agentserver] audit of refused enrolled hello failed credential=%s: %v", credID, err)
		}
	}()
}
