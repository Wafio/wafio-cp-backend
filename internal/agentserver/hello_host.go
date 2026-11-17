package agentserver

import (
	"context"
	"errors"
	"log"
	"time"

	"github.com/wafio/wafio-cp-backend/internal/adapter/repository"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// Host checks at Hello. Revoking a host used to only mark its row:
// Hello never looked at it for an agent it already knew (and ignored a
// host_key such an agent presented), so the host's agents reconnected and
// kept receiving desired state. Now an agent bound to a revoked host is
// refused, a presented host_key is always verified, and an unknown agent
// whose hostname names a revoked host is refused instead of registering
// afresh. A revoke or delete also revokes every credential enrolled for the
// host, so its machine cannot reconnect under another name; a
// project-wide credential is not tied to one machine and stays valid until
// it is revoked on the Credentials page.

// errHelloHostRevoked refuses an agent of a revoked host.
var errHelloHostRevoked = status.Error(codes.PermissionDenied, "host revoked")

// errHelloAgentLimit refuses registering one more agent in a full project.
var errHelloAgentLimit = status.Errorf(codes.ResourceExhausted,
	"agent limit reached: at most %d agents per project", repository.MaxAgentsPerProject)

// refuseRevokedHost returns errHelloHostRevoked when hostID (or, for an
// agent bound to no host, the reported hostname) names a revoked host of
// projectID. A lookup error lets the agent in (logged): a database blip
// must not refuse the fleet, and the stream's periodic re-check catches up.
func (s *Server) refuseRevokedHost(ctx context.Context, projectID, hostID, hostname string) error {
	if s.Repo == nil || s.Repo.Host == nil {
		return nil
	}
	var revoked bool
	var err error
	switch {
	case hostID != "":
		revoked, err = s.Repo.Host.HostRevoked(ctx, projectID, hostID)
	case hostname != "":
		// A live host claiming the name wins (a machine rebuilt under the
		// same OS hostname and registered as a new host, or a common name
		// like "ubuntu"): only a name no live host claims is refused.
		if live, lerr := s.Repo.Host.GetByName(ctx, projectID, hostname); lerr == nil && live != nil {
			return nil
		}
		revoked, err = s.Repo.Host.RevokedHostNamed(ctx, projectID, hostname)
	default:
		return nil
	}
	if err != nil {
		log.Printf("[agentserver] hello host check failed project=%s host=%q hostname=%q: %v (admitted)", projectID, hostID, hostname, err)
		return nil
	}
	if revoked {
		return errHelloHostRevoked
	}
	return nil
}

// registerErr maps an agent registration failure to its gRPC status.
func registerErr(what string, err error) error {
	if errors.Is(err, repository.ErrAgentLimit) {
		return errHelloAgentLimit
	}
	return status.Errorf(codes.Internal, "%s: %v", what, err)
}

// linkableHostByName returns the non-revoked host an agent reporting
// hostname belongs to: the host of that name (or reported hostname), else
// the host a sibling agent with that hostname is linked to. "" when none.
func (s *Server) linkableHostByName(ctx context.Context, projectID, hostname string) string {
	if hostname == "" {
		return ""
	}
	if host, err := s.Repo.Host.GetByName(ctx, projectID, hostname); err == nil && host != nil {
		return host.ID // GetByName skips revoked hosts
	}
	sibling := s.Repo.EBPF.GetHostIDByHostname(ctx, projectID, hostname)
	if sibling == "" {
		return ""
	}
	if revoked, err := s.Repo.Host.HostRevoked(ctx, projectID, sibling); err != nil || revoked {
		return ""
	}
	return sibling
}

// linkAgentByNameAsync links an unlinked agent to the host its hostname
// names, in the background (best effort, as before).
func (s *Server) linkAgentByNameAsync(projectID, agentID, hostname string) {
	if hostname == "" {
		return
	}
	go func() { //nolint:gosec // G118: best-effort link must outlive the Hello request context
		defer recoverPanic("link-agent-host")
		lCtx, lCancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer lCancel()
		if hostID := s.linkableHostByName(lCtx, projectID, hostname); hostID != "" {
			_ = s.Repo.EBPF.LinkAgentToHost(lCtx, projectID, agentID, hostID)
		}
	}()
}
