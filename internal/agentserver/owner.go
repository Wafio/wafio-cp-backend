package agentserver

import (
	"context"
	"time"
)

// ownerLookupTimeout bounds the one query a project's first owner lookup
// costs (later lookups are cache hits).
const ownerLookupTimeout = 2 * time.Second

// projectOwner names the account that owns projectID, for the per-account
// fair share of the shared queues and tables. It is cached by the
// repository (a hit is a map lookup); a project whose owner cannot be read is
// charged to itself, never to another account.
func (s *Server) projectOwner(projectID string) string {
	if s == nil {
		return projectID
	}
	if s.ownerOf != nil {
		return s.ownerOf(projectID)
	}
	if s.Repo == nil || s.Repo.Project == nil {
		return projectID
	}
	// Cache first: the context below allocates, and this runs once per
	// WAF decision.
	if owner, known := s.Repo.Project.CachedOwner(projectID); known {
		if owner == "" {
			return projectID
		}
		return owner
	}
	ctx, cancel := context.WithTimeout(context.Background(), ownerLookupTimeout)
	defer cancel()
	return s.Repo.Project.OwnerOrSelf(ctx, projectID)
}
