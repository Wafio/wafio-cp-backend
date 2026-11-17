package handlers

import (
	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
)

// Overview parameter checks. Every Overview parameter is part of the
// response cache key, so each is bounded before it can reach the cache.

// clampBucketSecs keeps the Overview timeline between one bucket and 1,440
// buckets for the window (and at least 60 s per bucket), so bucket_seconds
// cannot ask for an unbounded series.
func clampBucketSecs(b, minutes int) int {
	window := minutes * 60
	lo := max(60, (window+1439)/1440)
	hi := max(lo, window)
	return min(max(b, lo), hi)
}

// isCanonicalUUID reports an empty string or a lower-case hyphenated UUID.
func isCanonicalUUID(s string) bool {
	if s == "" {
		return true
	}
	u, err := uuid.Parse(s)
	return err == nil && u.String() == s
}

// overviewScopeOwned checks the optional host and WAF agent filters of the
// Overview against the project: "" when both are absent or belong to it,
// else the error code of the one that does not (answered as 404, like any
// cross-tenant id), or err for a lookup failure (answered as 500).
func (h *WAFAgentHandler) overviewScopeOwned(c *fiber.Ctx, projectID, hostID, wafAgentID string) (string, error) {
	if hostID != "" {
		host, err := h.Repo.Host.GetByID(c.UserContext(), projectID, hostID)
		switch {
		case err != nil && !isNotFoundOrInvalidID(err):
			return "", err
		case err != nil || host == nil:
			return "HOST_NOT_FOUND", nil
		}
	}
	if wafAgentID != "" {
		agent, err := h.Repo.EBPF.GetAgentByID(c.UserContext(), wafAgentID)
		switch {
		case err != nil && !isNotFoundOrInvalidID(err):
			return "", err
		case err != nil || agent == nil || agent.ProjectID != projectID:
			return "AGENT_NOT_FOUND", nil
		}
	}
	return "", nil
}
