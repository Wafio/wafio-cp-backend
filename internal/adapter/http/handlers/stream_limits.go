package handlers

import (
	"context"
	"errors"
	"strconv"
	"sync"

	"github.com/gofiber/fiber/v2"
	"github.com/wafio/wafio-cp-backend/internal/adapter/repository"
)

// streamLimiter caps open dashboard SSE streams per project, per user per
// project, per user and process-wide, like the decision broker does for the
// live-decision streams. Every stream is a held connection and a
// goroutine, and the WAF liveness stream also runs a query every 5 s, so a
// stream with only a process-wide cap (or none, as /waf/stream once had)
// let one account hold every slot -- or the database pool. The per-user
// ceilings keep one account, even one with access to many projects, from
// taking every slot. The per-owner ceiling counts every stream of
// every project one account owns (projects.user_id), whoever opened it: one
// person minting accounts and inviting them to their own projects is held
// to a fair part of the process-wide cap.
//
// The zero value is ready to use; the caps are passed to acquire.
type streamLimiter struct {
	mu           sync.Mutex
	open         int
	projects     map[string]int
	users        map[string]int
	userProjects map[streamUserProject]int
	owners       map[string]int
}

// streamCaps are a stream's ceilings (0 admits nothing).
type streamCaps struct {
	perProject, perUserProject, perUser, perOwner, total int
}

type streamUserProject struct{ user, project string }

var (
	// errStreamLimitProject: the project or the process is at its ceiling.
	errStreamLimitProject = errors.New("stream limit reached for the project")
	// errStreamLimitUser: the user is at a per-user ceiling.
	errStreamLimitUser = errors.New("stream limit reached for the user")
	// errStreamLimitOwner: the projects of the project's owner are at
	// their ceiling.
	errStreamLimitOwner = errors.New("stream limit reached for the projects of the owner")
)

// acquire reserves a slot for userID in projectID under caps, or says which
// ceiling refused it. ownerID is the account owning the project; "" skips
// the per-owner ceiling.
func (l *streamLimiter) acquire(projectID, ownerID, userID string, caps streamCaps) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.projects == nil {
		l.projects = make(map[string]int)
		l.users = make(map[string]int)
		l.userProjects = make(map[streamUserProject]int)
		l.owners = make(map[string]int)
	}
	up := streamUserProject{userID, projectID}
	if l.users[userID] >= caps.perUser || l.userProjects[up] >= caps.perUserProject {
		return errStreamLimitUser
	}
	if l.projects[projectID] >= caps.perProject || l.open >= caps.total {
		return errStreamLimitProject
	}
	if ownerID != "" && l.owners[ownerID] >= caps.perOwner {
		return errStreamLimitOwner
	}
	l.open++
	l.projects[projectID]++
	l.users[userID]++
	l.userProjects[up]++
	if ownerID != "" {
		l.owners[ownerID]++
	}
	return nil
}

// release frees a slot acquire handed out (same arguments).
func (l *streamLimiter) release(projectID, ownerID, userID string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.open--
	decrementOrDelete(l.projects, projectID)
	decrementOrDelete(l.users, userID)
	decrementOrDelete(l.userProjects, streamUserProject{userID, projectID})
	if ownerID != "" {
		decrementOrDelete(l.owners, ownerID)
	}
}

// streamProjectOwner names the account owning projectID for the per-owner
// stream ceiling: ownerOf when set (tests), else the repository's cached
// lookup; a project whose owner cannot be read counts as its own owner.
func streamProjectOwner(ctx context.Context, repo *repository.Repository, ownerOf func(string) string, projectID string) string {
	if ownerOf != nil {
		return ownerOf(projectID)
	}
	if repo == nil || repo.Project == nil {
		return projectID
	}
	return repo.Project.OwnerOrSelf(ctx, projectID)
}

// count is the number of open streams.
func (l *streamLimiter) count() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.open
}

func decrementOrDelete[K comparable](m map[K]int, k K) {
	if n := m[k] - 1; n > 0 {
		m[k] = n
	} else {
		delete(m, k)
	}
}

// sseStreamLimitResponse answers a refused stream with 429 STREAM_LIMIT,
// naming the ceiling that refused it: the account's, the project owner's
// (with its size, perOwner) or the project's.
func sseStreamLimitResponse(c *fiber.Ctx, err error, what string, perOwner int) error {
	msg := "too many open " + what + " streams for this project; close an existing one and retry"
	switch {
	case errors.Is(err, errStreamLimitUser):
		msg = "too many open " + what + " streams for this account; close an existing one and retry"
	case errors.Is(err, errStreamLimitOwner):
		msg = ownerStreamLimitMessage(what, perOwner)
	}
	return c.Status(fiber.StatusTooManyRequests).JSON(fiber.Map{"error": msg, "code": "STREAM_LIMIT"})
}

// ownerStreamLimitMessage names the per-owner ceiling.
func ownerStreamLimitMessage(what string, perOwner int) string {
	return "too many open " + what + " streams across the projects of this project's owner (limit " +
		strconv.Itoa(perOwner) + "); close an existing one and retry"
}
