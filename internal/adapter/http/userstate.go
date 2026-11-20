package httpadapter

import (
	"context"
	"crypto/x509"

	"github.com/wafio/wafio-cp-backend/internal/adapter/http/auth"
	"github.com/wafio/wafio-cp-backend/internal/adapter/http/handlers"
	"github.com/wafio/wafio-cp-backend/internal/adapter/repository"
	"github.com/wafio/wafio-cp-backend/internal/application"
	"github.com/wafio/wafio-cp-backend/shared/metrics"
)

// AppOption adjusts NewFiberApp.
type AppOption func(*appOptions)

type appOptions struct {
	tlsResolver      handlers.HostResolver
	tlsRoots         *x509.CertPool
	userStateLoader  auth.UserStateLoader
	metrics          *metrics.Registry
	geoRanges        handlers.GeoRangeSource
	passwordRecovery *application.PasswordRecovery
	storage          *application.Storage
}

// WithAppTLS replaces what the TLS endpoints use outside the database: the resolver behind the
// dns_mismatch warning and the roots that decide whether an uploaded chain is trusted. Nil keeps the
// system resolver and the system roots. For tests, which must not touch the network.
func WithAppTLS(resolver handlers.HostResolver, roots *x509.CertPool) AppOption {
	return func(o *appOptions) { o.tlsResolver, o.tlsRoots = resolver, roots }
}

// WithStorage replaces the data retention / database size service
// NewFiberApp builds from repo (tests: fake stores). The caller runs its
// loop (Run); NewFiberApp starts Run only for the service it builds.
func WithStorage(s *application.Storage) AppOption {
	return func(o *appOptions) { o.storage = s }
}

func resolveOptions(opts []AppOption) appOptions {
	var o appOptions
	for _, apply := range opts {
		apply(&o)
	}
	return o
}

// WithGeoRanges gives the host firewall handlers the control plane's GeoIP
// country database, for the geo capacity check at save. Nil (no database)
// leaves the check to the host agent.
func WithGeoRanges(src handlers.GeoRangeSource) AppOption {
	return func(o *appOptions) { o.geoRanges = src }
}

// WithPasswordRecovery replaces the password recovery service NewFiberApp
// builds from cfg (tests: a stub mailer, a fixed base URL). The caller runs
// its worker (Run); NewFiberApp starts Run only for the service it builds.
func WithPasswordRecovery(r *application.PasswordRecovery) AppOption {
	return func(o *appOptions) { o.passwordRecovery = r }
}

// WithUserStateLoader replaces the users-table lookup behind token
// revocation. For tests that run the real app without a database.
func WithUserStateLoader(load auth.UserStateLoader) AppOption {
	return func(o *appOptions) { o.userStateLoader = load }
}

// newUserStates builds the RequireJWT user-state cache: the users row by
// default, the WithUserStateLoader override when given.
func newUserStates(repo *repository.Repository, opts []AppOption) *auth.UserStates {
	var o appOptions
	for _, apply := range opts {
		apply(&o)
	}
	load := o.userStateLoader
	if load == nil {
		load = func(ctx context.Context, userID string) (auth.UserState, error) {
			st, err := repo.User.AuthState(ctx, userID)
			if err != nil {
				return auth.UserState{}, err
			}
			return auth.UserState{Exists: st.Exists, Role: st.Role, TokenVersion: st.TokenVersion}, nil
		}
	}
	return auth.NewUserStates(load, auth.UserStateTTL)
}

// streamAccess is the handlers.StreamGuard of the SSE routes: the same
// checks RequireJWT and RequireProjectAccess made when the stream opened,
// repeated while it stays open.
type streamAccess struct {
	users *auth.UserStates
	// memberRole returns the user's project role ("" = not a member).
	memberRole func(ctx context.Context, projectID, userID string) (string, error)
}

func newStreamAccess(repo *repository.Repository, users *auth.UserStates) streamAccess {
	return streamAccess{users: users, memberRole: repo.ProjectMember.GetRole}
}

// StillAllowed fails closed: any lookup error ends the stream (the client
// reconnects through the full authorization).
func (s streamAccess) StillAllowed(ctx context.Context, sub handlers.StreamSubject) bool {
	st, err := s.users.Get(ctx, sub.UserID)
	if err != nil || !st.Exists || sub.TokenVersion < st.TokenVersion {
		return false
	}
	if st.Role == "admin" {
		return true // RequireProjectAccess lets system admins into every project
	}
	role, err := s.memberRole(ctx, sub.ProjectID, sub.UserID)
	return err == nil && role != "" && roleLevel(role) >= roleLevel(sub.MinRole)
}
