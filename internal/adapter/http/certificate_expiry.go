package httpadapter

import (
	"context"

	"github.com/wafio/wafio-cp-backend/internal/adapter/repository"
	"github.com/wafio/wafio-cp-backend/internal/application"
)

// certificateExpiryStore gives the expiry warnings the TLS tables and the project members.
type certificateExpiryStore struct {
	*repository.TLSRepo
	members *repository.ProjectMemberRepo
}

func (s certificateExpiryStore) Members(ctx context.Context, projectID string) ([]application.ExpiryMember, error) {
	list, err := s.members.List(ctx, projectID)
	if err != nil {
		return nil, err
	}
	out := make([]application.ExpiryMember, len(list))
	for i, m := range list {
		out[i] = application.ExpiryMember{Email: m.UserEmail, Role: m.Role}
	}
	return out, nil
}

// newCertificateExpiry returns the certificate expiry warnings, whose loop it starts on ctx. Nil
// without a database (handler tests without one).
func newCertificateExpiry(ctx context.Context, repo *repository.Repository, mail *application.MailSettings) *application.CertificateExpiry {
	if repo == nil || repo.DB == nil || repo.TLS == nil || repo.ProjectMember == nil || mail == nil {
		return nil
	}
	s := &application.CertificateExpiry{
		Store: certificateExpiryStore{TLSRepo: repo.TLS, members: repo.ProjectMember},
		Mail:  mail,
	}
	go s.Run(ctx)
	return s
}
