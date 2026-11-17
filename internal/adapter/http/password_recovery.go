package httpadapter

import (
	"github.com/wafio/wafio-cp-backend/internal/adapter/repository"
	"github.com/wafio/wafio-cp-backend/internal/application"
	"github.com/wafio/wafio-cp-backend/internal/config"
	"github.com/wafio/wafio-cp-backend/internal/domain"
)

// newMailSettings builds the control plane's live mail configuration: the
// server configuration's smtp block and server.base_url where they are
// set, else what an administrator saved (system_settings "smtp_settings",
// password encrypted with the TOTP encryption key).
func newMailSettings(cfg *config.Config, repo *repository.Repository) *application.MailSettings {
	ms := &application.MailSettings{Server: application.MailServerConfig{
		Host:       cfg.SMTP.Host,
		Port:       cfg.SMTP.Port,
		Encryption: cfg.SMTP.Encryption,
		Username:   cfg.SMTP.Username,
		Password:   cfg.SMTP.Password,
		From:       cfg.SMTP.From,
		BaseURL:    cfg.Server.BaseURL,
	}}
	if repo != nil && repo.SystemSettings != nil {
		ms.Store = repo.SystemSettings
	}
	if repo != nil && repo.User != nil && repo.User.TOTPCrypto != nil {
		ms.Crypto = repo.User.TOTPCrypto
	}
	return ms
}

// newPasswordRecovery builds the password recovery service
// on the live mail configuration: email recovery is on while a mail server
// and an absolute dashboard base URL are in force. Reset links always
// point at that base URL, never at the request's Host header.
//
// Whether it is on is shown under Administration › Email (SMTP)
// (recovery_available) and by GET /api/auth/recovery; it can change at any
// save, so nothing is logged at boot.
func newPasswordRecovery(repo *repository.Repository, mail *application.MailSettings) *application.PasswordRecovery {
	var store domain.PasswordResetStore
	if repo != nil && repo.PasswordReset != nil {
		store = repo.PasswordReset
	}
	return application.NewPasswordRecovery(application.PasswordRecoveryConfig{Store: store, Mail: mail})
}
