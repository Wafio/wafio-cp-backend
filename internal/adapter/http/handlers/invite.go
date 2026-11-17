package handlers

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"html"
	"log"
	"net/url"
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/jackc/pgx/v5"
	"github.com/wafio/wafio-cp-backend/internal/adapter/http/auth"
	"github.com/wafio/wafio-cp-backend/internal/adapter/repository"
	"github.com/wafio/wafio-cp-backend/internal/application"
	wemail "github.com/wafio/wafio-cp-backend/shared/email"
)

// InviteMail is the live mail configuration (application.MailSettings):
// the link base and the mail server are read at each use, so a change under
// Administration › Email (SMTP) applies without a restart.
type InviteMail interface {
	Current(ctx context.Context) (application.MailState, error)
	SendHTML(ctx context.Context, to, subject, body string) error
}

type InviteHandler struct {
	Repo *repository.Repository
	// Mail supplies links and delivery at each use. Without it BaseURL and
	// SMTP are a fixed configuration (tests).
	Mail    InviteMail
	BaseURL string
	SMTP    wemail.Config
}

// linkBase is the base of invitation links: the dashboard base URL in
// force, "" for relative links.
func (h *InviteHandler) linkBase(ctx context.Context) string {
	if h.Mail != nil {
		st, _ := h.Mail.Current(ctx) // on a storage error: the server configuration's part
		return st.LinkBase
	}
	return strings.TrimRight(h.BaseURL, "/")
}

// mailInvite sends an invitation email in the background when a mail server
// is in force; without one nothing is sent (the link is in the response).
// Nor is it sent while the link is not an absolute http(s) URL: without a
// dashboard base URL the API returns a relative link, which the dashboard
// completes with its own address, but a relative link in an email leads
// nowhere (email links never use the request Host).
func (h *InviteHandler) mailInvite(ctx context.Context, to, subject, inviteURL string, expiresAt time.Time) {
	var send func(ctx context.Context, to, subject, body string) error
	switch {
	case h.Mail != nil:
		// A storage error leaves the configuration's server, if any.
		if st, _ := h.Mail.Current(ctx); st.Server.Host == "" {
			return
		}
		send = h.Mail.SendHTML
	case h.SMTP.Host != "":
		cfg := h.SMTP
		send = func(_ context.Context, to, subject, body string) error {
			return wemail.SendHTML(cfg, to, subject, body)
		}
	default:
		return
	}
	if !isAbsoluteHTTPURL(inviteURL) {
		log.Printf("[invite] invitation email to %s not sent: no dashboard base URL (Administration › Email (SMTP) or server.base_url)", to)
		return
	}
	htmlBody := buildInviteEmail(inviteURL, expiresAt)
	go func() {
		sendCtx, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()
		if err := send(sendCtx, to, subject, htmlBody); err != nil {
			log.Printf("[invite] failed to send invite email to %s: %v", to, err)
		}
	}()
}

// isAbsoluteHTTPURL reports whether link is an absolute http(s) URL with a host.
func isAbsoluteHTTPURL(link string) bool {
	u, err := url.Parse(link)
	return err == nil && (u.Scheme == "http" || u.Scheme == "https") && u.Host != ""
}

type createInviteRequest struct {
	Email string `json:"email"`
}

type createProjectInviteRequest struct {
	Email string `json:"email"`
	Role  string `json:"role"`
}

func generateInviteToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func normalizeInviteRole(role string) (string, bool) {
	role = strings.ToLower(strings.TrimSpace(role))
	if role == "" {
		role = "member"
	}
	switch role {
	case "viewer", "member", "owner":
		return role, true
	default:
		return "", false
	}
}

func (h *InviteHandler) CreateInvite(c *fiber.Ctx) error {
	callerID, _ := c.Locals(auth.UserIDKey).(string)

	var body createInviteRequest
	_ = c.BodyParser(&body)
	body.Email = wemail.NormalizeEmail(body.Email)

	token, err := generateInviteToken()
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to generate token"})
	}
	// An open invite (no email) admits whoever holds the link, so it lives
	// for a day instead of a week.
	expiresAt := time.Now().Add(inviteTTL(body.Email))

	if err := h.Repo.InviteToken.Create(c.UserContext(), token, body.Email, callerID, "", "member", expiresAt); err != nil {
		if h.Repo.Audit != nil {
			_ = h.Repo.Audit.LogSystem(c.UserContext(), repository.SystemAuditEvent{
				ActorUserID: callerID,
				Action:      "admin.invite_created",
				TargetType:  "invite",
				TargetID:    body.Email,
				Outcome:     "failure",
				HTTPStatus:  fiber.StatusInternalServerError,
				IP:          c.IP(),
				UserAgent:   string(c.Request().Header.UserAgent()),
			})
		}
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to create invite"})
	}

	if h.Repo.Audit != nil {
		_ = h.Repo.Audit.LogSystem(c.UserContext(), repository.SystemAuditEvent{
			ActorUserID: callerID,
			Action:      "admin.invite_created",
			TargetType:  "invite",
			TargetID:    body.Email,
			Outcome:     "success",
			HTTPStatus:  fiber.StatusCreated,
			IP:          c.IP(),
			UserAgent:   string(c.Request().Header.UserAgent()),
		})
	}

	inviteURL := h.linkBase(c.UserContext()) + "/register?token=" + token

	if body.Email != "" {
		h.mailInvite(c.UserContext(), body.Email, "You've been invited to Wafio", inviteURL, expiresAt)
	}

	return c.Status(fiber.StatusCreated).JSON(fiber.Map{
		"token":      token,
		"invite_url": inviteURL,
		"email":      body.Email,
		"expires_at": expiresAt,
	})
}

func (h *InviteHandler) CreateProjectInvite(c *fiber.Ctx) error {
	projectID := c.Params("id")
	callerID, _ := c.Locals(auth.UserIDKey).(string)
	callerRole, _ := c.Locals(auth.UserRoleKey).(string)

	var body createProjectInviteRequest
	if err := c.BodyParser(&body); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid body"})
	}
	body.Email = wemail.NormalizeEmail(body.Email)
	if body.Email == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "email is required"})
	}
	role, ok := normalizeInviteRole(body.Role)
	if !ok {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "role must be 'viewer', 'member', or 'owner'"})
	}

	if callerRole != "admin" {
		memberRole, err := h.Repo.ProjectMember.GetRole(c.UserContext(), projectID, callerID)
		if err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to verify project access"})
		}
		if memberRole != "owner" {
			return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "owner access required"})
		}
	}

	if _, err := h.Repo.Project.GetByID(c.UserContext(), projectID); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "project not found"})
		}
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to load project"})
	}

	token, err := generateInviteToken()
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to generate token"})
	}
	expiresAt := time.Now().Add(7 * 24 * time.Hour)

	log.Printf("[invite] creating token: callerID=%q callerRole=%q projectID=%q email=%q role=%q", callerID, callerRole, projectID, body.Email, role)
	if err := h.Repo.InviteToken.CreateForProject(c.UserContext(), token, body.Email, callerID, projectID, role, expiresAt); err != nil {
		log.Printf("[invite] CreateForProject error: %v (callerID=%s projectID=%s email=%s role=%s)", err, callerID, projectID, body.Email, role)
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to create invite"})
	}

	inviteURL := h.linkBase(c.UserContext()) + "/invite/" + token
	h.mailInvite(c.UserContext(), body.Email, "You've been invited to join a Wafio project", inviteURL, expiresAt)

	_ = h.Repo.Audit.Log(c.UserContext(), repository.AuditEvent{ProjectID: projectID, ActorUserID: callerID, Action: "member.invite_created", TargetType: "invite", TargetName: body.Email, IP: c.IP(), UserAgent: string(c.Request().Header.UserAgent()), MetadataJSON: map[string]any{"role": role, "expires_at": expiresAt, "delivery": "unconfirmed"}})
	return c.Status(fiber.StatusCreated).JSON(fiber.Map{
		"token":      token,
		"invite_url": inviteURL,
		"email":      body.Email,
		"expires_at": expiresAt,
	})
}

// ListInvites returns every invitation (admin), paged with ?limit= (≤ 100;
// omitted = up to 100) and ?offset=. Each entry carries invite_url, the link
// the invitee opens, next to the raw token.
//
//	GET /api/admin/invites?limit=&offset=
func (h *InviteHandler) ListInvites(c *fiber.Ctx) error {
	all, err := h.Repo.InviteToken.List(c.UserContext())
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to list invites", "code": "INTERNAL_ERROR"})
	}
	page := parsePage(c, maxListLimit)
	list := pageOf(all, page)
	out := make([]fiber.Map, 0, len(list))
	base := h.linkBase(c.UserContext())
	for _, it := range list {
		// Same links CreateInvite and CreateProjectInvite hand out.
		inviteURL := base + "/register?token=" + it.Token
		if it.ProjectID != "" {
			inviteURL = base + "/invite/" + it.Token
		}
		out = append(out, fiber.Map{
			"token":      it.Token,
			"invite_url": inviteURL,
			"email":      it.Email,
			"created_by": it.CreatedBy,
			"project_id": it.ProjectID,
			"role":       it.Role,
			"expires_at": it.ExpiresAt,
			"used_at":    it.UsedAt,
			"created_at": it.CreatedAt,
		})
	}
	return c.JSON(fiber.Map{"invites": out, "total": len(all), "limit": page.Limit, "offset": page.Offset})
}

func (h *InviteHandler) DeleteInvite(c *fiber.Ctx) error {
	callerID, _ := c.Locals(auth.UserIDKey).(string)
	token := c.Params("token")
	targetID := "unknown"
	if it, err := h.Repo.InviteToken.GetByToken(c.UserContext(), token); err == nil && it.Email != "" {
		targetID = it.Email
	}
	if err := h.Repo.InviteToken.Delete(c.UserContext(), token); err != nil {
		if h.Repo.Audit != nil {
			_ = h.Repo.Audit.LogSystem(c.UserContext(), repository.SystemAuditEvent{
				ActorUserID: callerID,
				Action:      "admin.invite_deleted",
				TargetType:  "invite",
				TargetID:    targetID,
				Outcome:     "failure",
				HTTPStatus:  fiber.StatusInternalServerError,
				IP:          c.IP(),
				UserAgent:   string(c.Request().Header.UserAgent()),
			})
		}
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to delete invite"})
	}
	if h.Repo.Audit != nil {
		_ = h.Repo.Audit.LogSystem(c.UserContext(), repository.SystemAuditEvent{
			ActorUserID: callerID,
			Action:      "admin.invite_deleted",
			TargetType:  "invite",
			TargetID:    targetID,
			Outcome:     "success",
			HTTPStatus:  fiber.StatusOK,
			IP:          c.IP(),
			UserAgent:   string(c.Request().Header.UserAgent()),
		})
	}
	return c.JSON(fiber.Map{"ok": true})
}

func (h *InviteHandler) GetInviteInfo(c *fiber.Ctx) error {
	token := c.Params("token")
	it, err := h.Repo.InviteToken.GetByToken(c.UserContext(), token)
	if err != nil {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "invite not found"})
	}
	if it.UsedAt != nil {
		return c.Status(fiber.StatusGone).JSON(fiber.Map{"error": "invite already used"})
	}
	if time.Now().After(it.ExpiresAt) {
		return c.Status(fiber.StatusGone).JSON(fiber.Map{"error": "invite expired"})
	}

	projectName := ""
	if it.ProjectID != "" {
		project, err := h.Repo.Project.GetByID(c.UserContext(), it.ProjectID)
		if err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "invite not found"})
			}
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to load invite project"})
		}
		projectName = project.Name
	}

	userExists := false
	if inviteEmail := wemail.NormalizeEmail(it.Email); inviteEmail != "" {
		_, err := h.Repo.User.GetByEmail(c.UserContext(), inviteEmail)
		switch {
		case err == nil:
			userExists = true
		case errors.Is(err, pgx.ErrNoRows):
			userExists = false
		default:
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to look up invited user"})
		}
	}

	return c.JSON(fiber.Map{
		"email":        it.Email,
		"project_id":   it.ProjectID,
		"project_name": projectName,
		"role":         it.Role,
		"user_exists":  userExists,
		"expires_at":   it.ExpiresAt,
	})
}

func (h *InviteHandler) AcceptInvite(c *fiber.Ctx) error {
	userID, _ := c.Locals(auth.UserIDKey).(string)
	userEmail, _ := c.Locals(auth.UserEmailKey).(string)
	if userID == "" {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "authentication required"})
	}

	token := c.Params("token")
	it, err := h.Repo.InviteToken.GetByToken(c.UserContext(), token)
	if err != nil {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "invite not found"})
	}
	if it.ProjectID == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invite is not a project invite"})
	}
	if it.UsedAt != nil {
		return c.Status(fiber.StatusGone).JSON(fiber.Map{"error": "invite already used"})
	}
	if time.Now().After(it.ExpiresAt) {
		return c.Status(fiber.StatusGone).JSON(fiber.Map{"error": "invite expired"})
	}
	emailMatches := func(inv *repository.InviteToken) error {
		if inviteEmail := wemail.NormalizeEmail(inv.Email); inviteEmail != "" && inviteEmail != wemail.NormalizeEmail(userEmail) {
			return errInviteWrongRecipient
		}
		return nil
	}
	if emailMatches(it) != nil {
		return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "this invite was sent to a different email address"})
	}

	// Claim, membership and audit in one transaction; of two concurrent
	// accepts of one token only the first succeeds.
	it, _, err = h.Repo.InviteToken.AcceptProjectInvite(c.UserContext(), token, userID, emailMatches,
		func(inv *repository.InviteToken) repository.AuditEvent {
			return repository.AuditEvent{
				ActorUserID: userID, Action: repository.AuditMemberJoinedByInvite,
				TargetType: "user", TargetID: userID, TargetName: userEmail,
				IP: c.IP(), UserAgent: string(c.Request().Header.UserAgent()),
				MetadataJSON: map[string]any{"role": inv.Role, "via": "accept"},
			}
		})
	switch {
	case err == nil:
	case errors.Is(err, repository.ErrInviteUnavailable):
		return c.Status(fiber.StatusGone).JSON(fiber.Map{"error": "invite already used or expired"})
	case errors.Is(err, errInviteWrongRecipient):
		return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "this invite was sent to a different email address"})
	default:
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to add project member"})
	}

	return c.JSON(fiber.Map{
		"project_id": it.ProjectID,
		"role":       it.Role,
		"ok":         true,
	})
}

var errInviteWrongRecipient = errors.New("invite sent to a different email address")

// Invite lifetimes: an invite bound to an email lasts a week; an open admin
// invite, redeemable by anyone who sees the link, a day.
const (
	inviteTTLAddressed = 7 * 24 * time.Hour
	inviteTTLOpen      = 24 * time.Hour
)

func inviteTTL(email string) time.Duration {
	if email == "" {
		return inviteTTLOpen
	}
	return inviteTTLAddressed
}

func buildInviteEmail(inviteURL string, expiresAt time.Time) string {
	expiry := expiresAt.Format("2 January 2006, 15:04 UTC")
	safeURL := html.EscapeString(inviteURL)

	var sb strings.Builder
	sb.WriteString(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>You're invited to Wafio</title>
<style>
  body{margin:0;padding:0;background:#0b0e14;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;color:#e2e8f0}
  .wrap{max-width:560px;margin:40px auto;padding:0 16px}
  .card{background:#141720;border:1px solid rgba(255,255,255,0.08);border-radius:12px;overflow:hidden}
  .header{background:linear-gradient(135deg,#0d1520 0%,#0f2030 100%);padding:36px 40px;text-align:center;border-bottom:1px solid rgba(20,184,166,0.2)}
  .logo{display:inline-flex;align-items:center;gap:10px}
  .logo-icon{width:40px;height:40px;background:rgba(20,184,166,0.15);border-radius:10px;border:1px solid rgba(20,184,166,0.3);display:inline-flex;align-items:center;justify-content:center;vertical-align:middle}
  .logo-text{font-size:22px;font-weight:700;color:#fff;letter-spacing:-0.3px;vertical-align:middle}
  .logo-text span{color:#14b8a6}
  .body{padding:40px}
  .badge{display:inline-block;background:rgba(20,184,166,0.12);color:#14b8a6;border:1px solid rgba(20,184,166,0.25);border-radius:99px;font-size:12px;font-weight:600;letter-spacing:0.05em;text-transform:uppercase;padding:4px 12px;margin-bottom:20px}
  h1{margin:0 0 12px;font-size:24px;font-weight:700;color:#f1f5f9;line-height:1.3}
  p{margin:0 0 16px;font-size:15px;line-height:1.7;color:#94a3b8}
  .cta-wrap{text-align:center;margin:32px 0}
  .cta{display:inline-block;background:#14b8a6;color:#fff;text-decoration:none;font-weight:600;font-size:15px;padding:14px 36px;border-radius:8px;letter-spacing:0.01em}
  .divider{border:none;border-top:1px solid rgba(255,255,255,0.06);margin:28px 0}
  .meta{background:rgba(255,255,255,0.03);border-radius:8px;padding:16px 20px;margin:0 0 24px}
  .meta-label{font-size:13px;color:#64748b;font-weight:500}
  .meta-value{font-size:13px;color:#cbd5e1;font-weight:600;float:right}
  .url-box{background:#0b0e14;border:1px solid rgba(255,255,255,0.08);border-radius:6px;padding:10px 14px;margin:12px 0 0;word-break:break-all}
  .url-box a{color:#38bdf8;font-size:12px;font-family:monospace;text-decoration:none}
  .footer{padding:24px 40px;border-top:1px solid rgba(255,255,255,0.06);text-align:center}
  .footer p{font-size:12px;color:#475569;margin:0 0 4px;line-height:1.6}
  .footer a{color:#64748b;text-decoration:none}
  @media(max-width:600px){.body,.header,.footer{padding-left:24px;padding-right:24px}}
</style>
</head>
<body>
<div class="wrap">
  <div class="card">
    <div class="header">
      <div class="logo">
        <div class="logo-icon">
          <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="#14b8a6" stroke-width="2"><path d="M12 2l8 4v6c0 5-3.5 9.4-8 10-4.5-.6-8-5-8-10V6l8-4z"/></svg>
        </div>
        &nbsp;<span class="logo-text">Waf<span>io</span></span>
      </div>
    </div>
    <div class="body">
      <div class="badge">&#x2709; Invitation</div>
      <h1>You've been invited to join Wafio</h1>
      <p>An administrator has created an account invitation for you on <strong style="color:#e2e8f0">Wafio</strong>, a web application firewall and eBPF host firewall.</p>
      <p>Click the button below to set up your account and get started:</p>
      <div class="cta-wrap">
        <a href="` + safeURL + `" class="cta">Accept Invitation &#x2192;</a>
      </div>
      <hr class="divider"/>
      <div class="meta">
        <span class="meta-label">&#x23F0; Link expires</span>
        <span class="meta-value">` + expiry + `</span>
        <div style="clear:both"></div>
      </div>
      <p style="font-size:13px;color:#64748b;margin-bottom:4px">If the button above doesn't work, copy and paste this link into your browser:</p>
      <div class="url-box"><a href="` + safeURL + `">` + safeURL + `</a></div>
    </div>
    <div class="footer">
      <p>This invitation was sent by a Wafio administrator.</p>
      <p>If you weren't expecting this, you can safely ignore this email — no account will be created without your action.</p>
      <p style="margin-top:12px"><a href="#">Wafio Security Platform</a></p>
    </div>
  </div>
</div>
</body>
</html>`)
	return sb.String()
}

func (h *InviteHandler) ListProjectInvites(c *fiber.Ctx) error {
	limit, offset := c.QueryInt("limit", 20), c.QueryInt("offset", 0)
	if limit < 1 || limit > 100 || offset < 0 {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid pagination"})
	}
	list, total, err := h.Repo.InviteToken.ListPendingProject(c.UserContext(), c.Params("id"), limit, offset)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to list invitations"})
	}
	out := make([]fiber.Map, 0, len(list))
	base := h.linkBase(c.UserContext())
	for _, invite := range list {
		out = append(out, fiber.Map{"token": invite.Token, "email": invite.Email, "role": invite.Role, "expires_at": invite.ExpiresAt, "invite_url": base + "/invite/" + invite.Token})
	}
	return c.JSON(fiber.Map{"invites": out, "total": total})
}

func (h *InviteHandler) DeleteProjectInvite(c *fiber.Ctx) error {
	projectID := c.Params("id")
	deleted, err := h.Repo.InviteToken.DeleteProject(c.UserContext(), projectID, c.Params("token"))
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to revoke invitation"})
	}
	if !deleted {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "invitation not found"})
	}
	userID, _ := c.Locals(auth.UserIDKey).(string)
	_ = h.Repo.Audit.Log(c.UserContext(), repository.AuditEvent{ProjectID: projectID, ActorUserID: userID, Action: "member.invite_revoked", TargetType: "invite", IP: c.IP(), UserAgent: string(c.Request().Header.UserAgent())})
	return c.JSON(fiber.Map{"ok": true})
}
