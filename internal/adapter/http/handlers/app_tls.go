package handlers

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"net"
	"net/netip"
	"slices"
	"sync"
	"time"
	"unicode/utf16"
	"unicode/utf8"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/wafio/wafio-cp-backend/internal/adapter/http/auth"
	"github.com/wafio/wafio-cp-backend/internal/adapter/repository"
	"github.com/wafio/wafio-cp-backend/internal/domain"
	"github.com/wafio/wafio-cp-backend/internal/otp"
)

// HostResolver looks up the addresses of a host name. *net.Resolver is one.
type HostResolver interface {
	LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error)
}

// AppTLSHandler serves how an application is served over TLS: the settings, the uploaded
// certificate with its private key, and the request for an ACME certificate. No answer carries the
// key: the views below have no field for it.
type AppTLSHandler struct {
	Repo        *repository.Repository
	AgentServer interface{ PushBundleToProject(projectID string) }
	// Resolver looks up the hosts for the dns_mismatch warning; nil uses the system resolver.
	Resolver HostResolver
	// Roots decide whether an uploaded chain is trusted; nil uses the system roots.
	Roots *x509.CertPool
}

const (
	// tlsDNSBudget is the time all lookups of one save share. A save never waits longer for a warning.
	tlsDNSBudget   = 2 * time.Second
	tlsDNSParallel = 8
	// tlsResolvedShown caps the addresses a dns_mismatch warning lists for one host.
	tlsResolvedShown = 8

	// The days left at or below which a certificate gets the expires_soon warning. An ACME
	// certificate renews itself a third of the way through its life, so for it the warning means that
	// the renewal is late.
	tlsExpiresSoonUploadedDays = 30
	tlsExpiresSoonACMEDays     = 14
)

// Codes and names of the TLS answers.
const (
	tlsWarnNotTrusted  = "not_trusted"
	tlsWarnExpiresSoon = "expires_soon"
	tlsWarnDNSMismatch = "dns_mismatch"

	tlsCodeInvalidCert = "INVALID_CERTIFICATE"
	tlsCodeInvalidTLS  = "INVALID_TLS_SETTINGS"
	tlsCodeKeyEncrypt  = "KEY_ENCRYPTION_UNAVAILABLE"

	// tlsFieldUploadBody names the whole request of an upload that is too large to read a field from.
	tlsFieldUploadBody = "body"
)

// ── Views ─────────────────────────────────────────────────────────────────

type tlsCertificateView struct {
	ID         string    `json:"id"`
	Source     string    `json:"source"`
	Names      []string  `json:"names"`
	Issuer     string    `json:"issuer"`
	NotBefore  time.Time `json:"not_before"`
	NotAfter   time.Time `json:"not_after"`
	DaysLeft   int       `json:"days_left"`
	LeafSHA256 string    `json:"leaf_sha256"`
	KeyType    string    `json:"key_type"`
	Trusted    bool      `json:"trusted"`
	CreatedAt  time.Time `json:"created_at"`
}

type tlsACMEView struct {
	RequestID   string     `json:"request_id"`
	RequestedAt *time.Time `json:"requested_at"`
}

type tlsStatusView struct {
	AgentID       string     `json:"agent_id"`
	Source        string     `json:"source"`
	State         string     `json:"state"`
	CertificateID *string    `json:"certificate_id"`
	LeafSHA256    string     `json:"leaf_sha256"`
	Error         string     `json:"error"`
	NextAttemptAt *time.Time `json:"next_attempt_at"`
	RequestID     string     `json:"request_id"`
	ReceivedAt    time.Time  `json:"received_at"`
	Names         []string   `json:"names"`
	Issuer        string     `json:"issuer"`
	NotBefore     *time.Time `json:"not_before"`
	NotAfter      *time.Time `json:"not_after"`
}

type tlsWarning struct {
	Code           string     `json:"code"`
	Host           string     `json:"host,omitempty"`
	Resolved       []string   `json:"resolved,omitempty"`
	AgentAddresses []string   `json:"agent_addresses,omitempty"`
	DaysLeft       *int       `json:"days_left,omitempty"`
	NotAfter       *time.Time `json:"not_after,omitempty"`
}

type tlsStateView struct {
	Mode           string              `json:"mode"`
	Hosts          []string            `json:"hosts"`
	Listen         string              `json:"listen"`
	RedirectListen string              `json:"redirect_listen"`
	Source         string              `json:"source"`
	Certificate    *tlsCertificateView `json:"certificate"`
	ACME           *tlsACMEView        `json:"acme"`
	Status         *tlsStatusView      `json:"status"`
	AgentSupported *bool               `json:"agent_supported"`
	AgentHostBound *bool               `json:"agent_host_bound"`
	Warnings       []tlsWarning        `json:"warnings"`
}

// tlsRead is what the TLS endpoints read about one application.
type tlsRead struct {
	tls    repository.AppTLS
	cert   *repository.AppCertificate
	agent  *repository.TLSAgent
	status *repository.TLSStatus
}

func daysLeft(notAfter, now time.Time) int {
	return int(math.Floor(notAfter.Sub(now).Hours() / 24))
}

func certificateView(c repository.AppCertificate, now time.Time) *tlsCertificateView {
	return &tlsCertificateView{
		ID: c.ID, Source: c.Source, Names: c.Names, Issuer: c.Issuer,
		NotBefore: c.NotBefore.UTC(), NotAfter: c.NotAfter.UTC(), DaysLeft: daysLeft(c.NotAfter, now),
		LeafSHA256: c.LeafSHA256, KeyType: c.KeyType, Trusted: c.Trusted, CreatedAt: c.CreatedAt.UTC(),
	}
}

func utcOrNil(t *time.Time) *time.Time {
	if t == nil {
		return nil
	}
	u := t.UTC()
	return &u
}

func statusView(s *repository.TLSStatus) *tlsStatusView {
	if s == nil {
		return nil
	}
	v := &tlsStatusView{
		AgentID: s.AgentID, Source: s.Source, State: s.State, LeafSHA256: s.LeafSHA256, Error: s.Error,
		NextAttemptAt: utcOrNil(s.NextAttemptAt), RequestID: s.RequestID, ReceivedAt: s.ReceivedAt.UTC(),
		Names: s.Names, Issuer: s.Issuer, NotBefore: utcOrNil(s.NotBefore), NotAfter: utcOrNil(s.NotAfter),
	}
	if s.CertificateID != "" {
		v.CertificateID = &s.CertificateID
	}
	return v
}

// stateWarnings are the warnings that follow from what is stored.
func (r tlsRead) stateWarnings(now time.Time) []tlsWarning {
	out := []tlsWarning{}
	soon := func(notAfter time.Time, limit int) {
		if d := daysLeft(notAfter, now); d <= limit {
			na := notAfter.UTC()
			out = append(out, tlsWarning{Code: tlsWarnExpiresSoon, DaysLeft: &d, NotAfter: &na})
		}
	}
	switch r.tls.Source {
	case domain.TLSSourceUploaded:
		if r.cert != nil {
			if !r.cert.Trusted {
				out = append(out, tlsWarning{Code: tlsWarnNotTrusted})
			}
			soon(r.cert.NotAfter, tlsExpiresSoonUploadedDays)
		}
	case domain.TLSSourceACME:
		if r.status != nil && r.status.Source == domain.TLSSourceACME && r.status.NotAfter != nil {
			soon(*r.status.NotAfter, tlsExpiresSoonACMEDays)
		}
	}
	return out
}

func (r tlsRead) view(now time.Time) tlsStateView {
	v := tlsStateView{
		Mode: r.tls.Mode, Hosts: r.tls.Hosts, Listen: r.tls.Listen, RedirectListen: r.tls.RedirectListen, Source: r.tls.Source,
		Status: statusView(r.status), Warnings: r.stateWarnings(now),
	}
	if r.cert != nil {
		v.Certificate = certificateView(*r.cert, now)
	}
	if r.tls.ACMERequestID != "" {
		v.ACME = &tlsACMEView{RequestID: r.tls.ACMERequestID, RequestedAt: utcOrNil(r.tls.ACMERequestedAt)}
	}
	if r.agent != nil {
		v.AgentSupported = r.agent.Supported
		bound := r.agent.HostBound
		v.AgentHostBound = &bound
	}
	return v
}

func (h *AppTLSHandler) read(ctx context.Context, projectID, appID string) (tlsRead, error) {
	var r tlsRead
	var err error
	if r.tls, r.cert, err = h.Repo.TLS.GetTLS(ctx, projectID, appID); err != nil {
		return r, err
	}
	if r.agent, err = h.Repo.TLS.GetTLSAgent(ctx, projectID, appID); err != nil {
		return r, err
	}
	r.status, err = h.Repo.TLS.GetTLSStatus(ctx, projectID, appID)
	return r, err
}

// ── Answers ───────────────────────────────────────────────────────────────

func tlsAnswer(c *fiber.Ctx, status int, code, text string, extra fiber.Map) error {
	body := fiber.Map{"error": text, "code": code}
	for k, v := range extra {
		body[k] = v
	}
	return c.Status(status).JSON(body)
}

// tlsRefused answers the refusals of the TLS checks. They come from the TLS endpoints and from the
// edits of an application that can place it next to a TLS listener. handled is false for any other
// error, which the caller maps as it always did.
func tlsRefused(c *fiber.Ctx, err error) (handled bool, answered error) {
	var field *domain.TLSFieldError
	var conflict *domain.TLSConflictError
	var coverage *repository.TLSCoverageError
	var soon *repository.ACMETooSoonError
	switch {
	case errors.As(err, &field):
		return true, tlsAnswer(c, fiber.StatusBadRequest, tlsCodeInvalidTLS, field.Error(), fiber.Map{"field": field.Field})
	case errors.As(err, &conflict):
		return true, tlsAnswer(c, fiber.StatusConflict, conflict.Code, conflict.Error(), fiber.Map{"field": conflict.Field})
	case errors.As(err, &coverage):
		return true, tlsAnswer(c, fiber.StatusConflict, "CERTIFICATE_DOES_NOT_COVER",
			"The current certificate does not cover "+coverage.Host+". Upload a certificate that covers every host, or change the hosts.",
			fiber.Map{"host": coverage.Host})
	case errors.As(err, &soon):
		return true, tlsAnswer(c, fiber.StatusConflict, "ACME_REQUEST_TOO_SOON", soon.Error(),
			fiber.Map{"retry_after": int(soon.RetryAfter.Seconds()) + 1})
	case errors.Is(err, repository.ErrTLSUnsupported):
		return true, tlsAnswer(c, fiber.StatusConflict, "TLS_UNSUPPORTED",
			"The WAF agent that serves this application does not serve TLS certificates. Upgrade the agent first.", nil)
	case errors.Is(err, repository.ErrCertificateRequired):
		return true, tlsAnswer(c, fiber.StatusConflict, "CERTIFICATE_REQUIRED",
			"Upload a certificate that is valid now before you use an uploaded certificate.", nil)
	case errors.Is(err, repository.ErrAgentNotHostBound):
		return true, tlsAnswer(c, fiber.StatusConflict, "AGENT_NOT_HOST_BOUND",
			"The WAF agent that serves this application has no credential bound to its host, so it cannot receive a private key. "+
				"Enroll the agent again with a host key, then retry.", nil)
	case errors.Is(err, repository.ErrCertificateInUse):
		return true, tlsAnswer(c, fiber.StatusConflict, "CERTIFICATE_IN_USE",
			"This certificate is serving traffic. Switch the application to ACME or to proxy mode first, or upload a replacement.", nil)
	}
	return false, nil
}

func (h *AppTLSHandler) refused(c *fiber.Ctx, err error) error {
	if errors.Is(err, pgx.ErrNoRows) {
		return maintenanceNotFound(c)
	}
	if handled, answered := tlsRefused(c, err); handled {
		return answered
	}
	apiErr := ResolveDBError(err, "app")
	return c.Status(apiErr.HTTPStatus).JSON(fiber.Map{"error": apiErr.Message, "code": apiErr.Code})
}

func (h *AppTLSHandler) push(projectID string, bumped bool) {
	if bumped && h.AgentServer != nil {
		go h.AgentServer.PushBundleToProject(projectID)
	}
}

func (h *AppTLSHandler) audit(c *fiber.Ctx, action, projectID, appID string, meta map[string]any) {
	userID, _ := c.Locals(auth.UserIDKey).(string)
	appName := ""
	if app, err := h.Repo.App.GetByID(c.UserContext(), appID); err == nil {
		appName = app.Name
	}
	_ = h.Repo.Audit.Log(c.UserContext(), repository.AuditEvent{
		ProjectID: projectID, ActorUserID: userID,
		Action: action, TargetType: "app", TargetID: appID, TargetName: appName,
		IP: c.IP(), UserAgent: string(c.Request().Header.UserAgent()),
		MetadataJSON: meta,
	})
}

// ── Settings ──────────────────────────────────────────────────────────────

// Get returns the TLS settings of the application, its current certificate without the key, and what
// the agent last reported.
//
//	GET /api/projects/:id/apps/:appId/tls
func (h *AppTLSHandler) Get(c *fiber.Ctx) error {
	r, err := h.read(c.UserContext(), c.Params("id"), c.Params("appId"))
	if err != nil {
		return h.refused(c, err)
	}
	return c.JSON(r.view(time.Now()))
}

// Put replaces the TLS settings and pushes the bundle. The checks that need the other applications
// of the agent run in the repository under a lock, so two saves at once are measured one after the
// other.
//
//	PUT /api/projects/:id/apps/:appId/tls
func (h *AppTLSHandler) Put(c *fiber.Ctx) error {
	projectID, appID := c.Params("id"), c.Params("appId")
	var in domain.TLSSettings
	if err := c.BodyParser(&in); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid body", "code": "BAD_REQUEST"})
	}
	if err := in.Normalize(); err != nil {
		return h.refused(c, err)
	}
	out, err := h.Repo.TLS.UpdateTLS(c.UserContext(), projectID, appID, in, time.Now())
	if err != nil {
		return h.refused(c, err)
	}
	h.push(projectID, out.BundleBumped)
	h.audit(c, repository.AuditAppTLSUpdated, projectID, appID, map[string]any{
		"mode": out.Saved.Mode, "source": out.Saved.Source, "hosts": out.Saved.Hosts,
		"listen": out.Saved.Listen, "redirect_listen": out.Saved.RedirectListen,
		"previous_mode": out.Previous.Mode, "previous_source": out.Previous.Source,
	})
	return h.answerState(c, projectID, appID, out.Saved.Mode == domain.TLSModeGateway)
}

// answerState answers with the state as GET gives it. With dns it adds the dns_mismatch warnings.
func (h *AppTLSHandler) answerState(c *fiber.Ctx, projectID, appID string, dns bool) error {
	now := time.Now()
	r, err := h.read(c.UserContext(), projectID, appID)
	if err != nil {
		return h.refused(c, err)
	}
	v := r.view(now)
	if dns && r.agent != nil {
		v.Warnings = append(v.Warnings, h.dnsWarnings(c.UserContext(), projectID, r.agent.ID, r.tls.Hosts)...)
	}
	return c.JSON(v)
}

// ── DNS hint ──────────────────────────────────────────────────────────────

var carrierGradeNAT = netip.MustParsePrefix("100.64.0.0/10")

// publicAddr says whether a is an address the internet can reach: not private, loopback, link-local,
// shared (carrier-grade NAT) or unspecified.
func publicAddr(a netip.Addr) bool {
	return a.IsGlobalUnicast() && !a.IsPrivate() && !carrierGradeNAT.Contains(a)
}

// dnsWarnings compares what the hosts resolve to with the public address the agent's host reports. A
// warning is a hint and nothing is stored. There is none when the host reports no public address
// (an address behind a NAT or a load balancer says nothing about what DNS should answer), when a name
// does not resolve, or when the lookups run out of the shared time.
func (h *AppTLSHandler) dnsWarnings(ctx context.Context, projectID, agentID string, hosts []string) []tlsWarning {
	reported, err := h.Repo.TLS.AgentReportedAddresses(ctx, projectID, agentID)
	if err != nil {
		slog.Warn("tls_agent_addresses_lookup_failed", "err", err)
		return nil
	}
	known := slices.DeleteFunc(reported, func(a netip.Addr) bool { return !publicAddr(a) })
	if len(known) == 0 {
		return nil
	}
	var resolver HostResolver = net.DefaultResolver
	if h.Resolver != nil {
		resolver = h.Resolver
	}
	return dnsMismatches(ctx, resolver, hosts, known)
}

func dnsMismatches(ctx context.Context, resolver HostResolver, hosts []string, known []netip.Addr) []tlsWarning {
	ctx, cancel := context.WithTimeout(ctx, tlsDNSBudget)
	defer cancel()
	agentAddrs := make([]string, 0, len(known))
	for _, a := range known {
		agentAddrs = append(agentAddrs, a.String())
	}
	found := make([]*tlsWarning, len(hosts))
	var wg sync.WaitGroup
	slots := make(chan struct{}, tlsDNSParallel)
start:
	for i, host := range hosts {
		select {
		case slots <- struct{}{}:
		case <-ctx.Done():
			break start
		}
		// A free slot and a spent budget are both ready: the budget wins.
		if ctx.Err() != nil {
			break start
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer func() { <-slots }()
			addrs, err := resolver.LookupNetIP(ctx, "ip", host)
			if err != nil || len(addrs) == 0 {
				return
			}
			shown := []string{}
			for _, a := range addrs {
				a = a.Unmap()
				if slices.Contains(known, a) {
					return
				}
				if publicAddr(a) {
					shown = append(shown, a.String())
				}
			}
			slices.Sort(shown)
			shown = slices.Compact(shown)
			found[i] = &tlsWarning{Code: tlsWarnDNSMismatch, Host: host, Resolved: shown[:min(len(shown), tlsResolvedShown)], AgentAddresses: agentAddrs}
		}()
	}
	wg.Wait()
	var out []tlsWarning
	for _, w := range found {
		if w != nil {
			out = append(out, *w)
		}
	}
	return out
}

// ── ACME ──────────────────────────────────────────────────────────────────

// RequestACME asks the agent to order a certificate, or to try again.
//
//	POST /api/projects/:id/apps/:appId/tls/acme
func (h *AppTLSHandler) RequestACME(c *fiber.Ctx) error {
	projectID, appID := c.Params("id"), c.Params("appId")
	out, err := h.Repo.TLS.RequestACME(c.UserContext(), projectID, appID, time.Now())
	if err != nil {
		return h.refused(c, err)
	}
	h.push(projectID, out.BundleBumped)
	h.audit(c, repository.AuditAppTLSACMERequested, projectID, appID, map[string]any{
		"request_id": out.Saved.ACMERequestID, "hosts": out.Saved.Hosts, "mode": out.Saved.Mode,
	})
	return h.answerState(c, projectID, appID, false)
}

// ── Uploaded certificate ──────────────────────────────────────────────────

// unquoteJSONString decodes the JSON string literal raw into bytes without making a Go string, which
// could not be cleared. It reports false when raw is not a string literal. Absent and null give no
// bytes.
func unquoteJSONString(raw []byte) ([]byte, bool) {
	if len(raw) == 0 || string(raw) == "null" {
		return nil, true
	}
	if len(raw) < 2 || raw[0] != '"' || raw[len(raw)-1] != '"' {
		return nil, false
	}
	in := raw[1 : len(raw)-1]
	out := make([]byte, 0, len(in))
	fail := func() ([]byte, bool) {
		clear(out)
		return nil, false
	}
	for i := 0; i < len(in); {
		if in[i] != '\\' {
			out = append(out, in[i])
			i++
			continue
		}
		if i+1 >= len(in) {
			return fail()
		}
		switch esc := in[i+1]; esc {
		case '"', '\\', '/':
			out = append(out, esc)
		case 'b':
			out = append(out, '\b')
		case 'f':
			out = append(out, '\f')
		case 'n':
			out = append(out, '\n')
		case 'r':
			out = append(out, '\r')
		case 't':
			out = append(out, '\t')
		case 'u':
			r, ok := hex4(in[i+2:])
			if !ok {
				return fail()
			}
			i += 4
			if utf16.IsSurrogate(r) {
				// A high half needs its low half right behind it. Anything else is the replacement
				// character, as in encoding/json.
				pair := utf8.RuneError
				if rest := in[i+2:]; len(rest) >= 6 && rest[0] == '\\' && rest[1] == 'u' {
					if low, ok := hex4(rest[2:]); ok {
						pair = utf16.DecodeRune(r, low)
					}
				}
				if pair != utf8.RuneError {
					i += 6
				}
				r = pair
			}
			out = utf8.AppendRune(out, r)
		default:
			return fail()
		}
		i += 2
	}
	return out, true
}

func hex4(b []byte) (rune, bool) {
	if len(b) < 4 {
		return 0, false
	}
	var r rune
	for _, c := range b[:4] {
		switch {
		case c >= '0' && c <= '9':
			c -= '0'
		case c >= 'a' && c <= 'f':
			c = c - 'a' + 10
		case c >= 'A' && c <= 'F':
			c = c - 'A' + 10
		default:
			return 0, false
		}
		r = r<<4 | rune(c)
	}
	return r, true
}

// certRefusal answers an upload that is refused with the code and the reason, never with the
// input.
func certRefusal(c *fiber.Ctx, field, reason, text, host string) error {
	extra := fiber.Map{"field": field, "reason": reason}
	if host != "" {
		extra["host"] = host
	}
	return tlsAnswer(c, fiber.StatusBadRequest, tlsCodeInvalidCert, text, extra)
}

// UploadCertificate stores a certificate chain and its private key as the current certificate of the
// application. The key is sealed before it is stored, and neither the key nor the request body that
// carried it is ever returned, logged or returned as an error: every refusal is answered here with
// a code, a field and a fixed text, and never reaches the error handler, which logs what it is given.
//
//	POST /api/projects/:id/apps/:appId/tls/certificate
func (h *AppTLSHandler) UploadCertificate(c *fiber.Ctx) error {
	userID, _ := c.Locals(auth.UserIDKey).(string)
	projectID, appID := c.Params("id"), c.Params("appId")

	// The body is read as it came in: Fiber's Body would unpack a compressed one into a copy that
	// cannot be cleared. Everything cut out of it is cleared on every way out, refusals included.
	body := c.Request().Body()
	defer clear(body)
	var in struct {
		ChainPEM json.RawMessage `json:"chain_pem"`
		KeyPEM   json.RawMessage `json:"key_pem"`
	}
	defer func() { clear(in.KeyPEM) }()

	enc := h.Repo.User.TOTPCrypto
	if enc == nil {
		return tlsAnswer(c, fiber.StatusServiceUnavailable, tlsCodeKeyEncrypt,
			"Certificate keys cannot be stored: no encryption key is configured on the control plane (totp.enc_key).", nil)
	}
	if len(body) > domain.CertUploadMaxBytes {
		return certRefusal(c, tlsFieldUploadBody, domain.CertReasonTooLarge,
			fmt.Sprintf("The request is larger than %d KiB.", domain.CertUploadMaxBytes>>10), "")
	}
	if err := json.Unmarshal(body, &in); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid body", "code": "BAD_REQUEST"})
	}
	chain, chainOK := unquoteJSONString(in.ChainPEM)
	key, keyOK := unquoteJSONString(in.KeyPEM)
	defer clear(key)
	if !chainOK || !keyOK {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid body", "code": "BAD_REQUEST"})
	}

	settings, _, err := h.Repo.TLS.GetTLS(c.UserContext(), projectID, appID)
	if err != nil {
		return h.refused(c, err)
	}
	now := time.Now()
	up, err := domain.ParseCertificateUpload(domain.CertificateUploadInput{
		ChainPEM: chain, KeyPEM: key, Hosts: settings.Hosts, Now: now, Roots: h.Roots,
	})
	if err != nil {
		var refused *domain.CertificateError
		if errors.As(err, &refused) {
			return certRefusal(c, refused.Field, refused.Reason, refused.Msg, refused.Host)
		}
		slog.Error("app_tls_upload_check_failed", "err_type", fmt.Sprintf("%T", err))
		return tlsAnswer(c, fiber.StatusInternalServerError, "INTERNAL_ERROR", "An error occurred while processing your request. Please try again or contact support.", nil)
	}
	defer clear(up.KeyPEM)

	id := uuid.NewString()
	stored, err := h.Repo.TLS.InsertCertificate(c.UserContext(), projectID, appID, repository.NewCertificate{
		ID: id, CertificateInfo: up.CertificateInfo, KeyType: up.KeyType, Key: up.KeyPEM, CreatedBy: userID,
	}, enc)
	if err != nil {
		var coverage *repository.TLSCoverageError
		switch {
		case errors.As(err, &coverage):
			// The hosts changed after they were read above.
			return certRefusal(c, domain.CertFieldChain, domain.CertReasonNamesDoNotCover,
				"the leaf certificate does not cover "+coverage.Host, coverage.Host)
		case errors.Is(err, otp.ErrNoEncryptionKey):
			return tlsAnswer(c, fiber.StatusServiceUnavailable, tlsCodeKeyEncrypt,
				"Certificate keys cannot be stored: no encryption key is configured on the control plane (totp.enc_key).", nil)
		case errors.Is(err, pgx.ErrNoRows), errors.Is(err, repository.ErrAgentNotHostBound):
			return h.refused(c, err)
		}
		// The error is not logged with its text: it comes from the store, and a certificate upload is
		// the one request where nothing about the input may reach a log.
		slog.Error("app_tls_upload_store_failed", "err_type", fmt.Sprintf("%T", err))
		apiErr := ResolveDBError(err, "app")
		return c.Status(apiErr.HTTPStatus).JSON(fiber.Map{"error": apiErr.Message, "code": apiErr.Code})
	}
	h.push(projectID, stored.BundleBumped)

	view := repository.AppCertificate{
		ID: id, AppID: appID, Source: domain.TLSSourceUploaded, LeafSHA256: up.LeafSHA256, Names: up.Names, Issuer: up.Issuer,
		KeyType: up.KeyType, NotBefore: up.NotBefore, NotAfter: up.NotAfter, Trusted: up.Trusted, CreatedAt: now,
	}
	// What is stored has the creation time of the database; another upload may also have replaced
	// this one already, and then the answer is what this request stored.
	if _, current, err := h.Repo.TLS.GetTLS(c.UserContext(), projectID, appID); err == nil && current != nil && current.ID == id {
		view = *current
	}
	h.audit(c, repository.AuditAppTLSCertificateUploaded, projectID, appID, map[string]any{
		"certificate_id": id, "names": up.Names, "not_after": up.NotAfter.UTC().Format(time.RFC3339),
		"leaf_sha256": up.LeafSHA256, "key_type": up.KeyType, "replaced_certificate_id": stored.ReplacedID,
	})
	return c.Status(fiber.StatusCreated).JSON(certificateView(view, now))
}

// DeleteCertificate removes the private keys of the application's certificates and the pointer to the
// current one. It is refused while the application serves from that certificate.
//
//	DELETE /api/projects/:id/apps/:appId/tls/certificate
func (h *AppTLSHandler) DeleteCertificate(c *fiber.Ctx) error {
	projectID, appID := c.Params("id"), c.Params("appId")
	id, err := h.Repo.TLS.DeleteCertificate(c.UserContext(), projectID, appID)
	if err != nil {
		return h.refused(c, err)
	}
	if id == "" {
		return tlsAnswer(c, fiber.StatusNotFound, "CERTIFICATE_NOT_FOUND", "The application has no certificate.", nil)
	}
	h.audit(c, repository.AuditAppTLSCertificateDeleted, projectID, appID, map[string]any{"certificate_id": id})
	return c.JSON(fiber.Map{"deleted": true})
}
