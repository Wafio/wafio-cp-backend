package httpadapter

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"

	"github.com/wafio/wafio-cp-backend/internal/adapter/repository"
	"github.com/wafio/wafio-cp-backend/internal/domain"
)

func TestDBAppTLSReadAndAccess(t *testing.T) {
	tf := newTLSFixture(t)

	// A fresh application reads as proxy mode with the default listener, and nothing else set.
	got := tf.get(t, "viewer")
	wantStatus(t, "viewer reads", got, fiber.StatusOK, "")
	if got.body["mode"] != "proxy" || got.body["listen"] != "0.0.0.0:443" || got.body["redirect_listen"] != "" || got.body["source"] != "" || len(strs(got.body["hosts"])) != 0 {
		t.Errorf("a new application is not in proxy mode with the default listener: %s", got.raw)
	}
	for _, key := range []string{"certificate", "acme", "status", "agent_supported"} {
		if v, has := got.body[key]; !has || v != nil {
			t.Errorf("%s = %v, want null", key, v)
		}
	}
	if got.body["agent_host_bound"] != false {
		t.Errorf("agent_host_bound = %v, want false for an agent without a credential bound to its host", got.body["agent_host_bound"])
	}
	if list, ok := got.body["warnings"].([]any); !ok || len(list) != 0 {
		t.Errorf("warnings = %v, want []", got.body["warnings"])
	}

	// An application that no agent serves says nothing about an agent.
	created := call(t, tf.app, http.MethodPost, "/api/projects/"+tf.project+"/apps", tf.tokens["owner"], map[string]any{"name": "lone-" + uuid.NewString()[:6]})
	wantStatus(t, "create app", created, fiber.StatusCreated, "")
	lone, _ := created.body["app"].(map[string]any)
	loneURL := tf.tlsURL(lone["id"].(string))
	r := tf.do(t, http.MethodGet, loneURL, "viewer", nil)
	wantStatus(t, "read the TLS of an application without an agent", r, fiber.StatusOK, "")
	if v, has := r.body["agent_supported"]; !has || v != nil {
		t.Errorf("agent_supported = %v, want null", v)
	}
	if v, has := r.body["agent_host_bound"]; !has || v != nil {
		t.Errorf("agent_host_bound = %v, want null", v)
	}

	// What the agent said and its credential show up.
	yes := true
	tf.supports(t, &yes)
	tf.bind(t, tf.agentID)
	r = tf.get(t, "viewer")
	if r.body["agent_supported"] != true || r.body["agent_host_bound"] != true {
		t.Errorf("agent_supported %v, agent_host_bound %v, want true, true", r.body["agent_supported"], r.body["agent_host_bound"])
	}

	// Roles: a viewer reads and cannot write; another tenant finds nothing.
	writes := map[string]func(as, url string) testResponse{
		"PUT tls": func(as, url string) testResponse {
			return tf.do(t, http.MethodPut, url, as, map[string]any{"mode": "proxy"})
		},
		"POST tls/certificate": func(as, url string) testResponse {
			return tf.do(t, http.MethodPost, url+"/certificate", as, map[string]any{"chain_pem": "x", "key_pem": "y"})
		},
		"POST tls/acme": func(as, url string) testResponse { return tf.do(t, http.MethodPost, url+"/acme", as, nil) },
		"DELETE tls/certificate": func(as, url string) testResponse {
			return tf.do(t, http.MethodDelete, url+"/certificate", as, nil)
		},
	}
	foreign, err := tf.repo.App.Create(context.Background(), &repository.App{ProjectID: tf.other, Name: "foreign-" + uuid.NewString()[:8]})
	if err != nil {
		t.Fatal(err)
	}
	foreignURL := tf.tlsURL(foreign.ID)
	gen := tf.generation(t, tf.agentID)
	for name, send := range writes {
		wantStatus(t, "viewer "+name, send("viewer", tf.url), fiber.StatusForbidden, "")
		wantStatus(t, "outsider "+name, send("outsider", tf.url), fiber.StatusNotFound, "")
		wantStatus(t, "member of both projects, foreign application, "+name, send("memberB", foreignURL), fiber.StatusNotFound, "")
	}
	wantStatus(t, "outsider reads", tf.get(t, "outsider"), fiber.StatusNotFound, "")
	wantStatus(t, "member of both projects reads a foreign application", tf.do(t, http.MethodGet, foreignURL, "memberB", nil), fiber.StatusNotFound, "")
	wantStatus(t, "no token", call(t, tf.app, http.MethodGet, tf.url, "", nil), fiber.StatusUnauthorized, "")
	for _, action := range []string{repository.AuditAppTLSUpdated, repository.AuditAppTLSCertificateUploaded, repository.AuditAppTLSACMERequested, repository.AuditAppTLSCertificateDeleted} {
		if tf.audits(t, action) != 0 {
			t.Errorf("a refused call wrote an %s row", action)
		}
	}
	if tf.generation(t, tf.agentID) != gen {
		t.Error("a refused call bumped the bundle")
	}

	// A member writes. The calls run in the order that lets each one succeed.
	wantStatus(t, "member saves a draft", tf.put(t, "memberA", map[string]any{"mode": "proxy", "hosts": []string{"shop.example.com"}}), fiber.StatusOK, "")
	c := tf.newCert(t, certOpts{})
	wantStatus(t, "member uploads", tf.upload(t, "memberA", c), fiber.StatusCreated, "")
	wantStatus(t, "member requests ACME", tf.acme(t, "memberA"), fiber.StatusOK, "")
	wantStatus(t, "member deletes", tf.deleteCertificate(t, "memberA"), fiber.StatusOK, "")
}

func TestDBAppTLSPutValidation(t *testing.T) {
	tf := newTLSFixture(t)
	gen, audits := tf.generation(t, tf.agentID), tf.audits(t, repository.AuditAppTLSUpdated)

	for name, c := range map[string]struct {
		body  map[string]any
		field string
	}{
		"no mode":                 {map[string]any{}, "mode"},
		"unknown mode":            {map[string]any{"mode": "tunnel"}, "mode"},
		"unknown source":          {map[string]any{"mode": "proxy", "source": "letsencrypt"}, "source"},
		"gateway without source":  {map[string]any{"mode": "gateway", "hosts": []string{"a.example.com"}}, "source"},
		"gateway without a host":  {map[string]any{"mode": "gateway", "source": "acme"}, "hosts"},
		"a wildcard":              {gateway("acme", "*.example.com"), "hosts"},
		"an IP address":           {gateway("acme", "10.0.0.1"), "hosts"},
		"no dot":                  {gateway("acme", "localhost"), "hosts"},
		"a port":                  {gateway("acme", "a.example.com:8443"), "hosts"},
		"an empty label":          {gateway("acme", "a..example.com"), "hosts"},
		"a trailing dot":          {gateway("acme", "a.example.com."), "hosts"},
		"too many hosts":          {gateway("acme", manyHosts(101)...), "hosts"},
		"listen without a port":   {map[string]any{"mode": "proxy", "listen": "0.0.0.0"}, "listen"},
		"listen port zero":        {map[string]any{"mode": "proxy", "listen": "0.0.0.0:0"}, "listen"},
		"listen is a host name":   {map[string]any{"mode": "proxy", "listen": "example.com:443"}, "listen"},
		"redirect is listen":      {map[string]any{"mode": "proxy", "listen": "0.0.0.0:443", "redirect_listen": "0.0.0.0:443"}, "redirect_listen"},
		"redirect overlaps":       {map[string]any{"mode": "proxy", "listen": "[::]:8443", "redirect_listen": "0.0.0.0:8443"}, "redirect_listen"},
		"redirect is not address": {map[string]any{"mode": "proxy", "redirect_listen": "80"}, "redirect_listen"},
	} {
		r := tf.put(t, "owner", c.body)
		wantStatus(t, name, r, fiber.StatusBadRequest, "INVALID_TLS_SETTINGS")
		if r.body["field"] != c.field {
			t.Errorf("%s: field %v, want %s: %s", name, r.body["field"], c.field, r.raw)
		}
	}
	for name, body := range map[string][]byte{"not JSON": []byte("not json"), "wrong type": []byte(`{"mode": 5}`), "hosts as text": []byte(`{"mode":"proxy","hosts":"a.example.com"}`)} {
		wantStatus(t, name, tf.raw(t, http.MethodPut, tf.url, "owner", body, nil), fiber.StatusBadRequest, "BAD_REQUEST")
	}
	if tf.generation(t, tf.agentID) != gen || tf.audits(t, repository.AuditAppTLSUpdated) != audits {
		t.Error("a refused save bumped the bundle or wrote an audit row")
	}
	if got := tf.get(t, "owner"); got.body["mode"] != "proxy" || got.body["source"] != "" || len(strs(got.body["hosts"])) != 0 {
		t.Errorf("a refused save changed the settings: %s", got.raw)
	}
}

func manyHosts(n int) []string {
	out := make([]string, n)
	for i := range out {
		out[i] = "h" + strings.Repeat("x", i%5) + string(rune('a'+i%26)) + string(rune('a'+i/26%26)) + ".example.com"
	}
	return out
}

func TestDBAppTLSPutStoresAndBumpsTheBundle(t *testing.T) {
	tf := newTLSFixture(t)
	ctx := context.Background()

	// A draft in proxy mode: stored, normalized, and the agent's bundle does not change.
	gen := tf.generation(t, tf.agentID)
	r := tf.put(t, "owner", map[string]any{"mode": "proxy", "hosts": []string{" Shop.Example.com ", "shop.example.com", "www.example.com"}, "listen": "0.0.0.0:8443"})
	wantStatus(t, "draft", r, fiber.StatusOK, "")
	if hosts := strs(r.body["hosts"]); strings.Join(hosts, ",") != "shop.example.com,www.example.com" || r.body["listen"] != "0.0.0.0:8443" {
		t.Errorf("draft answered %s", r.raw)
	}
	if tf.generation(t, tf.agentID) != gen {
		t.Error("a draft in proxy mode bumped the bundle")
	}
	if tf.audits(t, repository.AuditAppTLSUpdated) != 1 {
		t.Error("the draft wrote no audit row")
	}

	// To gateway with ACME: the bundle moves, a request id is minted, and the answer is the GET shape.
	r = tf.put(t, "owner", map[string]any{"mode": "gateway", "source": "acme", "hosts": []string{"shop.example.com"}, "redirect_listen": "0.0.0.0:80"})
	wantStatus(t, "gateway", r, fiber.StatusOK, "")
	if tf.generation(t, tf.agentID) <= gen {
		t.Error("the switch to gateway did not bump the bundle")
	}
	acme, _ := r.body["acme"].(map[string]any)
	reqID, _ := acme["request_id"].(string)
	if _, err := uuid.Parse(reqID); err != nil || acme["requested_at"] == nil {
		t.Errorf("no ACME request was made: %s", r.raw)
	}
	if r.body["mode"] != "gateway" || r.body["source"] != "acme" || r.body["listen"] != "0.0.0.0:443" || r.body["redirect_listen"] != "0.0.0.0:80" {
		t.Errorf("gateway answered %s", r.raw)
	}
	if got := tf.get(t, "viewer"); got.raw != r.raw {
		t.Errorf("GET after PUT: %s\nPUT answered: %s", got.raw, r.raw)
	}
	meta := tf.lastAudit(t, repository.AuditAppTLSUpdated)
	if meta["mode"] != "gateway" || meta["source"] != "acme" || meta["previous_mode"] != "proxy" || meta["listen"] != "0.0.0.0:443" {
		t.Errorf("audit metadata %v", meta)
	}
	var target, targetName string
	if err := tf.repo.DB.QueryRow(ctx, `SELECT target_id::text, target_name FROM agent_audit WHERE action = $1 AND project_id = $2 ORDER BY created_at DESC LIMIT 1`,
		repository.AuditAppTLSUpdated, tf.project).Scan(&target, &targetName); err != nil || target != tf.appID || targetName != tf.name {
		t.Errorf("audit target %q %q, %v", target, targetName, err)
	}

	// The same settings again: nothing changes for the agent, and the request id stays.
	gen = tf.generation(t, tf.agentID)
	again := tf.put(t, "owner", map[string]any{"mode": "gateway", "source": "acme", "hosts": []string{"shop.example.com"}, "redirect_listen": "0.0.0.0:80"})
	wantStatus(t, "same settings", again, fiber.StatusOK, "")
	if tf.generation(t, tf.agentID) != gen {
		t.Error("a save without a change bumped the bundle")
	}
	if a2, _ := again.body["acme"].(map[string]any); a2["request_id"] != reqID {
		t.Errorf("the request id changed: %v", a2)
	}

	// A listener change goes out; so does leaving gateway.
	wantStatus(t, "listener change", tf.put(t, "owner", map[string]any{"mode": "gateway", "source": "acme", "hosts": []string{"shop.example.com"}, "listen": "0.0.0.0:9443"}), fiber.StatusOK, "")
	if tf.generation(t, tf.agentID) <= gen {
		t.Error("a listener change did not bump the bundle")
	}
	gen = tf.generation(t, tf.agentID)
	wantStatus(t, "back to proxy", tf.put(t, "owner", map[string]any{"mode": "proxy"}), fiber.StatusOK, "")
	if tf.generation(t, tf.agentID) <= gen {
		t.Error("leaving gateway did not bump the bundle")
	}
}

// The agent decides whether a switch to gateway is allowed: one that said it cannot serve TLS refuses
// it, one that never said is let through, and an application already in gateway mode stays editable.
func TestDBAppTLSPutAgentSupport(t *testing.T) {
	tf := newTLSFixture(t)
	yes, no := true, false
	body := gateway("acme", "shop.example.com")
	gen := tf.generation(t, tf.agentID)

	tf.supports(t, &no)
	r := tf.put(t, "owner", body)
	wantStatus(t, "agent that cannot", r, fiber.StatusConflict, "TLS_UNSUPPORTED")
	if got := tf.get(t, "owner"); got.body["mode"] != "proxy" || got.body["agent_supported"] != false || tf.generation(t, tf.agentID) != gen {
		t.Errorf("a refused switch changed something: %s", got.raw)
	}
	// A draft is not a switch.
	wantStatus(t, "draft on that agent", tf.put(t, "owner", map[string]any{"mode": "proxy", "hosts": []string{"shop.example.com"}}), fiber.StatusOK, "")

	tf.supports(t, nil)
	wantStatus(t, "agent that never said", tf.put(t, "owner", body), fiber.StatusOK, "")
	tf.supports(t, &no)
	wantStatus(t, "hosts edit after the agent reports less", tf.put(t, "owner", gateway("acme", "shop.example.com", "www.example.com")), fiber.StatusOK, "")
	tf.supports(t, &yes)
	wantStatus(t, "agent that can", tf.put(t, "owner", map[string]any{"mode": "proxy"}), fiber.StatusOK, "")
	wantStatus(t, "switch again", tf.put(t, "owner", body), fiber.StatusOK, "")
}

func TestDBAppTLSPutUploadedSource(t *testing.T) {
	tf := newTLSFixture(t)
	body := gateway("uploaded", "shop.example.com")

	r := tf.put(t, "owner", body)
	wantStatus(t, "no certificate", r, fiber.StatusConflict, "CERTIFICATE_REQUIRED")

	// A certificate for another host, uploaded while the application has no hosts yet.
	other := tf.newCert(t, certOpts{names: []string{"other.example.com"}})
	wantStatus(t, "upload for another host", tf.upload(t, "owner", other), fiber.StatusCreated, "")
	r = tf.put(t, "owner", body)
	wantStatus(t, "certificate for another host", r, fiber.StatusConflict, "CERTIFICATE_DOES_NOT_COVER")
	if r.body["host"] != "shop.example.com" {
		t.Errorf("the answer names host %v: %s", r.body["host"], r.raw)
	}

	// A wildcard covers one label.
	wild := tf.newCert(t, certOpts{names: []string{"*.example.com"}})
	wantStatus(t, "upload wildcard", tf.upload(t, "owner", wild), fiber.StatusCreated, "")
	r = tf.put(t, "owner", gateway("uploaded", "a.b.example.com"))
	wantStatus(t, "two labels", r, fiber.StatusConflict, "CERTIFICATE_DOES_NOT_COVER")

	// The key only goes to an agent with a credential bound to its host.
	r = tf.put(t, "owner", body)
	wantStatus(t, "agent without a bound credential", r, fiber.StatusConflict, "AGENT_NOT_HOST_BOUND")
	if !strings.Contains(r.body["error"].(string), "Enroll the agent again") {
		t.Errorf("no hint to enroll again: %s", r.raw)
	}
	tf.bind(t, tf.agentID)
	gen := tf.generation(t, tf.agentID)
	r = tf.put(t, "owner", body)
	wantStatus(t, "everything in place", r, fiber.StatusOK, "")
	if tf.generation(t, tf.agentID) <= gen {
		t.Error("the switch did not bump the bundle")
	}
	cert, _ := r.body["certificate"].(map[string]any)
	if cert["id"] == nil || r.body["agent_host_bound"] != true || strs(cert["names"])[0] != "*.example.com" {
		t.Errorf("answer %s", r.raw)
	}

	// A hosts edit while in gateway checks the certificate again.
	r = tf.put(t, "owner", gateway("uploaded", "shop.example.com", "a.b.example.com"))
	wantStatus(t, "hosts edit the certificate does not cover", r, fiber.StatusConflict, "CERTIFICATE_DOES_NOT_COVER")
	wantStatus(t, "hosts edit that it covers", tf.put(t, "owner", gateway("uploaded", "shop.example.com", "www.example.com")), fiber.StatusOK, "")

	// An expired current certificate is none.
	tf.exec(t, `UPDATE app_certificates SET not_after = NOW() - INTERVAL '1 hour' WHERE app_id = $1 AND replaced_at IS NULL`, tf.appID)
	wantStatus(t, "back to a draft", tf.put(t, "owner", map[string]any{"mode": "proxy", "source": "uploaded", "hosts": []string{"shop.example.com"}}), fiber.StatusOK, "")
	wantStatus(t, "expired certificate", tf.put(t, "owner", body), fiber.StatusConflict, "CERTIFICATE_REQUIRED")
}

// The checks that need the other applications of the agent answer with the setting to change.
func TestDBAppTLSPutPlacementConflicts(t *testing.T) {
	tf := newTLSFixture(t)
	second := tf.route(t, tf.agentID, "second", 18091)
	secondURL := tf.tlsURL(second)
	putSecond := func(body map[string]any) testResponse { return tf.do(t, http.MethodPut, secondURL, "owner", body) }

	wantStatus(t, "first application", tf.put(t, "owner", map[string]any{"mode": "gateway", "source": "acme", "hosts": []string{"shop.example.com"}, "redirect_listen": "0.0.0.0:80"}), fiber.StatusOK, "")

	// The same host on the same listener.
	r := putSecond(gateway("acme", "SHOP.example.com"))
	wantStatus(t, "same host", r, fiber.StatusConflict, "HOST_CONFLICT")
	if r.body["field"] != "hosts" || !strings.Contains(r.body["error"].(string), "shop.example.com") {
		t.Errorf("answer %s", r.raw)
	}
	// Another host on the same listener is fine while the limits agree.
	wantStatus(t, "another host", putSecond(gateway("acme", "blog.example.com")), fiber.StatusOK, "")

	// A redirect address that is another application's HTTPS address, or its own plain listener.
	r = putSecond(map[string]any{"mode": "gateway", "source": "acme", "hosts": []string{"blog.example.com"}, "listen": "0.0.0.0:8443", "redirect_listen": "0.0.0.0:443"})
	wantStatus(t, "redirect on an HTTPS address", r, fiber.StatusConflict, "LISTEN_CONFLICT")
	if r.body["field"] != "redirect_listen" {
		t.Errorf("field %v", r.body["field"])
	}
	r = putSecond(map[string]any{"mode": "gateway", "source": "acme", "hosts": []string{"blog.example.com"}, "listen": "0.0.0.0:18090"})
	wantStatus(t, "HTTPS on the plain listener of another application", r, fiber.StatusConflict, "LISTEN_CONFLICT")
	if r.body["field"] != "listen" {
		t.Errorf("field %v", r.body["field"])
	}
	r = tf.put(t, "owner", map[string]any{"mode": "gateway", "source": "acme", "hosts": []string{"shop.example.com"}, "listen": "127.0.0.1:18091"})
	wantStatus(t, "HTTPS on the plain listener of another application, the other way", r, fiber.StatusConflict, "LISTEN_CONFLICT")

	// Applications that share a listener may have different limits: the agent takes the largest value
	// of the listener and applies the limits of each application after routing.
	limits := map[string]any{"proxy_config": map[string]any{"timeouts": map[string]any{"read_ms": 1500}, "max_body_bytes": 1048576}}
	wantStatus(t, "different limits on a shared listener", tf.do(t, http.MethodPut, "/api/projects/"+tf.project+"/apps/"+second, "owner", limits), fiber.StatusOK, "")
	wantStatus(t, "saved again with other limits on the shared listener", putSecond(gateway("acme", "blog.example.com", "www.blog.example.com")), fiber.StatusOK, "")
}

func TestDBAppTLSDNSWarning(t *testing.T) {
	tf := newTLSFixture(t)
	body := gateway("acme", "shop.example.com", "www.example.com")
	tf.resolver.set("shop.example.com", "198.51.100.7")
	tf.resolver.set("www.example.com", "203.0.113.10")
	// toGateway leaves gateway mode and goes back with body, which is a switch the hint looks at.
	toGateway := func(body map[string]any) testResponse {
		t.Helper()
		wantStatus(t, "to proxy", tf.put(t, "owner", map[string]any{"mode": "proxy"}), fiber.StatusOK, "")
		return tf.put(t, "owner", body)
	}
	lookups := func(from int) int { return tf.resolver.lookups() - from }

	// The agent's host reported no address: nothing to compare, and nothing is looked up.
	r := toGateway(body)
	wantStatus(t, "no addresses known", r, fiber.StatusOK, "")
	if len(warningCodes(r)) != 0 || tf.resolver.lookups() != 0 {
		t.Errorf("no address known: warnings %v, %d lookups", warningCodes(r), tf.resolver.lookups())
	}
	// An address behind a NAT says nothing about what DNS should answer.
	tf.hostInfo(t, tf.agentID, `{"primary_ip":"10.0.0.5","public_ip":"not an address"}`)
	if r = toGateway(body); len(warningCodes(r)) != 0 || tf.resolver.lookups() != 0 {
		t.Errorf("private address: warnings %v, %d lookups", warningCodes(r), tf.resolver.lookups())
	}

	tf.hostInfo(t, tf.agentID, `{"primary_ip":"10.0.0.5","public_ip":"203.0.113.10"}`)
	r = toGateway(body)
	wantStatus(t, "one host points elsewhere", r, fiber.StatusOK, "")
	warnings, _ := r.body["warnings"].([]any)
	if len(warnings) != 1 {
		t.Fatalf("warnings = %s", r.raw)
	}
	w := warnings[0].(map[string]any)
	if w["code"] != "dns_mismatch" || w["host"] != "shop.example.com" || strings.Join(strs(w["resolved"]), ",") != "198.51.100.7" || strings.Join(strs(w["agent_addresses"]), ",") != "203.0.113.10" {
		t.Errorf("warning = %v", w)
	}
	// Nothing about DNS is stored.
	if got := tf.get(t, "owner"); len(warningCodes(got)) != 0 {
		t.Errorf("GET carries DNS warnings: %s", got.raw)
	}

	// A save in gateway mode that adds no host looks nothing up; one that adds a host looks up that host only.
	before := tf.resolver.lookups()
	if r = tf.put(t, "owner", body); len(warningCodes(r)) != 0 || lookups(before) != 0 {
		t.Errorf("a save without a new host: warnings %v, %d lookups", warningCodes(r), lookups(before))
	}
	tf.resolver.set("blog.example.com", "198.51.100.9")
	r = tf.put(t, "owner", gateway("acme", "shop.example.com", "www.example.com", "blog.example.com"))
	if codes := warningCodes(r); len(codes) != 1 || lookups(before) != 1 || r.body["warnings"].([]any)[0].(map[string]any)["host"] != "blog.example.com" {
		t.Errorf("a save that adds a host: warnings %s, %d lookups", r.raw, lookups(before))
	}

	// Once the name points at the agent, the warning goes.
	tf.resolver.set("shop.example.com", "203.0.113.10")
	if r = toGateway(body); len(warningCodes(r)) != 0 {
		t.Errorf("warnings %v for a host that points at the agent", warningCodes(r))
	}
	// A draft looks nothing up. A name that does not resolve, and one that resolves to private
	// addresses only, give no warning: they look the same, so neither is reported.
	tf.resolver.set("shop.example.com", "198.51.100.7")
	before = tf.resolver.lookups()
	if r = tf.put(t, "owner", map[string]any{"mode": "proxy", "hosts": []string{"shop.example.com"}}); len(warningCodes(r)) != 0 || lookups(before) != 0 {
		t.Errorf("a draft in proxy mode looked up names: %v, %d lookups", warningCodes(r), lookups(before))
	}
	tf.resolver.set("internal.example.com", "10.1.2.3", "fd00::5")
	for _, host := range []string{"unknown.example.com", "internal.example.com"} {
		if r = toGateway(gateway("acme", host)); len(warningCodes(r)) != 0 {
			t.Errorf("%s gave %v", host, warningCodes(r))
		}
	}

	// One save looks up at most ten names; the rest stay unchecked.
	hosts := make([]string, 14)
	for i := range hosts {
		hosts[i] = fmt.Sprintf("many%02d.example.com", i)
		tf.resolver.set(hosts[i], "198.51.100.7")
	}
	before = tf.resolver.lookups()
	r = toGateway(gateway("acme", hosts...))
	if n, got := lookups(before), len(warningCodes(r)); n != 10 || got != 10 {
		t.Errorf("14 hosts: %d lookups and %d warnings, want 10 and 10", n, got)
	}

	// A name server that never answers holds a save for the budget and no longer.
	tf.resolver.mu.Lock()
	tf.resolver.stuck = true
	tf.resolver.mu.Unlock()
	start := time.Now()
	r = toGateway(body)
	elapsed := time.Since(start)
	wantStatus(t, "stuck resolver", r, fiber.StatusOK, "")
	if len(warningCodes(r)) != 0 || elapsed < 1800*time.Millisecond || elapsed > 3500*time.Millisecond {
		t.Errorf("stuck resolver: warnings %v after %v, want none after about 2 s", warningCodes(r), elapsed)
	}
}

func TestDBAppTLSACME(t *testing.T) {
	tf := newTLSFixture(t)
	ctx := context.Background()

	r := tf.acme(t, "owner")
	wantStatus(t, "no host", r, fiber.StatusBadRequest, "INVALID_TLS_SETTINGS")
	if r.body["field"] != "hosts" {
		t.Errorf("field %v", r.body["field"])
	}

	wantStatus(t, "draft with a host", tf.put(t, "owner", map[string]any{"mode": "proxy", "hosts": []string{"shop.example.com"}}), fiber.StatusOK, "")
	gen := tf.generation(t, tf.agentID)
	r = tf.acme(t, "owner")
	wantStatus(t, "request", r, fiber.StatusOK, "")
	first, _ := r.body["acme"].(map[string]any)
	if r.body["source"] != "acme" || first["request_id"] == "" || first["requested_at"] == nil {
		t.Errorf("answer %s", r.raw)
	}
	if tf.generation(t, tf.agentID) != gen {
		t.Error("a request in proxy mode bumped the bundle")
	}
	if tf.audits(t, repository.AuditAppTLSACMERequested) != 1 || tf.lastAudit(t, repository.AuditAppTLSACMERequested)["request_id"] != first["request_id"] {
		t.Error("the request wrote no audit row with its id")
	}

	// One request in five minutes.
	r = tf.acme(t, "owner")
	wantStatus(t, "too soon", r, fiber.StatusConflict, "ACME_REQUEST_TOO_SOON")
	if after, _ := r.body["retry_after"].(float64); after < 1 || after > 300 {
		t.Errorf("retry_after = %v, want 1 to 300: %s", r.body["retry_after"], r.raw)
	}
	if tf.audits(t, repository.AuditAppTLSACMERequested) != 1 {
		t.Error("a refused request wrote an audit row")
	}
	if got := tf.get(t, "owner"); got.body["acme"].(map[string]any)["request_id"] != first["request_id"] {
		t.Error("a refused request changed the id")
	}

	// After the interval a new id goes out, in gateway mode with a bump.
	wantStatus(t, "to gateway", tf.put(t, "owner", gateway("acme", "shop.example.com")), fiber.StatusOK, "")
	tf.exec(t, `UPDATE apps SET acme_requested_at = NOW() - INTERVAL '6 minutes' WHERE id = $1`, tf.appID)
	gen = tf.generation(t, tf.agentID)
	r = tf.acme(t, "owner")
	wantStatus(t, "retry", r, fiber.StatusOK, "")
	if second, _ := r.body["acme"].(map[string]any); second["request_id"] == first["request_id"] || second["request_id"] == "" {
		t.Errorf("no new request id: %s", r.raw)
	}
	if tf.generation(t, tf.agentID) <= gen {
		t.Error("a request in gateway mode did not bump the bundle")
	}
	if n := tf.audits(t, repository.AuditAppTLSACMERequested); n != 2 {
		t.Errorf("%d audit rows, want 2", n)
	}

	// The status the agent sent for the old request is gone; one for the new request is shown.
	status := repository.TLSStatusReport{ProjectID: tf.project, AgentID: tf.agentID, AppID: tf.appID, Source: "acme", State: "active", RequestID: r.body["acme"].(map[string]any)["request_id"].(string),
		LeafSHA256: strings.Repeat("ab", 32), Chain: &domain.CertificateInfo{Names: []string{"shop.example.com"}, Issuer: "Test CA", NotBefore: time.Now().Add(-24 * time.Hour), NotAfter: time.Now().Add(10 * 24 * time.Hour)}}
	if ok, err := tf.repo.TLS.UpsertTLSStatus(ctx, status); err != nil || !ok {
		t.Fatalf("status: %v %v", ok, err)
	}
	got := tf.get(t, "owner")
	st, _ := got.body["status"].(map[string]any)
	if st["state"] != "active" || st["source"] != "acme" || st["certificate_id"] != nil || st["issuer"] != "Test CA" || st["agent_id"] != tf.agentID {
		t.Errorf("status = %v", st)
	}
	if codes := warningCodes(got); len(codes) != 1 || codes[0] != "expires_soon" {
		t.Errorf("an ACME certificate with 10 days left: warnings %v", codes)
	}
	wantStatus(t, "back to a draft", tf.put(t, "owner", map[string]any{"mode": "proxy", "source": "acme", "hosts": []string{"shop.example.com"}}), fiber.StatusOK, "")
	if got = tf.get(t, "owner"); got.body["status"] != nil {
		t.Errorf("the status of a gateway that no longer runs is still shown: %s", got.raw)
	}
}

func TestDBAppTLSDeleteCertificate(t *testing.T) {
	tf := newTLSFixture(t)
	tf.bind(t, tf.agentID)

	r := tf.deleteCertificate(t, "owner")
	wantStatus(t, "no certificate", r, fiber.StatusNotFound, "CERTIFICATE_NOT_FOUND")
	if tf.audits(t, repository.AuditAppTLSCertificateDeleted) != 0 {
		t.Error("deleting nothing wrote an audit row")
	}

	c := tf.newCert(t, certOpts{})
	up := tf.upload(t, "owner", c)
	wantStatus(t, "upload", up, fiber.StatusCreated, "")
	id := up.body["id"].(string)
	wantStatus(t, "serve from it", tf.put(t, "owner", gateway("uploaded", "shop.example.com")), fiber.StatusOK, "")

	wantStatus(t, "in use", tf.deleteCertificate(t, "owner"), fiber.StatusConflict, "CERTIFICATE_IN_USE")
	if tf.keyRows(t, tf.appID) != 1 || !tf.keyOpens(t, id, c) {
		t.Error("a refused delete touched the key")
	}

	wantStatus(t, "serve from ACME", tf.put(t, "owner", gateway("acme", "shop.example.com")), fiber.StatusOK, "")
	gen := tf.generation(t, tf.agentID)
	r = tf.deleteCertificate(t, "owner")
	wantStatus(t, "delete", r, fiber.StatusOK, "")
	if r.body["deleted"] != true || len(r.body) != 1 {
		t.Errorf("answer %s", r.raw)
	}
	if tf.keyRows(t, tf.appID) != 0 || tf.certificates(t, tf.appID) != 1 {
		t.Errorf("%d key rows, %d certificate rows; want the record kept and the key gone", tf.keyRows(t, tf.appID), tf.certificates(t, tf.appID))
	}
	if tf.generation(t, tf.agentID) != gen {
		t.Error("a delete bumped the bundle, which does not change")
	}
	if tf.lastAudit(t, repository.AuditAppTLSCertificateDeleted)["certificate_id"] != id {
		t.Error("the audit row does not name the certificate")
	}
	if got := tf.get(t, "owner"); got.body["certificate"] != nil || got.body["source"] != "acme" {
		t.Errorf("after the delete: %s", got.raw)
	}
	wantStatus(t, "delete again", tf.deleteCertificate(t, "owner"), fiber.StatusNotFound, "CERTIFICATE_NOT_FOUND")

	// Back to the uploaded source with nothing to serve.
	wantStatus(t, "a draft on the uploaded source", tf.put(t, "owner", map[string]any{"mode": "proxy", "source": "uploaded", "hosts": []string{"shop.example.com"}}), fiber.StatusOK, "")
	wantStatus(t, "gateway without a certificate", tf.put(t, "owner", gateway("uploaded", "shop.example.com")), fiber.StatusConflict, "CERTIFICATE_REQUIRED")
}
