package httpadapter

import (
	"log"
	"net"
	"net/netip"

	"github.com/gofiber/fiber/v2"
	"github.com/wafio/wafio-cp-backend/internal/config"
	"github.com/wafio/wafio-cp-backend/internal/domain"
)

// clientIPPolicy builds the client-address rule from the configuration.
// Config.Validate refuses a bad server.trusted_proxies or proxy_header at
// boot; should one still get here, no proxy is trusted (fail closed: every
// caller keys on its TCP peer, as without a reverse proxy).
func clientIPPolicy(cfg *config.Config) *domain.ClientIPPolicy {
	if cfg == nil {
		return nil
	}
	p, err := cfg.Server.ClientIPPolicy()
	if err != nil {
		log.Printf("[SECURITY] %v; trusting no reverse proxy", err)
		return nil
	}
	if p.Enabled() {
		log.Printf("[startup] client IP: %s from %d trusted reverse prox(ies)", p.Header(), len(cfg.Server.TrustedProxies))
	}
	return p
}

// clientIPMiddleware makes c.IP() the client's address when the TCP peer is
// a trusted reverse proxy (server.trusted_proxies, server.proxy_header;
// domain.ClientIPPolicy). Every per-IP limiter (login, OTP, recovery,
// enrollment, agent ingest, reads/writes), the login lockout, audit rows and
// the access log read c.IP(), so the address is resolved once here and set
// as the request's remote address. It must be the first middleware.
//
// The peer always comes from the connection itself: fasthttp keeps a remote
// address set on a request for the next request on the same keep-alive
// connection, and a proxy multiplexes different clients over one. With no
// trusted proxy the handler is a no-op and c.IP() stays the peer.
func clientIPMiddleware(p *domain.ClientIPPolicy) fiber.Handler {
	if !p.Enabled() {
		return func(c *fiber.Ctx) error { return c.Next() }
	}
	return func(c *fiber.Ctx) error {
		fctx := c.Context()
		var peerAddr net.Addr
		if conn := fctx.Conn(); conn != nil {
			peerAddr = conn.RemoteAddr()
		}
		tcp, ok := peerAddr.(*net.TCPAddr)
		if !ok {
			// Not a TCP peer (tests, a unix socket): nothing to resolve.
			fctx.SetRemoteAddr(nil)
			return c.Next()
		}
		peer, ok := netip.AddrFromSlice(tcp.IP)
		if !ok {
			fctx.SetRemoteAddr(nil)
			return c.Next()
		}
		var xff []string
		for _, v := range fctx.Request.Header.PeekAll(domain.ProxyHeaderForwardedFor) {
			xff = append(xff, string(v))
		}
		var xRealIP string
		if all := fctx.Request.Header.PeekAll(domain.ProxyHeaderRealIP); len(all) > 0 {
			xRealIP = string(all[len(all)-1])
		}
		client := p.ClientIP(peer, xff, xRealIP)
		fctx.SetRemoteAddr(&net.TCPAddr{IP: net.IP(client.AsSlice()), Port: tcp.Port})
		return c.Next()
	}
}
