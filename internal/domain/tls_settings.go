package domain

import (
	"fmt"
	"net/netip"
	"strings"
)

// How an application is served over TLS.
const (
	// TLSModeProxy leaves TLS to whatever sits in front of the agent. It is what every application
	// did before the agent could terminate TLS, so it is the default.
	TLSModeProxy = "proxy"
	// TLSModeGateway lets the agent terminate TLS for the hosts of the application.
	TLSModeGateway = "gateway"

	// TLSSourceNone is stored while no source was chosen; a gateway application needs one.
	TLSSourceNone = ""
	// TLSSourceACME means the agent orders and renews the certificate itself.
	TLSSourceACME = "acme"
	// TLSSourceUploaded means the chain and key come from app_certificates.
	TLSSourceUploaded = "uploaded"

	// DefaultTLSListen is the HTTPS listener of an application that names none.
	DefaultTLSListen = "0.0.0.0:443"

	// TLSMaxHosts is the most host names one application can serve.
	TLSMaxHosts = 100
)

// Codes of a TLSConflictError, the ones the HTTP API answers with.
const (
	TLSConflictListen = "LISTEN_CONFLICT"
	TLSConflictHost   = "HOST_CONFLICT"
)

// TLSSettings is what the dashboard saves for the TLS of one application. Normalize turns it into
// the form that is stored and sent to the agent.
type TLSSettings struct {
	Mode           string   `json:"mode"`
	Hosts          []string `json:"hosts"`
	Listen         string   `json:"listen"`
	RedirectListen string   `json:"redirect_listen"`
	Source         string   `json:"source"`
}

// TLSFieldError is a rejected field of a TLSSettings. Field is the JSON key.
type TLSFieldError struct {
	Field, Msg string
}

func (e *TLSFieldError) Error() string { return e.Field + ": " + e.Msg }

func tlsErr(field, format string, args ...any) error {
	return &TLSFieldError{Field: field, Msg: fmt.Sprintf(format, args...)}
}

// Normalize validates s and rewrites it to its stored form: host names in lower case, trimmed and
// without repeats (first one kept), both listeners as ip:port with the default HTTPS listener filled
// in. It returns a *TLSFieldError for the first field that is not valid. The checks do not depend
// on other applications; those are CheckTLSPlacement. A proxy application may keep an empty host
// list, a gateway application needs at least one host and a source.
func (s *TLSSettings) Normalize() error {
	switch s.Mode {
	case TLSModeProxy, TLSModeGateway:
	default:
		return tlsErr("mode", "must be %q or %q", TLSModeProxy, TLSModeGateway)
	}
	switch s.Source {
	case TLSSourceNone, TLSSourceACME, TLSSourceUploaded:
	default:
		return tlsErr("source", "must be %q or %q", TLSSourceACME, TLSSourceUploaded)
	}
	if s.Mode == TLSModeGateway && s.Source == TLSSourceNone {
		return tlsErr("source", "is required when mode is %q", TLSModeGateway)
	}

	hosts, err := normalizeTLSHosts(s.Hosts)
	if err != nil {
		return err
	}
	if s.Mode == TLSModeGateway && len(hosts) == 0 {
		return tlsErr("hosts", "at least one host is required when mode is %q", TLSModeGateway)
	}
	s.Hosts = hosts

	listen := strings.TrimSpace(s.Listen)
	if listen == "" {
		listen = DefaultTLSListen
	}
	if s.Listen, err = canonicalTLSListen("listen", listen); err != nil {
		return err
	}
	if redirect := strings.TrimSpace(s.RedirectListen); redirect == "" {
		s.RedirectListen = ""
	} else {
		if s.RedirectListen, err = canonicalTLSListen("redirect_listen", redirect); err != nil {
			return err
		}
		if s.RedirectListen == s.Listen {
			return tlsErr("redirect_listen", "must differ from listen")
		}
		if listenersOverlap(s.Listen, s.RedirectListen) {
			return tlsErr("redirect_listen", "must not use the port of listen on an address that overlaps it")
		}
	}
	return nil
}

func normalizeTLSHosts(in []string) ([]string, error) {
	out := make([]string, 0, len(in))
	seen := make(map[string]bool, len(in))
	for _, h := range in {
		h = lowerASCII(strings.TrimSpace(h))
		if seen[h] {
			continue
		}
		seen[h] = true
		if msg := checkTLSHost(h); msg != "" {
			return nil, tlsErr("hosts", "%q %s", cutMaintenanceValue(h), msg)
		}
		out = append(out, h)
	}
	if len(out) > TLSMaxHosts {
		return nil, tlsErr("hosts", "at most %d hosts", TLSMaxHosts)
	}
	return out, nil
}

// lowerASCII lower-cases A to Z and nothing else. strings.ToLower also folds U+0130 to i and the
// Kelvin sign to k, which would turn a name that is not ASCII into another name that is.
func lowerASCII(s string) string {
	b := []byte(s)
	for i, c := range b {
		if 'A' <= c && c <= 'Z' {
			b[i] = c + 'a' - 'A'
		}
	}
	return string(b)
}

// checkTLSHost returns why h is not a host name the agent serves, or "". The agent matches the
// name of the TLS handshake and the Host header exactly, so only plain lower-case DNS names are
// allowed.
func checkTLSHost(h string) string {
	switch {
	case h == "":
		return "is empty"
	case len(h) > 253:
		return "is longer than 253 bytes"
	case strings.Contains(h, "*"):
		return "must not contain a wildcard"
	case strings.Contains(h, ":"):
		return "must not contain a port or be an IPv6 address"
	case strings.HasSuffix(h, "."):
		return "must not end with a dot"
	}
	if _, err := netip.ParseAddr(h); err == nil {
		return "must be a DNS name, not an IP address"
	}
	if !strings.Contains(h, ".") {
		return "must contain at least one dot"
	}
	labels := strings.Split(h, ".")
	// A browser reads a name like 10.1.1 as an address.
	if last := labels[len(labels)-1]; strings.Trim(last, "0123456789") == "" && last != "" {
		return "must not end with a label of digits only"
	}
	for _, label := range labels {
		switch {
		case label == "":
			return "has an empty label"
		case len(label) > 63:
			return "has a label longer than 63 bytes"
		case label[0] == '-' || label[len(label)-1] == '-':
			return "has a label that starts or ends with a hyphen"
		}
		for i := 0; i < len(label); i++ {
			c := label[i]
			if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '-' {
				return "must use only letters, digits, hyphens and dots (write an international name in its xn-- form)"
			}
		}
	}
	return ""
}

// canonicalTLSListen returns v written the way the agent compares listener addresses.
func canonicalTLSListen(field, v string) (string, error) {
	ap, err := netip.ParseAddrPort(v)
	if err != nil || ap.Addr().Zone() != "" || ap.Port() == 0 {
		return "", tlsErr(field, "must be ip:port or [ipv6]:port with a port from 1 to 65535")
	}
	return ap.String(), nil
}

// TLSSite is one application in gateway mode as far as the placement checks need it.
type TLSSite struct {
	AppID, Name    string
	Listen         string
	RedirectListen string
	Hosts          []string
}

// PlainListener is the listener an application opens for itself (listen_host and listen_port of
// apps). The agent refuses a bundle that names one address twice.
type PlainListener struct {
	AppID, Name string
	Addr        netip.AddrPort
}

// TLSConflictError says why an application cannot be placed on an agent next to the others. Code is
// one of the TLSConflict values. OtherAppName is an application of the same project, because an
// agent only serves the applications of its own project.
type TLSConflictError struct {
	Code string
	// Field is the JSON key of the setting that must change: hosts, listen or redirect_listen, or
	// listen_port when it is the plain listener of the application that clashes.
	Field string
	// Address is the listener that is shared or taken; Host is the host that clashes. Either may be "".
	Address, Host string
	OtherAppID    string
	OtherAppName  string
}

func (e *TLSConflictError) Error() string {
	switch e.Code {
	case TLSConflictHost:
		return fmt.Sprintf("host %s on %s is already served by application %s", e.Host, e.Address, e.OtherAppName)
	default:
		return fmt.Sprintf("address %s is already used by application %s", e.Address, e.OtherAppName)
	}
}

// listenersOverlap says whether two different listener addresses cannot both be bound: the same
// port, and one of them is a wildcard that takes the other. 0.0.0.0 takes every IPv4 address and
// [::] takes every address, since a socket on it is dual-stack by default on Linux. The same
// address twice is not an overlap: it is one listener that both applications share, where that is
// allowed.
func listenersOverlap(a, b string) bool {
	if a == b || a == "" || b == "" {
		return false
	}
	x, err := netip.ParseAddrPort(a)
	if err != nil {
		return false
	}
	y, err := netip.ParseAddrPort(b)
	if err != nil || x.Port() != y.Port() {
		return false
	}
	return wildcardTakes(x.Addr(), y.Addr()) || wildcardTakes(y.Addr(), x.Addr())
}

func wildcardTakes(wildcard, other netip.Addr) bool {
	switch wildcard {
	case netip.IPv6Unspecified():
		return true
	case netip.IPv4Unspecified():
		return other.Is4()
	}
	return false
}

// listenersClash is for a listener of one kind against one of another kind (HTTPS, redirect or
// plain): they can never be the same listener, so the same address clashes too, and so does an
// overlap. Linux refuses the second bind whatever kind of listener it is for.
func listenersClash(a, b string) bool {
	return a != "" && b != "" && (a == b || listenersOverlap(a, b))
}

// CheckTLSPlacement checks that self can run on an agent that also serves others (the other
// applications in gateway mode on that agent) and plain (the plain listeners of every application
// on it, self included). self is in gateway mode when its Listen is set; otherwise it only has its
// own plain listener, in plain, to place. It returns a *TLSConflictError.
//
// The agent applies a bundle as a whole and refuses all of it when one of these does not hold, so
// they are refused when the setting is saved: a listener address is used by one kind of listener
// only (a plain listener, HTTPS, or a redirect), except that several applications may share one
// HTTPS listener and one redirect listener by naming the same address; two addresses on one port
// cannot both be bound when one of them is a wildcard (a plain listener counts as well); a host
// once per HTTPS listener; and a host that one redirect listener sends to one HTTPS port only. Two
// plain listeners are only compared by the database, which refuses the same address twice on an
// agent. Applications that share an HTTPS listener may have different limits: the agent applies the
// largest value per listener and the limits of each application after routing.
func CheckTLSPlacement(self TLSSite, others []TLSSite, plain []PlainListener) error {
	gateway := self.Listen != ""
	if gateway {
		for _, field := range []struct {
			name, addr string
		}{{"listen", self.Listen}, {"redirect_listen", self.RedirectListen}} {
			if field.addr == "" {
				continue
			}
			if _, err := netip.ParseAddrPort(field.addr); err != nil {
				return tlsErr(field.name, "must be ip:port or [ipv6]:port")
			}
			for _, p := range plain {
				if listenersClash(field.addr, p.Addr.String()) {
					return &TLSConflictError{Code: TLSConflictListen, Field: field.name, Address: field.addr, OtherAppID: p.AppID, OtherAppName: p.Name}
				}
			}
		}
	}

	// The plain listener of self against the HTTPS and redirect listeners of the others.
	for _, p := range plain {
		if p.AppID != self.AppID {
			continue
		}
		for _, o := range others {
			if o.AppID == self.AppID {
				continue
			}
			for _, addr := range []string{o.Listen, o.RedirectListen} {
				if listenersClash(addr, p.Addr.String()) {
					return &TLSConflictError{Code: TLSConflictListen, Field: "listen_port", Address: addr, OtherAppID: o.AppID, OtherAppName: o.Name}
				}
			}
		}
	}
	if !gateway {
		return nil
	}

	for _, o := range others {
		if o.AppID == self.AppID {
			continue
		}
		clash := func(field, addr string) error {
			return &TLSConflictError{Code: TLSConflictListen, Field: field, Address: addr, OtherAppID: o.AppID, OtherAppName: o.Name}
		}
		switch {
		case listenersClash(self.RedirectListen, o.Listen):
			return clash("redirect_listen", o.Listen)
		case listenersClash(o.RedirectListen, self.Listen):
			return clash("listen", self.Listen)
		case listenersOverlap(self.Listen, o.Listen):
			return clash("listen", o.Listen)
		case listenersOverlap(self.RedirectListen, o.RedirectListen):
			return clash("redirect_listen", o.RedirectListen)
		}
	}

	for _, o := range others {
		if o.AppID == self.AppID {
			continue
		}
		if o.Listen == self.Listen {
			if host, ok := sharedTLSHost(self.Hosts, o.Hosts); ok {
				return &TLSConflictError{Code: TLSConflictHost, Field: "hosts", Address: self.Listen, Host: host, OtherAppID: o.AppID, OtherAppName: o.Name}
			}
		}
		// One redirect listener answers a host with one HTTPS port. Two applications that share it
		// and a host, on HTTPS listeners with different ports, would give it two.
		if self.RedirectListen != "" && o.RedirectListen == self.RedirectListen && tlsPort(o.Listen) != tlsPort(self.Listen) {
			if host, ok := sharedTLSHost(self.Hosts, o.Hosts); ok {
				return &TLSConflictError{Code: TLSConflictListen, Field: "redirect_listen", Address: self.RedirectListen, Host: host, OtherAppID: o.AppID, OtherAppName: o.Name}
			}
		}
	}
	return nil
}

func tlsPort(addr string) uint16 {
	ap, err := netip.ParseAddrPort(addr)
	if err != nil {
		return 0
	}
	return ap.Port()
}

func sharedTLSHost(a, b []string) (string, bool) {
	in := make(map[string]bool, len(b))
	for _, h := range b {
		in[h] = true
	}
	for _, h := range a {
		if in[h] {
			return h, true
		}
	}
	return "", false
}
