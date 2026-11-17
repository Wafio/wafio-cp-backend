package hostpolicy

import (
	"errors"
	"fmt"
	"math"
	"net/netip"
	"sort"
	"strings"
	"time"
)

// Lockout guard.
//
// A firewall policy the dataplane would enforce as written must never cut
// SSH or the agent ↔ control-plane path. The same checks run on the control
// plane before a desired state is stored (so the dashboard shows the error
// before anything is pushed) and on the host agent before any map changes.
//
// Division of labour with the dataplane (wafio_xdp.c / wafio_tc.c):
//   - Replies to connections this host opened pass the ingress default deny
//     and wildcard blocklist entries (XDP reply bypass, connection tracking).
//   - Replies to tracked inbound connections (SSH sessions) pass the egress
//     port filter and wildcard egress entries (TC reply exemption).
//   - The configured control-plane address:port is always passed in both
//     directions (TC egress; XDP only for replies of a tracked flow).
//
// What the dataplane cannot know is which inbound port an operator uses to
// reach the host, so ingress Deny All must allow the SSH port explicitly, and
// a wildcard blocklist must leave an allowlisted management address.

var (
	ErrIngressDenyNeedsConntrack   = errors.New("connection tracking must be enabled before ingress Deny All; replies to connections this host opens would otherwise be dropped")
	ErrIngressDenyNeedsAllow       = errors.New("ingress Deny All requires a non-expiring ingress ALLOW rule for the SSH port over TCP")
	ErrEgressDenyNeedsConntrack    = errors.New("connection tracking must be enabled before egress Deny All; replies to inbound connections such as SSH would otherwise be dropped")
	ErrWildcardBlockNeedsConntrack = errors.New("connection tracking must be enabled before blocking 0.0.0.0/0 or ::/0; replies to connections this host opens would otherwise be dropped")
	ErrWildcardBlockNeedsAllowlist = errors.New("blocking every address of a family (0.0.0.0/0 or ::/0), or half of it or more, requires a non-expiring allowlist entry of the same family for management access")
	// ErrEgressBlockTooBroad: egress entries other than the family-wide one
	// drop replies to inbound connections too (only 0.0.0.0/0 and ::/0 spare
	// them); covering half a family or more that way cuts SSH replies
	// to most of the world.
	ErrEgressBlockTooBroad = errors.New("egress blocklist entries cover half of an address family or more; replies to inbound connections such as SSH would be dropped — use 0.0.0.0/0 or ::/0 (replies stay open) or egress Deny All")
	ErrInvalidPortPolicy   = errors.New("invalid port rule")
	// ErrDataplaneLacksExemptions is agent-side only: the attached BPF objects
	// predate the reply exemption, so egress Deny All or a wildcard blocklist
	// would cut SSH replies and the control-plane stream.
	// ErrEgressDenyUnpinned is agent-side only: egress Deny All without a
	// permanent DNS allow while the control plane is configured by name and
	// not yet pinned in the dataplane — the agent could not reach it again.
	ErrEgressDenyUnpinned = errors.New("egress Deny All without a DNS (53/udp) ALLOW rule needs the control-plane address pinned in the dataplane first; it is not yet")
	// ErrNoControlPlaneMap: the attached XDP object has no wafio_cp_endpoints.
	ErrNoControlPlaneMap        = errors.New("attached eBPF objects have no control-plane endpoint map")
	ErrDataplaneLacksExemptions = errors.New("the attached eBPF objects predate the reply and control-plane exemptions; egress Deny All and 0.0.0.0/0 or ::/0 blocklist entries need the current objects")

	// Geo allow mode ("only these countries") is a default deny for every
	// public source outside the listed countries, guarded like the other
	// broad drops: it needs connection tracking (replies to connections this
	// host opens, and the inbound sessions already open, pass through it), at
	// least one country, and an explicit acknowledgement that sources
	// outside the list — possibly the operator's own — are dropped.
	ErrGeoModeInvalid         = errors.New(`geo mode must be "block" or "allow"`)
	ErrGeoCountryInvalid      = errors.New("country codes must be ISO 3166-1 alpha-2 (two letters)")
	ErrGeoAllowNeedsConntrack = errors.New("connection tracking must be enabled before geo allow mode; replies to connections this host opens and the sessions already open would otherwise be dropped")
	ErrGeoAllowEmpty          = errors.New("geo allow mode needs at least one allowed country; it would otherwise drop every public source")
	ErrGeoAllowUnacknowledged = errors.New("geo allow mode drops every public source outside the allowed countries, possibly your own; confirm it (allow_acknowledged) after adding the address you administer from to the allowlist")
	// ErrGeoAllowNoDataset is agent-side only: no GeoIP country database is
	// loaded, so allow mode would drop every public source.
	ErrGeoAllowNoDataset = errors.New("geo allow mode needs the GeoIP country database on the host agent (security data geoip-country); none is loaded")
	// ErrGeoAllowNoRanges is agent-side only: the GeoIP database has no
	// range for any allowed country.
	ErrGeoAllowNoRanges = errors.New("the GeoIP country database has no address range for the allowed countries; allow mode would drop every public source")
)

// DefaultSSHPort is guarded when no sshd listener was detected.
const DefaultSSHPort uint16 = 22

// DefaultControlPlanePort is the agent gRPC port (server.agent_grpc_addr).
const DefaultControlPlanePort uint16 = 9090

// Stable API codes for the lockout-guard errors. The dashboard keys on these.
var firewallErrorCodes = []struct {
	err  error
	code string
}{
	{ErrIngressDenyNeedsConntrack, "CONNTRACK_REQUIRED"},
	{ErrEgressDenyNeedsConntrack, "CONNTRACK_REQUIRED"},
	{ErrWildcardBlockNeedsConntrack, "CONNTRACK_REQUIRED"},
	{ErrIngressDenyNeedsAllow, "SSH_ALLOW_REQUIRED"},
	{ErrWildcardBlockNeedsAllowlist, "WILDCARD_BLOCK_NEEDS_ALLOWLIST"},
	{ErrEgressBlockTooBroad, "EGRESS_BLOCK_TOO_BROAD"},
	{ErrInvalidPortPolicy, "PORT_POLICY_INVALID"},
	{ErrDataplaneLacksExemptions, "FIREWALL_DATAPLANE_OUTDATED"},
	{ErrEgressDenyUnpinned, "CONTROL_PLANE_UNPINNED"},
	{ErrInvalidIPEntry, "INVALID_IP"},
	{ErrAllowlistNestingTooDeep, "ALLOWLIST_NESTING_TOO_DEEP"},
	{ErrAllowlistWildcardScoped, "ALLOWLIST_WILDCARD_SCOPED"},
	{ErrAllowlistPortsTooMany, "ALLOWLIST_PORTS_TOO_MANY"},
	{ErrInvalidPorts, "INVALID_PORTS"},
	{ErrAllowlistPortsUnsupported, "ALLOWLIST_PORTS_UNSUPPORTED"},
	{ErrBlocklistNestingTooDeep, "BLOCKLIST_NESTING_TOO_DEEP"},
	{ErrIPListCapacity, "IP_LIST_FULL"},
	{ErrIPListBatch, "IP_LIST_BATCH"},
	{ErrGeoModeInvalid, "GEO_MODE_INVALID"},
	{ErrGeoCountryInvalid, "GEO_COUNTRY_INVALID"},
	{ErrGeoAllowNeedsConntrack, "CONNTRACK_REQUIRED"},
	{ErrGeoAllowEmpty, "GEO_ALLOW_EMPTY"},
	{ErrGeoAllowUnacknowledged, "GEO_ALLOW_UNACKNOWLEDGED"},
	{ErrGeoAllowUnsupported, "GEO_ALLOW_UNSUPPORTED"},
	{ErrGeoAllowNoDataset, "GEO_ALLOW_NO_DATASET"},
	{ErrGeoAllowNoRanges, "GEO_ALLOW_NO_RANGES"},
	{ErrGeoRangesExceedCapacity, "GEO_RANGES_EXCEED_CAPACITY"},
}

// FirewallErrorCode returns the stable API code of a lockout-guard error.
func FirewallErrorCode(err error) (string, bool) {
	for _, c := range firewallErrorCodes {
		if errors.Is(err, c.err) {
			return c.code, true
		}
	}
	return "", false
}

// Warning codes: accepted configurations that still deserve a second look.
const (
	WarnEgressControlPlaneRuleMissing = "EGRESS_CONTROL_PLANE_RULE_MISSING"
	WarnEgressDNSRuleMissing          = "EGRESS_DNS_RULE_MISSING"
	WarnEgressWildcardBlock           = "EGRESS_WILDCARD_BLOCK"
	// WarnSSHPortAssumed: ingress Deny All is guarded on 22/tcp because no
	// sshd listener was detected (socket-activated sshd, dropbear, a
	// separate PID namespace, or an agent that does not report ssh_ports).
	WarnSSHPortAssumed = "SSH_PORT_ASSUMED"
	// WarnGeoAllowActive: geo allow mode is enforced (not monitor-only).
	WarnGeoAllowActive = "GEO_ALLOW_ACTIVE"
	// WarnGeoAllowNoEscape: geo allow mode is enforced and no allowlist
	// entry is a lockout escape (LockoutEscape): an administrator whose
	// address leaves the allowed countries has no way in but the console.
	WarnGeoAllowNoEscape = "GEO_ALLOW_NO_ESCAPE"
)

// FirewallWarning is a non-blocking lockout-check finding.
type FirewallWarning struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

// FirewallSafetyInput is the desired state the lockout guard judges.
type FirewallSafetyInput struct {
	Config           *FullConfigAPI
	PortPolicyConfig *PortPolicyConfigAPI
	PortPolicies     []PortPolicyAPI
	Blocklist        []BlocklistEntry
	Allowlist        []AllowlistEntry
	EgressBlocklist  []EgressBlocklistEntry
	// SSHPorts are the TCP ports sshd listens on; empty means DefaultSSHPort.
	// An allow rule for any one of them satisfies the ingress guard.
	SSHPorts []uint16
	// ControlPlanePort is the agent ↔ control-plane port named in the egress
	// warning; 0 means DefaultControlPlanePort.
	ControlPlanePort uint16
	// ControlPlaneUnpinned (agent side): the control plane is configured but
	// not pinned in wafio_cp_endpoints; egress Deny All then needs DNS.
	ControlPlaneUnpinned bool
	// GeoMode is the geo mode ("block", "allow"; "" = block); GeoAllowed the
	// allow-mode countries; GeoAllowAcknowledged the operator's confirmation
	// of allow mode's lockout warning (the dashboard confirm dialog).
	GeoMode              string
	GeoAllowed           []string
	GeoAllowAcknowledged bool
	// AllowlistPortsUnsupported (control plane): the host has not reported
	// "allowlist_ports", so its agent drops port-scoped entries before its
	// own check; they are no escape hatch here either.
	AllowlistPortsUnsupported bool
	// Now bounds entry expiry; zero means time.Now().
	Now time.Time
}

func (in FirewallSafetyInput) now() time.Time {
	if in.Now.IsZero() {
		return time.Now()
	}
	return in.Now
}

func (in FirewallSafetyInput) conntrack() bool {
	return in.Config != nil && in.Config.Global.EnableConntrack
}

// GeoAllowActive: geo allow mode is on. Like the agent, geo filtering
// counts as enabled when no config is given.
func (in FirewallSafetyInput) GeoAllowActive() bool {
	mode, _ := NormalizeGeoMode(in.GeoMode)
	return mode == GeoModeAllow && (in.Config == nil || in.Config.Global.EnableGeoblock)
}

func (in FirewallSafetyInput) ingressDeny() bool {
	p := in.PortPolicyConfig
	return p != nil && p.Enabled && p.DefaultIngress == "deny"
}

func (in FirewallSafetyInput) egressDeny() bool {
	p := in.PortPolicyConfig
	return p != nil && p.Enabled && p.DefaultEgress == "deny"
}

// ValidatePortPolicyRule rejects rule fields the dataplane cannot represent
// literally. Unknown actions used to become DROP; an unknown protocol
// silently meant "any". Empty proto/direction keep their documented defaults
// (any protocol, ingress).
func ValidatePortPolicyRule(p PortPolicyAPI) error {
	label := fmt.Sprintf("port rule %d/%s/%s", p.Port, p.Proto, p.Direction)
	switch {
	case p.Port == 0:
		return fmt.Errorf("%w: %s: port must be 1-65535", ErrInvalidPortPolicy, label)
	case p.Action != "allow" && p.Action != "drop" && p.Action != "log":
		return fmt.Errorf("%w: %s: action %q is not allow, drop or log", ErrInvalidPortPolicy, label, Clip(p.Action))
	case p.Proto != "" && p.Proto != "any" && p.Proto != "tcp" && p.Proto != "udp":
		return fmt.Errorf("%w: %s: protocol %q is not tcp, udp or any", ErrInvalidPortPolicy, label, Clip(p.Proto))
	case p.Direction != "" && p.Direction != "ingress" && p.Direction != "egress" && p.Direction != "both":
		return fmt.Errorf("%w: %s: direction %q is not ingress, egress or both", ErrInvalidPortPolicy, label, Clip(p.Direction))
	case p.TTLMs < 0:
		return fmt.Errorf("%w: %s: ttl_ms must not be negative", ErrInvalidPortPolicy, label)
	}
	if p.ExpiresAt != "" {
		if _, err := time.Parse(time.RFC3339, p.ExpiresAt); err != nil {
			return fmt.Errorf("%w: %s: expires_at is not an RFC 3339 time", ErrInvalidPortPolicy, label)
		}
	}
	return nil
}

// PortPolicyDeadline is the one reading of a rule's expiry, shared by the
// lockout guard and Manager.AddPortPolicy so both agree:
// the earlier of now+ttl_ms and expires_at. expired: the deadline has
// passed — the dataplane then leaves the slot empty.
func PortPolicyDeadline(p PortPolicyAPI, now time.Time) (deadline time.Time, expiring, expired bool) {
	if p.TTLMs > 0 {
		deadline = now.Add(time.Duration(p.TTLMs) * time.Millisecond)
		expiring = true
	}
	if p.ExpiresAt != "" {
		if exp, err := time.Parse(time.RFC3339, p.ExpiresAt); err == nil && (!expiring || exp.Before(deadline)) {
			deadline = exp
			expiring = true
		}
	}
	return deadline, expiring, expiring && !deadline.After(now)
}

// Clip keeps echoed client input short enough for an API error message.
func Clip(s string) string {
	if len(s) > 16 {
		return s[:16] + "…"
	}
	return s
}

// ValidateFirewallSafety returns an error for a configuration that would
// lock the host out (or that the dataplane cannot represent), and warnings
// for accepted configurations that still block something operators rely on.
func ValidateFirewallSafety(in FirewallSafetyInput) ([]FirewallWarning, error) {
	for _, p := range in.PortPolicies {
		if err := ValidatePortPolicyRule(p); err != nil {
			return nil, err
		}
	}
	if _, ok := NormalizeGeoMode(in.GeoMode); !ok {
		return nil, fmt.Errorf("%w (got %q)", ErrGeoModeInvalid, Clip(in.GeoMode))
	}
	for _, code := range in.GeoAllowed {
		if _, ok := NormalizeCountryCode(code); !ok {
			return nil, fmt.Errorf("%w (got %q)", ErrGeoCountryInvalid, Clip(code))
		}
	}
	now := in.now()
	// Allowlist port scopes: valid, at most ALLOW_MAX_SCOPES, never
	// on a /0 entry, one set of ports per prefix.
	if err := ValidateAllowlistPorts(in.Allowlist, now); err != nil {
		return nil, err
	}
	// The IP lists must be representable as the XDP walk reads them.
	if err := ValidateIPListNesting(in.Allowlist, in.Blocklist, now); err != nil {
		return nil, err
	}

	rules := effectivePortRules(in.PortPolicies, now)
	var warnings []FirewallWarning

	sshAssumedWarned := false
	sshAssumedWarning := func() {
		if sshAssumedWarned {
			return
		}
		sshAssumedWarned = true
		warnings = append(warnings, FirewallWarning{
			Code: WarnSSHPortAssumed,
			Message: "No sshd listener was detected on the host (socket-activated sshd, dropbear or a separate PID namespace), " +
				"so the lockout check guards 22/tcp. Make sure your management port is allowed.",
		})
	}
	// escapeHatch: a permanent allowlist entry of the family that keeps SSH
	// open (every port, or a TCP/any scope on an SSH port). A scope that
	// relies on the assumed port 22 adds the SSH_PORT_ASSUMED warning.
	escapeHatch := func(family int) bool {
		allow := in.Allowlist
		if in.AllowlistPortsUnsupported {
			allow = unscopedAllowlist(allow)
		}
		ok, viaAssumed := lockoutEscapeFamily(allow, family, in.SSHPorts)
		if ok && viaAssumed {
			sshAssumedWarning()
		}
		return ok
	}

	if in.ingressDeny() {
		if !in.conntrack() {
			return nil, ErrIngressDenyNeedsConntrack
		}
		sshPorts := in.SSHPorts
		assumed := len(sshPorts) == 0
		if assumed {
			sshPorts = []uint16{DefaultSSHPort}
		}
		allowed := false
		for _, port := range sshPorts {
			if alwaysAllowed(rules, port, ProtoTCP, dirIngress) {
				allowed = true
				break
			}
		}
		if !allowed {
			hint := ""
			if assumed {
				hint = " (no sshd listener was detected on the host, so 22/tcp is assumed)"
			}
			return nil, fmt.Errorf("%w: add a permanent ingress ALLOW rule for %s that no other rule overrides%s",
				ErrIngressDenyNeedsAllow, portList(sshPorts, "tcp"), hint)
		}
		if assumed {
			sshAssumedWarning()
		}
	}

	if in.egressDeny() && !in.conntrack() {
		return nil, ErrEgressDenyNeedsConntrack
	}
	if in.egressDeny() && in.ControlPlaneUnpinned && !alwaysAllowed(rules, 53, ProtoUDP, dirEgress) {
		return nil, ErrEgressDenyUnpinned
	}

	liveBlocks := liveBlockIPs(in.Blocklist, now)
	for _, family := range wildcardFamilies(liveBlocks) {
		if !in.conntrack() {
			return nil, ErrWildcardBlockNeedsConntrack
		}
		if !escapeHatch(family) {
			return nil, fmt.Errorf("%w: add a permanent %s allowlist entry for your management network (every port, or scoped to SSH: %s)",
				ErrWildcardBlockNeedsAllowlist, familyName(family), portList(sshPortsOrDefault(in.SSHPorts), "tcp"))
		}
	}
	// Since prefixes are stored natively a block can cover most of a
	// family without being the /0 entry (0.0.0.0/1 + 128.0.0.0/1, or
	// 0.0.0.1-255.255.255.255). Such a block also drops the replies the /0
	// entry spares, so it needs the same escape hatch.
	for _, family := range broadFamilies(liveBlocks) {
		if !escapeHatch(family) {
			return nil, fmt.Errorf("%w: the blocklist covers half of %s or more; add a permanent %s allowlist entry for your management network (every port, or scoped to SSH: %s)",
				ErrWildcardBlockNeedsAllowlist, familyName(family), familyName(family), portList(sshPortsOrDefault(in.SSHPorts), "tcp"))
		}
	}
	liveEgress := liveEgressIPs(in.EgressBlocklist, now)
	egressWildcard := len(wildcardFamilies(liveEgress)) > 0
	if egressWildcard && !in.conntrack() {
		return nil, ErrWildcardBlockNeedsConntrack
	}
	if families := broadFamilies(liveEgress); len(families) > 0 {
		return nil, fmt.Errorf("%w (%s)", ErrEgressBlockTooBroad, familyName(families[0]))
	}
	if in.GeoAllowActive() {
		if !in.conntrack() {
			return nil, ErrGeoAllowNeedsConntrack
		}
		if len(in.GeoAllowed) == 0 {
			return nil, ErrGeoAllowEmpty
		}
		if !in.GeoAllowAcknowledged {
			return nil, ErrGeoAllowUnacknowledged
		}
		if !in.Config.Global.MonitorOnly && !escapeHatch(4) && !escapeHatch(6) {
			warnings = append(warnings, FirewallWarning{
				Code: WarnGeoAllowNoEscape,
				Message: "Geo allow mode is enforced and no permanent allowlist entry keeps SSH open (every port, or scoped to " +
					portList(sshPortsOrDefault(in.SSHPorts), "tcp") + "). If you administer the host from outside the allowed countries, allowlist that address first.",
			})
		}
		if !in.Config.Global.MonitorOnly {
			warnings = append(warnings, FirewallWarning{
				Code: WarnGeoAllowActive,
				Message: fmt.Sprintf("Geo allow mode is enforced: new inbound connections from outside %s (and from addresses missing from the GeoIP data) are dropped. "+
					"Replies to connections this host opens, TCP sessions open before the switch, allowlisted addresses (port-scoped entries on their ports only), private TCP sources "+
					"(private UDP only from the subnets of the interface the firewall runs on) and the control plane stay open.",
					countryList(in.GeoAllowed)),
			})
		}
	}

	if in.egressDeny() {
		cpPort := in.ControlPlanePort
		if cpPort == 0 {
			cpPort = DefaultControlPlanePort
		}
		if !alwaysAllowed(rules, cpPort, ProtoTCP, dirEgress) {
			warnings = append(warnings, FirewallWarning{
				Code: WarnEgressControlPlaneRuleMissing,
				Message: fmt.Sprintf("Egress Deny All has no permanent egress ALLOW rule for the control-plane port %d/tcp. "+
					"Current agents keep their own control-plane connection open; agents with older eBPF objects refuse this policy.", cpPort),
			})
		}
		if !alwaysAllowed(rules, 53, ProtoUDP, dirEgress) {
			warnings = append(warnings, FirewallWarning{
				Code:    WarnEgressDNSRuleMissing,
				Message: "Egress Deny All has no permanent egress ALLOW rule for DNS (53/udp): name resolution, package updates and most outbound clients stop.",
			})
		}
	}
	if egressWildcard {
		warnings = append(warnings, FirewallWarning{
			Code: WarnEgressWildcardBlock,
			Message: "The egress blocklist covers every address of a family: every outbound connection, DNS included, is dropped. " +
				"Replies to inbound connections, the control-plane connection, DHCP requests and IPv6 neighbour discovery stay open.",
		})
	}
	return warnings, nil
}

// ValidateHostFirewall is the host-agent entry point (gRPC desired state and
// local API alike): the lockout guard, plus refusal of states that rely on
// the newer dataplane when the attached objects predate it.
func ValidateHostFirewall(in FirewallSafetyInput, exemptions bool) ([]FirewallWarning, error) {
	warnings, err := ValidateFirewallSafety(in)
	if err != nil {
		return nil, err
	}
	if !exemptions && NeedsDataplaneExemptions(in) {
		return nil, ErrDataplaneLacksExemptions
	}
	return warnings, nil
}

// NeedsDataplaneExemptions reports whether in relies on the newer dataplane
// (TC reply exemption, wildcard-after-reply ordering, control-plane pass).
// Older BPF objects would enforce such a state as a lockout.
func NeedsDataplaneExemptions(in FirewallSafetyInput) bool {
	now := in.now()
	return in.egressDeny() ||
		len(wildcardFamilies(liveBlockIPs(in.Blocklist, now))) > 0 ||
		len(wildcardFamilies(liveEgressIPs(in.EgressBlocklist, now))) > 0
}

// Port-rule evaluation mirrors the dataplane exactly:
//   - a rule's BPF key is (port, proto, direction) with "" proto = any and
//     "" direction = ingress, so "" and "any" rules share one map slot and the
//     rule written last (later in the list) replaces the earlier one;
//   - the packet takes the first LIVE rule in lookup order (match_port_rule
//     in wafio_xdp.c / wafio_tc.c): exact protocol + direction, exact
//     protocol + both, any protocol + direction, any protocol + both; an
//     expired rule is skipped, never decisive.
// alwaysAllowed asks whether the port stays open now and after every
// expiring rule has lapsed.

const (
	ProtoAny uint8 = 0
	ProtoTCP uint8 = 6
	ProtoUDP uint8 = 17

	dirIngress uint8 = 0
	dirEgress  uint8 = 1
	dirBoth    uint8 = 2
)

type portRuleKey struct {
	port  uint16
	proto uint8
	dir   uint8
}

// portRuleKeyOf maps a validated rule to its BPF key (protoStringToNum /
// directionStringToNum in manager.go).
func portRuleKeyOf(p PortPolicyAPI) portRuleKey {
	k := portRuleKey{port: p.Port, proto: ProtoAny, dir: dirIngress}
	switch p.Proto {
	case "tcp":
		k.proto = ProtoTCP
	case "udp":
		k.proto = ProtoUDP
	}
	switch p.Direction {
	case "egress":
		k.dir = dirEgress
	case "both":
		k.dir = dirBoth
	}
	return k
}

// CanonicalPortPolicy spells out a rule's defaults ("" proto = any, ""
// direction = ingress) so two spellings of one map slot compare equal.
func CanonicalPortPolicy(p PortPolicyAPI) PortPolicyAPI {
	if p.Proto == "" {
		p.Proto = "any"
	}
	if p.Direction == "" {
		p.Direction = "ingress"
	}
	return p
}

// SamePortPolicyKey reports whether a and b occupy the same BPF map slot.
func SamePortPolicyKey(a, b PortPolicyAPI) bool { return portRuleKeyOf(a) == portRuleKeyOf(b) }

// portRuleExpires: the rule carries a TTL or an expiry, so it will lapse.
func portRuleExpires(p PortPolicyAPI) bool { return p.TTLMs != 0 || p.ExpiresAt != "" }

// portRuleExpired: the deadline has passed; AddPortPolicy empties the slot
// (PortPolicyDeadline), so such a rule never decides.
func portRuleExpired(p PortPolicyAPI, now time.Time) bool {
	_, _, expired := PortPolicyDeadline(p, now)
	return expired
}

// effectivePortRules is the map content after writing rules in order.
func effectivePortRules(rules []PortPolicyAPI, now time.Time) map[portRuleKey]PortPolicyAPI {
	out := make(map[portRuleKey]PortPolicyAPI, len(rules))
	for _, r := range rules {
		k := portRuleKeyOf(r)
		if portRuleExpired(r, now) {
			delete(out, k) // written last, and already gone from the lookup
			continue
		}
		out[k] = r
	}
	return out
}

// alwaysAllowed: the first live rule in lookup order is a permanent ALLOW,
// and no expiring rule ahead of it drops the port while it lasts. An
// expiring allow or log ahead of it keeps the port open until it lapses and
// then hands over; an expiring rule with nothing permanent behind it leaves
// the port to the default policy once it lapses.
func alwaysAllowed(rules map[portRuleKey]PortPolicyAPI, port uint16, proto, dir uint8) bool {
	for _, k := range []portRuleKey{{port, proto, dir}, {port, proto, dirBoth}, {port, ProtoAny, dir}, {port, ProtoAny, dirBoth}} {
		r, ok := rules[k]
		if !ok {
			continue
		}
		if portRuleExpires(r) {
			if r.Action == "drop" {
				return false
			}
			continue
		}
		return r.Action == "allow"
	}
	return false
}

func liveBlockIPs(entries []BlocklistEntry, now time.Time) []string {
	out := make([]string, 0, len(entries))
	for _, e := range entries {
		if e.ExpiresAt == nil || e.ExpiresAt.After(now) {
			out = append(out, e.IP)
		}
	}
	return out
}

func liveEgressIPs(entries []EgressBlocklistEntry, now time.Time) []string {
	out := make([]string, 0, len(entries))
	for _, e := range entries {
		if e.ExpiresAt == nil || e.ExpiresAt.After(now) {
			out = append(out, e.IP)
		}
	}
	return out
}

// wildcardFamilies returns 4 and/or 6 for entries the dataplane stores as
// the family-wide /0 entry — whatever their spelling (0.0.0.0/0, 1.2.3.4/0,
// 0.0.0.0-255.255.255.255, ::ffff:0:0/96, 0::0/0): the guard reads entries
// through the same IPListPrefixes the agent stores them with. An entry
// that does not parse is skipped here; the representability check refuses
// it.
func wildcardFamilies(ips []string) []int {
	var v4, v6 bool
	for _, ip := range ips {
		prefixes, err := IPListPrefixes(ip)
		if err != nil {
			continue
		}
		for _, p := range prefixes {
			if p.Bits() != 0 {
				continue
			}
			if p.Addr().Is4() {
				v4 = true
			} else {
				v6 = true
			}
		}
	}
	return familyList(v4, v6)
}

// broadFamilies returns 4 and/or 6 for entries that together cover half of
// a family or more without a /0 entry (wildcardFamilies has those).
func broadFamilies(ips []string) []int {
	var v4, v6 []netip.Prefix
	for _, ip := range ips {
		prefixes, err := IPListPrefixes(ip)
		if err != nil {
			continue
		}
		for _, p := range prefixes {
			if p.Bits() == 0 {
				continue
			}
			if p.Addr().Is4() {
				v4 = append(v4, p)
			} else {
				v6 = append(v6, p)
			}
		}
	}
	return familyList(prefixCoverage(v4) >= 0.5, prefixCoverage(v6) >= 0.5)
}

// prefixCoverage is the share of its family the union of prefixes covers
// (prefixes of one family; CIDR blocks are nested or disjoint).
func prefixCoverage(prefixes []netip.Prefix) float64 {
	sort.Slice(prefixes, func(i, j int) bool {
		if c := prefixes[i].Addr().Compare(prefixes[j].Addr()); c != 0 {
			return c < 0
		}
		return prefixes[i].Bits() < prefixes[j].Bits()
	})
	var share float64
	var last netip.Prefix
	for _, p := range prefixes {
		if last.IsValid() && last.Contains(p.Addr()) && last.Bits() <= p.Bits() {
			continue // nested in the previous block
		}
		share += math.Ldexp(1, -p.Bits())
		last = p
	}
	return share
}

func familyList(v4, v6 bool) []int {
	var out []int
	if v4 {
		out = append(out, 4)
	}
	if v6 {
		out = append(out, 6)
	}
	return out
}

// lockoutEscapeFamily reports a lockout-escape allowlist entry
// (LockoutEscape: permanent, every port or a TCP/any scope on an SSH port)
// of the given address family. viaAssumed: only scoped entries qualify and
// only because port 22 is assumed (no sshd listener was reported).
func lockoutEscapeFamily(entries []AllowlistEntry, family int, sshPorts []uint16) (ok, viaAssumed bool) {
	for _, e := range entries {
		if entryFamily(e.IP) != family || !LockoutEscape(e, sshPorts) {
			continue
		}
		if len(e.Ports) == 0 || len(sshPorts) > 0 {
			return true, false
		}
		ok, viaAssumed = true, true
	}
	return ok, viaAssumed
}

// unscopedAllowlist keeps the allowlist entries without ports.
func unscopedAllowlist(entries []AllowlistEntry) []AllowlistEntry {
	out := make([]AllowlistEntry, 0, len(entries))
	for _, e := range entries {
		if len(e.Ports) == 0 {
			out = append(out, e)
		}
	}
	return out
}

// sshPortsOrDefault is the SSH port set the guard checks.
func sshPortsOrDefault(ports []uint16) []uint16 {
	if len(ports) == 0 {
		return []uint16{DefaultSSHPort}
	}
	return ports
}

// entryFamily is the family of the trie an entry lands in (IPListPrefixes:
// an IPv4-mapped prefix of /96 or longer is IPv4, a shorter one stays IPv6);
// 0 for an entry that does not parse.
func entryFamily(entry string) int {
	prefixes, err := IPListPrefixes(entry)
	if err != nil || len(prefixes) == 0 {
		return 0
	}
	if prefixes[0].Addr().Is4() {
		return 4
	}
	return 6
}

func familyName(family int) string {
	if family == 6 {
		return "IPv6"
	}
	return "IPv4"
}

func portList(ports []uint16, proto string) string {
	parts := make([]string, 0, len(ports))
	for _, p := range ports {
		parts = append(parts, fmt.Sprintf("%d/%s", p, proto))
	}
	return strings.Join(parts, " or ")
}

// MaxPortScanUniquePorts mirrors MAX_SCAN_PORTS in wafio_xdp.c: the
// per-source table holds this many distinct ports, so a higher threshold is
// never reached. The program then refuses to decide and logs every TCP
// packet of the source instead.
const MaxPortScanUniquePorts = 32

// ValidatePortScanConfig rejects a port-scan configuration the dataplane
// cannot enforce as written.
func ValidatePortScanConfig(cfg PortScanConfigAPI) error {
	if !cfg.Enabled {
		return nil
	}
	if cfg.MaxUniquePorts < 1 || cfg.MaxUniquePorts > MaxPortScanUniquePorts {
		return fmt.Errorf("max_unique_ports must be in 1..%d", MaxPortScanUniquePorts)
	}
	if cfg.WindowMs < 10 || cfg.WindowMs > 60000 {
		return fmt.Errorf("port scan window_ms must be in 10..60000")
	}
	return nil
}

// NormalizePortScanConfig lowers a stored threshold above
// MaxPortScanUniquePorts to the limit and reports whether it did. Before the check
// the control plane accepted up to 128, which the dataplane enforced as "log
// every TCP packet, never detect". The lowered threshold detects, so it is
// switched to log-only (DropOnDetect false): what the dataplane did before
// never dropped, and a host must not start dropping on upgrade. Migration
// 000100 rewrites stored states the same way; agents normalise what an older
// control plane still delivers.
func NormalizePortScanConfig(cfg *PortScanConfigAPI) bool {
	if cfg == nil || !cfg.Enabled || cfg.MaxUniquePorts <= MaxPortScanUniquePorts {
		return false
	}
	cfg.MaxUniquePorts = MaxPortScanUniquePorts
	cfg.DropOnDetect = false
	return true
}

// Rates are per second; bursts are additional packets in each fixed window.
// MaxBPS counts bytes, not bits. Bounds protect nanosecond conversion and budgets.
func ValidateRateConfig(cfg RateConfigAPI) error {
	if cfg.WindowMs != 0 && (cfg.WindowMs < 10 || cfg.WindowMs > 60000) {
		return fmt.Errorf("rate window_ms must be 0 (default) or in 10..60000")
	}
	if uint64(cfg.MaxPPS)+uint64(cfg.BurstPPS) > uint64(^uint32(0)) || uint64(cfg.MaxSynPPS)+uint64(cfg.BurstSyn) > uint64(^uint32(0)) {
		return fmt.Errorf("rate plus burst exceeds supported limit")
	}
	return nil
}

// Return-flow authorizations expire from the last outbound packet, not replies.
func ConnectionFresh(protocol uint8, lastSeen, now uint64) bool {
	ttl := uint64(30_000_000_000)
	if protocol == 6 {
		ttl = 300_000_000_000
	}
	return now >= lastSeen && now-lastSeen < ttl
}

// countryList names up to five countries for a message ("ID, SG and 3 more").
func countryList(codes []string) string {
	if len(codes) <= 5 {
		return strings.Join(codes, ", ")
	}
	return fmt.Sprintf("%s and %d more", strings.Join(codes[:5], ", "), len(codes)-5)
}
