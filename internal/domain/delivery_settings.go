package domain

import (
	"fmt"
	"strings"
	"unicode/utf8"
)

// Limits of the three delivery parts of an application: compression, files from a folder and the
// response cache. The dashboard keeps the same numbers and messages in its own checks (the cases are
// test/frontend-fixtures/delivery-checks.json), and the WAF agent is never stricter than these.
const (
	KiB = 1 << 10
	MiB = 1 << 20
	GiB = 1 << 30
	TiB = 1 << 40

	deliveryDaySeconds = 24 * 60 * 60
	// DeliveryMaxSeconds is the longest lifetime or browser cache time: 365 days.
	DeliveryMaxSeconds = 365 * deliveryDaySeconds

	DefaultCompressionMinBytes = KiB
	MaxCompressionMinBytes     = MiB

	StaticMissingApp      = "app"
	StaticMissingNotFound = "not_found"
	StaticRootMaxBytes    = 1024

	CacheDefaultTTLSeconds     = 60 * 60
	CacheDefaultStaleSeconds   = 10 * 60
	CacheMaxStaleSeconds       = deliveryDaySeconds
	CacheDefaultDiskBytes      = GiB
	CacheMinDiskBytes          = 16 * MiB
	CacheMaxDiskBytes          = TiB
	CacheDefaultMemoryBytes    = 32 * MiB
	CacheMaxMemoryBytes        = 4 * GiB
	CacheDefaultMaxObjectBytes = 8 * MiB
	CacheMinMaxObjectBytes     = KiB
	CacheMaxMaxObjectBytes     = 64 * MiB
	CacheMaxSessionCookies     = 20
	CacheCookieNameMax         = 64
	CacheMaxRules              = 50
	CachePrefixMaxBytes        = 256

	CacheActionCache  = "cache"
	CacheActionBypass = "bypass"

	StripPathPrefixMaxBytes = 256
)

// DeliveryFieldError is a rejected field of a delivery object. Field is the JSON key, with the
// position for a rule: rules[2].prefix. Msg is the sentence the dashboard shows under that field.
type DeliveryFieldError struct {
	Field, Msg string
}

func (e *DeliveryFieldError) Error() string { return e.Field + ": " + e.Msg }

func deliveryErr(field, msg string) error { return &DeliveryFieldError{Field: field, Msg: msg} }

// Messages of the checks, one per kind of field. They are the texts of the Speed tab.
const (
	msgSeconds0To365Days = "Enter a time from 0 seconds to 365 days."
	msgSeconds0To1Day    = "Enter a time from 0 seconds to 1 day."
	msgRuleSeconds       = "Enter a time from 1 second to 365 days."
	msgBytes0To1MiB      = "Enter a size from 0 bytes to 1 MiB."
	msgDisk              = "Enter a size from 16 MiB to 1 TiB."
	msgMemory            = "Enter a size from 0 bytes to 4 GiB."
	msgObject            = "Enter a size from 1 KiB to 64 MiB, no more than the disk space."
	msgRootInvalid       = "Enter a full path that starts with /, such as /var/www/shop/public, without . or .. parts."
	msgRootForbidden     = "This folder holds system or WAFio files. Choose the folder of your site's files."
	msgMissing           = `Choose "Ask the application" or "Answer Not found".`
	msgCookies           = "Use up to 20 cookie names of up to 64 characters, without spaces, commas, semicolons or =."
	msgRulesMax          = "Up to 50 rules."
	msgRulePath          = "Enter a path that starts with /."
	msgRulePathShape     = "Use a path of up to 256 characters without spaces, ? or #."
	msgRuleOnce          = "Each path can have one rule."
	msgRuleAction        = `Choose "Keep for a time" or "Never keep".`
	msgCanonicalHost     = "Choose one of the host names above."
	msgStripPathPrefix   = "Enter a path that starts with /, such as /shop, without spaces, ?, #, % or . and .. parts, up to 256 characters."
)

// fillInt sets *v to def when the value was left out.
func fillInt(v **int64, def int64) {
	if *v == nil {
		*v = &def
	}
}

func outside(v *int64, lo, hi int64) bool { return *v < lo || *v > hi }

// Compression is the compression of forwarded answers of one application. It is stored in
// apps.compression, where {} is off, and sent to the agent in the bundle only while Enabled.
// MinBytes is a pointer so that an absent value takes the default while an explicit 0 is kept.
type Compression struct {
	Enabled  bool   `json:"enabled"`
	MinBytes *int64 `json:"min_bytes"`
}

// FillDefaults fills the values a request or a stored {} leaves out.
func (c *Compression) FillDefaults() { fillInt(&c.MinBytes, DefaultCompressionMinBytes) }

// Normalize fills the defaults and checks every field, whether the switch is on or off. It returns a
// *DeliveryFieldError for the first field that is not valid.
func (c *Compression) Normalize() error {
	c.FillDefaults()
	if outside(c.MinBytes, 0, MaxCompressionMinBytes) {
		return deliveryErr("min_bytes", msgBytes0To1MiB)
	}
	return nil
}

// StaticFiles is serving files from a folder of the agent's host. It is stored in apps.static_files
// and sent in the bundle only while Enabled.
type StaticFiles struct {
	Enabled bool `json:"enabled"`
	// Root is the absolute folder, "" until one is chosen; a switched-on part needs one.
	Root string `json:"root"`
	// Missing says what happens to a request whose file is not in the folder: StaticMissingApp
	// (the default) goes to the application, StaticMissingNotFound answers 404.
	Missing string `json:"missing"`
	// MaxAgeS is the browser cache time of a served file; 0 sets none.
	MaxAgeS int64 `json:"max_age_s"`
}

// forbiddenStaticRoots are the folders that are never served, and neither is a folder above or
// below one of them. The agent runs the same list again on the folder it resolved.
var forbiddenStaticRoots = []string{
	"/etc", "/root", "/proc", "/sys", "/dev", "/run", "/boot", "/usr",
	"/var/lib/wafio-waf-agent", "/var/cache/wafio-waf",
}

// StaticRootForbidden says whether an absolute path without empty, . or .. segments is the root
// folder, an ancestor of a forbidden folder, or a forbidden folder or something below one.
func StaticRootForbidden(root string) bool {
	if root == "/" {
		return true
	}
	for _, f := range forbiddenStaticRoots {
		if root == f || strings.HasPrefix(root, f+"/") || strings.HasPrefix(f, root+"/") {
			return true
		}
	}
	return false
}

// validStaticRoot says whether root is an absolute path with no empty, . or .. segment, no control
// character and at most StaticRootMaxBytes bytes.
func validStaticRoot(root string) bool {
	if root == "" || root[0] != '/' || len(root) > StaticRootMaxBytes || !utf8.ValidString(root) {
		return false
	}
	for _, r := range root {
		if r < 0x20 || r == 0x7f {
			return false
		}
	}
	if root == "/" {
		return true
	}
	for _, seg := range strings.Split(root[1:], "/") {
		if seg == "" || seg == "." || seg == ".." {
			return false
		}
	}
	return true
}

// Normalize trims the folder (spaces around it, and the slashes that end it, so "/var/www/shop/"
// is "/var/www/shop"), fills the defaults and checks every field. An empty folder is only
// refused while the switch is on.
func (s *StaticFiles) Normalize() error {
	s.Root = strings.TrimSpace(s.Root)
	if t := strings.TrimRight(s.Root, "/"); t != "" {
		s.Root = t
	}
	if s.Missing == "" {
		s.Missing = StaticMissingApp
	}
	if s.Root != "" || s.Enabled {
		if !validStaticRoot(s.Root) {
			return deliveryErr("root", msgRootInvalid)
		}
		if StaticRootForbidden(s.Root) {
			return deliveryErr("root", msgRootForbidden)
		}
	}
	if s.Missing != StaticMissingApp && s.Missing != StaticMissingNotFound {
		return deliveryErr("missing", msgMissing)
	}
	if s.MaxAgeS < 0 || s.MaxAgeS > DeliveryMaxSeconds {
		return deliveryErr("max_age_s", msgSeconds0To365Days)
	}
	return nil
}

// CacheRule is a path rule of the response cache: the longest matching prefix wins.
type CacheRule struct {
	// Prefix is a path that starts with /.
	Prefix string `json:"prefix"`
	// Action is CacheActionCache (keep the answer for TTLS seconds) or CacheActionBypass (never keep).
	Action string `json:"action"`
	// TTLS is 1 to 365 days for a keep rule and 0 for a bypass rule.
	TTLS int64 `json:"ttl_s"`
	// SignedIn lets a keep rule store answers for visitors who are signed in. The dashboard asks the
	// admin to type the prefix first.
	SignedIn bool `json:"signed_in"`
}

// Cache is the response cache of one application, stored in apps.cache and sent in the bundle only
// while Enabled. The numbers are pointers so that an absent value takes the default, which for
// DefaultTTLS and StaleIfErrorS and MemoryBytes is not the same as 0.
type Cache struct {
	Enabled bool `json:"enabled"`
	// DefaultTTLS is how long images, fonts, media, styles and scripts are kept when the application
	// gives no lifetime; 0 turns that off.
	DefaultTTLS *int64 `json:"default_ttl_s"`
	// StaleIfErrorS is how long a stored copy answers while the application is down; 0 sends the error.
	StaleIfErrorS  *int64 `json:"stale_if_error_s"`
	DiskBytes      *int64 `json:"disk_bytes"`
	MemoryBytes    *int64 `json:"memory_bytes"`
	MaxObjectBytes *int64 `json:"max_object_bytes"`
	// SessionCookies are cookie names that mark a visitor as signed in, besides the built-in ones.
	SessionCookies []string    `json:"session_cookies"`
	Rules          []CacheRule `json:"rules"`
}

// FillDefaults fills the values a request or a stored {} leaves out.
func (c *Cache) FillDefaults() {
	fillInt(&c.DefaultTTLS, CacheDefaultTTLSeconds)
	fillInt(&c.StaleIfErrorS, CacheDefaultStaleSeconds)
	fillInt(&c.DiskBytes, CacheDefaultDiskBytes)
	fillInt(&c.MemoryBytes, CacheDefaultMemoryBytes)
	fillInt(&c.MaxObjectBytes, CacheDefaultMaxObjectBytes)
	if c.SessionCookies == nil {
		c.SessionCookies = []string{}
	}
	if c.Rules == nil {
		c.Rules = []CacheRule{}
	}
}

// Normalize fills the defaults, trims and de-duplicates the cookie names (a repeat that differs only
// in case is dropped), and checks every field, whether the switch is on or off. It returns a
// *DeliveryFieldError for the first field that is not valid.
func (c *Cache) Normalize() error {
	c.FillDefaults()
	switch {
	case outside(c.DefaultTTLS, 0, DeliveryMaxSeconds):
		return deliveryErr("default_ttl_s", msgSeconds0To365Days)
	case outside(c.StaleIfErrorS, 0, CacheMaxStaleSeconds):
		return deliveryErr("stale_if_error_s", msgSeconds0To1Day)
	case outside(c.DiskBytes, CacheMinDiskBytes, CacheMaxDiskBytes):
		return deliveryErr("disk_bytes", msgDisk)
	case outside(c.MemoryBytes, 0, CacheMaxMemoryBytes):
		return deliveryErr("memory_bytes", msgMemory)
	case outside(c.MaxObjectBytes, CacheMinMaxObjectBytes, CacheMaxMaxObjectBytes) || *c.MaxObjectBytes > *c.DiskBytes:
		return deliveryErr("max_object_bytes", msgObject)
	}
	cookies := make([]string, 0, len(c.SessionCookies))
	seen := make(map[string]bool, len(c.SessionCookies))
	for _, name := range c.SessionCookies {
		name = strings.TrimSpace(name)
		if name == "" || seen[lowerASCII(name)] {
			continue
		}
		seen[lowerASCII(name)] = true
		if !validCookieName(name) {
			return deliveryErr("session_cookies", msgCookies)
		}
		cookies = append(cookies, name)
	}
	if len(cookies) > CacheMaxSessionCookies {
		return deliveryErr("session_cookies", msgCookies)
	}
	c.SessionCookies = cookies
	if len(c.Rules) > CacheMaxRules {
		return deliveryErr("rules", msgRulesMax)
	}
	prefixes := make(map[string]bool, len(c.Rules))
	for i := range c.Rules {
		if err := c.Rules[i].normalize(i, prefixes); err != nil {
			return err
		}
	}
	return nil
}

func (r *CacheRule) normalize(i int, prefixes map[string]bool) error {
	field := func(name string) string { return fmt.Sprintf("rules[%d].%s", i, name) }
	r.Prefix = strings.TrimSpace(r.Prefix)
	switch {
	case !strings.HasPrefix(r.Prefix, "/"):
		return deliveryErr(field("prefix"), msgRulePath)
	case !cachePrefixShape(r.Prefix):
		return deliveryErr(field("prefix"), msgRulePathShape)
	case prefixes[r.Prefix]:
		return deliveryErr(field("prefix"), msgRuleOnce)
	}
	prefixes[r.Prefix] = true
	switch r.Action {
	case CacheActionCache:
		if r.TTLS < 1 || r.TTLS > DeliveryMaxSeconds {
			return deliveryErr(field("ttl_s"), msgRuleSeconds)
		}
	case CacheActionBypass:
		// A rule that never keeps has no lifetime and no signed-in case.
		r.TTLS, r.SignedIn = 0, false
	default:
		return deliveryErr(field("action"), msgRuleAction)
	}
	return nil
}

// cachePrefixShape says whether p is a path of at most CachePrefixMaxBytes printable ASCII bytes
// with no space, ? or #.
func cachePrefixShape(p string) bool {
	if len(p) > CachePrefixMaxBytes {
		return false
	}
	for i := 0; i < len(p); i++ {
		if c := p[i]; c <= ' ' || c > '~' || c == '?' || c == '#' {
			return false
		}
	}
	return true
}

// validCookieName says whether name is an RFC 6265 token of 1 to CacheCookieNameMax bytes: printable
// ASCII without a separator, so no space, comma, semicolon or =.
func validCookieName(name string) bool {
	if len(name) == 0 || len(name) > CacheCookieNameMax {
		return false
	}
	for i := 0; i < len(name); i++ {
		c := name[i]
		if c <= ' ' || c >= 0x7f || strings.IndexByte(`()<>@,;:\"/[]?={}`, c) >= 0 {
			return false
		}
	}
	return true
}

// CheckStripPathPrefix returns why p is not a valid proxy_config.strip_path_prefix, or "". "" is no
// prefix. A prefix is "/" and segments: no empty, . or .. segment (so no trailing slash), printable
// ASCII without space, ?, #, % or backslash, at most StripPathPrefixMaxBytes bytes.
func CheckStripPathPrefix(p string) string {
	if p == "" {
		return ""
	}
	if p[0] != '/' || len(p) > StripPathPrefixMaxBytes {
		return msgStripPathPrefix
	}
	for i := 0; i < len(p); i++ {
		if c := p[i]; c <= ' ' || c > '~' || strings.IndexByte(`?#%\`, c) >= 0 {
			return msgStripPathPrefix
		}
	}
	for _, seg := range strings.Split(p[1:], "/") {
		if seg == "" || seg == "." || seg == ".." {
			return msgStripPathPrefix
		}
	}
	return ""
}

// CheckCanonicalHost returns why host is not a valid main host name among hosts, or "". "" is no
// main host. host and hosts are already normalized.
func CheckCanonicalHost(host string, hosts []string) string {
	if host == "" {
		return ""
	}
	for _, h := range hosts {
		if h == host {
			return ""
		}
	}
	return msgCanonicalHost
}
