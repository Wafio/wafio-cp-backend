package tracefilter

import "strings"

// IsPublicIdentityRead reports a read of a public identity file. Public
// identity lookup is normal for any process, not just named daemons.
// O_CREAT/O_TRUNC can modify files even when O_ACCMODE is O_RDONLY.
func IsPublicIdentityRead(t *TraceEventPayload) bool {
	if t.EventName != "openat" || t.Action != 0 || t.Flags&(3|64|512) != 0 {
		return false
	}
	if strings.HasSuffix(t.Filename, "/.ssh/authorized_keys") || isPublicSSHKey(t.Filename) {
		return true
	}
	switch t.Filename {
	case "/etc/passwd", "/etc/group", "/etc/nsswitch.conf", "/etc/login.defs":
		return true
	default:
		return false
	}
}

var publicSSHKeySuffixes = []string{
	"/.ssh/id_rsa.pub", "/.ssh/id_ecdsa.pub", "/.ssh/id_ed25519.pub",
	"/.ssh/id_dsa.pub", "/.ssh/id_ecdsa_sk.pub", "/.ssh/id_ed25519_sk.pub",
}

func isPublicSSHKey(filename string) bool {
	for _, suffix := range publicSSHKeySuffixes {
		if strings.HasSuffix(filename, suffix) {
			return true
		}
	}
	return false
}
