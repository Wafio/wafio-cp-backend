package domain

import (
	"math"
	"time"
)

// ExpiryCandidate is the certificate of an application in gateway mode that the expiry warnings
// look at: the uploaded certificate for an uploaded source, the chain the agent reported for acme.
type ExpiryCandidate struct {
	ProjectID, ProjectName, AppID, AppName string
	Hosts                                  []string
	Source                                 string
	// CertificateID is set for an uploaded source only.
	CertificateID string
	LeafSHA256    string
	// NotBefore is the start of the validity, the zero time when it is not known.
	NotBefore time.Time
	NotAfter  time.Time
	// NotifiedDays is the last threshold that was mailed for this certificate, nil when none.
	NotifiedDays *int
}

// Days left at which a certificate is warned about, largest first. The owner renews an uploaded
// certificate, so it has four levels. The agent renews an ACME certificate once a third of its
// lifetime is left, so a warning there means that the renewal is late, and only the last three apply.
// The last level, FinalExpiryDays, is the same for both and is never skipped.
var (
	UploadedExpiryDays = []int{30, 14, 3, FinalExpiryDays}
	ACMEExpiryDays     = []int{14, 3, FinalExpiryDays}
)

// FinalExpiryDays is the last warning level of every certificate, whatever its lifetime. It is the
// one mail that a short-lived ACME certificate whose renewal broke gets before it expires.
const FinalExpiryDays = 1

// DaysLeft is the whole days until notAfter, rounded down: 0 for less than a day, negative once the
// certificate has expired. The dashboard shows it and the warnings are measured in it, so a
// certificate with 12 days left is at 12 everywhere.
func DaysLeft(notAfter, now time.Time) int {
	return int(math.Floor(notAfter.Sub(now).Hours() / 24))
}

// ExpiryLevel is the tightest warning level the certificate has reached: the smallest level that is
// still at least the days left. due is false while it is above every level. A certificate that has
// expired is at the last level, and when the passes were far apart a certificate is at its current
// level only, not at the ones it passed.
//
// An ACME level is skipped when it is due before the agent has had its time to renew. The agent
// starts at a third of the lifetime (notBefore to notAfter) left, and a level of d days is due once
// fewer than d+1 days are left, so it is skipped when d+1 days are a third of the lifetime or more:
// a certificate that is merely renewing in the ordinary way would be reported as late. The final
// level is never skipped, so a certificate of a few days has that one only. An unknown start (the
// zero time) skips nothing.
func ExpiryLevel(source string, notBefore, notAfter, now time.Time) (days int, due bool) {
	var levels []int
	switch source {
	case TLSSourceUploaded:
		levels = UploadedExpiryDays
	case TLSSourceACME:
		levels = ACMEExpiryDays
	}
	left := DaysLeft(notAfter, now)
	lifetime := notAfter.Sub(notBefore)
	for _, d := range levels {
		if source == TLSSourceACME && d != FinalExpiryDays && !notBefore.IsZero() && lifetime > 0 && time.Duration(d+1)*24*time.Hour*3 >= lifetime {
			continue
		}
		if left <= d {
			days, due = d, true
		}
	}
	return days, due
}
