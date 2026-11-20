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
// certificate, so it has three levels. The agent renews an ACME certificate once a third of its
// lifetime is left, so a warning there means that the renewal is late, and only the last two apply.
var (
	UploadedExpiryDays = []int{30, 14, 3}
	ACMEExpiryDays     = []int{14, 3}
)

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
// An ACME level is skipped when it is a third of the lifetime or more (notBefore to notAfter): the
// agent starts to renew at a third, so a certificate that is merely renewing in the ordinary way
// would be reported as late. A certificate of a few days therefore has no level at all. An unknown
// start (the zero time) skips nothing.
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
		if source == TLSSourceACME && !notBefore.IsZero() && lifetime > 0 && time.Duration(d)*24*time.Hour*3 >= lifetime {
			continue
		}
		if left <= d {
			days, due = d, true
		}
	}
	return days, due
}
