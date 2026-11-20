package domain

import "time"

// ExpiryCandidate is the certificate of an application in gateway mode that the expiry warnings
// look at: the uploaded certificate for an uploaded source, the chain the agent reported for acme.
type ExpiryCandidate struct {
	ProjectID, ProjectName, AppID, AppName string
	Hosts                                  []string
	Source                                 string
	// CertificateID is set for an uploaded source only.
	CertificateID string
	LeafSHA256    string
	NotAfter      time.Time
	// NotifiedDays is the last threshold that was mailed for this certificate, nil when none.
	NotifiedDays *int
}
