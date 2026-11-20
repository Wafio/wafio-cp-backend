package repository

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"

	"github.com/wafio/wafio-cp-backend/internal/domain"
	"github.com/wafio/wafio-cp-backend/internal/otp"
)

// The kinds of value that totp.enc_key protects, in the order Rekey reports them.
const (
	RekeyKindTOTPSecret     = "totp_secret"
	RekeyKindTOTPPending    = "totp_pending_secret"
	RekeyKindSMTPPassword   = "smtp_password"
	RekeyKindMalwareKey     = "malware_key"
	RekeyKindCertificateKey = "certificate_key"
)

// The two secrets that sit inside a system_settings row: the row and the JSON field with the
// ciphertext. application.MailSettings and application.MalwareCredentials write them; a test
// saves both through those writers and reads them back after a rekey, so a rename on either side
// fails there.
const (
	smtpSettingsKey    = "smtp_settings"
	smtpPasswordField  = "password_ciphertext"
	malwareSettingsKey = "malware_bazaar_credentials"
	malwareKeyField    = "ciphertext"
)

// rekeyNamedRows bounds how many unreadable rows a report names.
const rekeyNamedRows = 20

// ErrRekeyUnreadable is returned when a stored value opens with neither key. Nothing was written.
var ErrRekeyUnreadable = errors.New("some stored values open with neither the old nor the new key")

// RekeyCount is what Rekey found for one kind of value. A value is never part of it.
type RekeyCount struct {
	Kind string
	// ToRewrite values open with the old key. AlreadyNew values open with the new key, which is how
	// a rerun after an interrupted rotation looks. NotSealed values are plain text from before the
	// key was set (a TOTP secret, or a setting that holds none) and stay as they are. Unreadable
	// values open with neither key.
	ToRewrite, AlreadyNew, NotSealed, Unreadable int
	// UnreadableRows names the rows of the unreadable values by id or setting name, at most 20.
	UnreadableRows []string
}

// RekeyReport is the result of Rekey.
type RekeyReport struct {
	Counts []RekeyCount
	// Applied is true when the values were rewritten and the transaction committed.
	Applied bool
}

func (r RekeyReport) sum(pick func(RekeyCount) int) int {
	n := 0
	for _, c := range r.Counts {
		n += pick(c)
	}
	return n
}

// ToRewrite is the number of values that open with the old key.
func (r RekeyReport) ToRewrite() int { return r.sum(func(c RekeyCount) int { return c.ToRewrite }) }

// Unreadable is the number of values that open with neither key.
func (r RekeyReport) Unreadable() int { return r.sum(func(c RekeyCount) int { return c.Unreadable }) }

// rekeyItem is one stored value with what it takes to open it, seal it again and write it back.
type rekeyItem struct {
	// label names the row in a report: an id or a setting name, never the value.
	label  string
	stored string
	// bound is set for a value sealed with SealBound, whose seal also depends on aad.
	bound bool
	aad   string
	write func(ctx context.Context, tx pgx.Tx, sealed string) error
}

func (it rekeyItem) isSealed() bool {
	if it.bound {
		return otp.IsBound(it.stored)
	}
	return otp.IsEncrypted(it.stored)
}

func (it rekeyItem) open(e *otp.Encryptor, stored string) ([]byte, error) {
	if it.bound {
		return e.OpenBound(stored, it.aad)
	}
	s, err := e.Decrypt(stored)
	return []byte(s), err
}

func (it rekeyItem) seal(e *otp.Encryptor, plain []byte) (string, error) {
	if it.bound {
		return e.SealBound(plain, it.aad)
	}
	return e.Encrypt(string(plain))
}

// reseal seals plain with e and checks that the result opens to the same bytes, so a value is never
// written that could not be read back.
func (it rekeyItem) reseal(e *otp.Encryptor, plain []byte) (string, error) {
	sealed, err := it.seal(e, plain)
	if err != nil {
		return "", err
	}
	back, err := it.open(e, sealed)
	defer clear(back)
	if err != nil || !bytes.Equal(back, plain) {
		return "", errors.New("a value did not open again after it was sealed")
	}
	return sealed, nil
}

type rekeyKind struct {
	name string
	load func(ctx context.Context, tx pgx.Tx, lock bool) ([]rekeyItem, error)
}

func rekeyKinds() []rekeyKind {
	return []rekeyKind{
		{RekeyKindTOTPSecret, loadUserSecrets(false)},
		{RekeyKindTOTPPending, loadUserSecrets(true)},
		{RekeyKindSMTPPassword, loadSettingSecret(smtpSettingsKey, smtpPasswordField)},
		{RekeyKindMalwareKey, loadSettingSecret(malwareSettingsKey, malwareKeyField)},
		{RekeyKindCertificateKey, loadCertificateKeys},
	}
}

// Rekey rewrites every value that is sealed with totp.enc_key from oldKey to newKey: the TOTP
// secrets and pending secrets of the users, the SMTP password and the malware database key of the
// settings, and the private keys of uploaded certificates. A value that already opens with newKey
// counts as done, so a run after an interrupted rotation is safe.
//
// Without apply it reports and writes nothing. With apply it locks every row it reads and writes in
// one transaction, and writes nothing at all when a value opens with neither key
// (ErrRekeyUnreadable, with the report). Stop the control plane first: it keeps no lock on the rows,
// and a secret saved between the read and the commit would be missed.
func (r *Repository) Rekey(ctx context.Context, oldKey, newKey *otp.Encryptor, apply bool) (RekeyReport, error) {
	if oldKey == nil || newKey == nil {
		return RekeyReport{}, errors.New("rekey needs the old and the new key")
	}
	opts := pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly}
	if apply {
		opts = pgx.TxOptions{}
	}
	tx, err := r.DB.BeginTx(ctx, opts)
	if err != nil {
		return RekeyReport{}, err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	type rewrite struct {
		item   rekeyItem
		sealed string
	}
	var rewrites []rewrite
	var report RekeyReport
	for _, kind := range rekeyKinds() {
		items, err := kind.load(ctx, tx, apply)
		if err != nil {
			return report, fmt.Errorf("read %s: %w", kind.name, err)
		}
		count := RekeyCount{Kind: kind.name}
		for _, it := range items {
			if !it.isSealed() {
				// A certificate key is never stored in any other form; every other value may
				// predate the key.
				if it.bound {
					count.unreadable(it.label)
				} else {
					count.NotSealed++
				}
				continue
			}
			if plain, err := it.open(oldKey, it.stored); err == nil {
				count.ToRewrite++
				if apply {
					sealed, err := it.reseal(newKey, plain)
					if err != nil {
						clear(plain)
						return report, fmt.Errorf("seal %s %s: %w", kind.name, it.label, err)
					}
					rewrites = append(rewrites, rewrite{it, sealed})
				}
				clear(plain)
			} else if plain, err := it.open(newKey, it.stored); err == nil {
				clear(plain)
				count.AlreadyNew++
			} else {
				count.unreadable(it.label)
			}
		}
		report.Counts = append(report.Counts, count)
	}
	if report.Unreadable() > 0 {
		return report, ErrRekeyUnreadable
	}
	if !apply {
		return report, nil
	}
	for _, w := range rewrites {
		if err := w.item.write(ctx, tx, w.sealed); err != nil {
			return report, fmt.Errorf("write %s: %w", w.item.label, err)
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return report, fmt.Errorf("commit: %w", err)
	}
	report.Applied = true
	return report, nil
}

func (c *RekeyCount) unreadable(label string) {
	c.Unreadable++
	if len(c.UnreadableRows) < rekeyNamedRows {
		c.UnreadableRows = append(c.UnreadableRows, label)
	}
}

func loadUserSecrets(pending bool) func(context.Context, pgx.Tx, bool) ([]rekeyItem, error) {
	sel := `SELECT id::text, totp_secret FROM users WHERE COALESCE(totp_secret, '') <> '' ORDER BY id`
	upd := `UPDATE users SET totp_secret = $2 WHERE id = $1`
	if pending {
		sel = `SELECT id::text, totp_pending_secret FROM users WHERE COALESCE(totp_pending_secret, '') <> '' ORDER BY id`
		upd = `UPDATE users SET totp_pending_secret = $2 WHERE id = $1`
	}
	return func(ctx context.Context, tx pgx.Tx, lock bool) ([]rekeyItem, error) {
		q := sel
		if lock {
			q += ` FOR UPDATE`
		}
		rows, err := tx.Query(ctx, q)
		if err != nil {
			return nil, err
		}
		defer rows.Close()
		var items []rekeyItem
		for rows.Next() {
			var id, stored string
			if err := rows.Scan(&id, &stored); err != nil {
				return nil, err
			}
			items = append(items, rekeyItem{label: "user " + id, stored: stored,
				write: func(ctx context.Context, tx pgx.Tx, sealed string) error {
					_, err := tx.Exec(ctx, upd, id, sealed)
					return err
				}})
		}
		return items, rows.Err()
	}
}

// loadSettingSecret finds the ciphertext in one field of a system_settings row. A row that is
// missing, is no JSON object or has no such field holds no secret.
func loadSettingSecret(key, field string) func(context.Context, pgx.Tx, bool) ([]rekeyItem, error) {
	return func(ctx context.Context, tx pgx.Tx, lock bool) ([]rekeyItem, error) {
		q := `SELECT value FROM system_settings WHERE key = $1`
		if lock {
			q += ` FOR UPDATE`
		}
		var raw []byte
		if err := tx.QueryRow(ctx, q, key).Scan(&raw); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return nil, nil
			}
			return nil, err
		}
		var fields map[string]json.RawMessage
		var stored string
		if json.Unmarshal(raw, &fields) != nil || json.Unmarshal(fields[field], &stored) != nil || stored == "" {
			return nil, nil
		}
		return []rekeyItem{{label: "setting " + key, stored: stored,
			write: func(ctx context.Context, tx pgx.Tx, sealed string) error {
				// The other fields of the row stay as they are.
				quoted, err := json.Marshal(sealed)
				if err != nil {
					return err
				}
				fields[field] = quoted
				out, err := json.Marshal(fields)
				if err != nil {
					return err
				}
				_, err = tx.Exec(ctx, `UPDATE system_settings SET value = $2, updated_at = NOW() WHERE key = $1`, key, out)
				return err
			}}}, nil
	}
}

func loadCertificateKeys(ctx context.Context, tx pgx.Tx, lock bool) ([]rekeyItem, error) {
	keys, err := sealedKeys(ctx, tx, lock)
	if err != nil {
		return nil, err
	}
	items := make([]rekeyItem, len(keys))
	for i, k := range keys {
		items[i] = rekeyItem{
			label: "certificate " + k.CertificateID, stored: k.Sealed, bound: true,
			aad: domain.CertificateKeyAAD(k.ProjectID, k.CertificateID),
			write: func(ctx context.Context, tx pgx.Tx, sealed string) error {
				return replaceSealedKey(ctx, tx, k.ProjectID, k.CertificateID, sealed)
			},
		}
	}
	return items, nil
}
