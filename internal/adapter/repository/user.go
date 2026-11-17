package repository

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/wafio/wafio-cp-backend/internal/otp"
)

type User struct {
	ID           string
	Email        string
	PasswordHash string
	Name         string
	Role         string
	TOTPSecret   string
	TOTPEnabled  bool
	// TokenVersion is the minimum `tv` claim a JWT for this user must carry. Loaded by GetByID
	// and GetByEmail; zero elsewhere.
	TokenVersion int
	CreatedAt    time.Time
	UpdatedAt    time.Time
}

type UserRepo struct {
	pool *pgxpool.Pool
	// TOTPCrypto encrypts/decrypts the totp_secret column at rest. Nil means
	// no key configured (plaintext fallback). Set from config at startup.
	TOTPCrypto *otp.Encryptor
}

// decryptTOTP decrypts an in-place loaded user's TOTP secret. On failure it
// blanks the secret (fail-closed) so a corrupt/unkeyed ciphertext can never be
// fed to the validator as if it were the real secret.
func (u *UserRepo) decryptTOTP(user *User) {
	if user == nil || user.TOTPSecret == "" {
		return
	}
	pt, err := u.TOTPCrypto.Decrypt(user.TOTPSecret)
	if err != nil {
		user.TOTPSecret = ""
		return
	}
	user.TOTPSecret = pt
}

func (u *UserRepo) Ping(ctx context.Context) error {
	return u.pool.QueryRow(ctx, `SELECT 1`).Scan(new(int))
}

func (u *UserRepo) HasAnyAdmin(ctx context.Context) (bool, error) {
	var count int
	err := u.pool.QueryRow(ctx, `SELECT COUNT(*) FROM users WHERE role = 'admin'`).Scan(&count)
	return count > 0, err
}

func (u *UserRepo) Create(ctx context.Context, email, passwordHash, name string) (*User, error) {
	row := u.pool.QueryRow(ctx,
		`INSERT INTO users (email, password_hash, name) VALUES ($1, $2, $3)
		 RETURNING id, email, password_hash, COALESCE(name, ''), role, COALESCE(totp_secret, ''), COALESCE(totp_enabled, false), created_at, updated_at`,
		email, passwordHash, name,
	)
	var user User
	err := row.Scan(&user.ID, &user.Email, &user.PasswordHash, &user.Name, &user.Role, &user.TOTPSecret, &user.TOTPEnabled, &user.CreatedAt, &user.UpdatedAt)
	if err != nil {
		return nil, err
	}
	u.decryptTOTP(&user)
	return &user, nil
}

func (u *UserRepo) GetByEmail(ctx context.Context, email string) (*User, error) {
	row := u.pool.QueryRow(ctx,
		`SELECT id, email, password_hash, COALESCE(name, ''), role, COALESCE(totp_secret, ''), COALESCE(totp_enabled, false), token_version, created_at, updated_at FROM users WHERE email = $1`,
		email,
	)
	var user User
	err := row.Scan(&user.ID, &user.Email, &user.PasswordHash, &user.Name, &user.Role, &user.TOTPSecret, &user.TOTPEnabled, &user.TokenVersion, &user.CreatedAt, &user.UpdatedAt)
	if err != nil {
		return nil, err
	}
	u.decryptTOTP(&user)
	return &user, nil
}

func (u *UserRepo) GetByID(ctx context.Context, id string) (*User, error) {
	row := u.pool.QueryRow(ctx,
		`SELECT id, email, password_hash, COALESCE(name, ''), role, COALESCE(totp_secret, ''), COALESCE(totp_enabled, false), token_version, created_at, updated_at FROM users WHERE id = $1`,
		id,
	)
	var user User
	err := row.Scan(&user.ID, &user.Email, &user.PasswordHash, &user.Name, &user.Role, &user.TOTPSecret, &user.TOTPEnabled, &user.TokenVersion, &user.CreatedAt, &user.UpdatedAt)
	if err != nil {
		return nil, err
	}
	u.decryptTOTP(&user)
	return &user, nil
}

func (u *UserRepo) UpdateName(ctx context.Context, id, name string) error {
	_, err := u.pool.Exec(ctx,
		`UPDATE users SET name = $1, updated_at = NOW() WHERE id = $2`,
		name, id,
	)
	return err
}

// UpdatePassword sets a new password hash and revokes every token issued so
// far: token_version is bumped in the same statement, and the new
// version is returned so the caller can issue a replacement token. The same
// statement deletes the user's outstanding password reset links:
// a link asked for before the change must not set the password
// afterwards. pgx.ErrNoRows means the user does not exist.
func (u *UserRepo) UpdatePassword(ctx context.Context, id, passwordHash string) (int, error) {
	var version int
	err := u.pool.QueryRow(ctx,
		`WITH links AS (DELETE FROM password_reset_tokens WHERE user_id = $2::uuid)
		 UPDATE users SET password_hash = $1, token_version = token_version + 1, updated_at = NOW()
		 WHERE id = $2 RETURNING token_version`,
		passwordHash, id,
	).Scan(&version)
	return version, err
}

func (u *UserRepo) List(ctx context.Context, limit, offset int) ([]User, int, error) {
	var total int
	if err := u.pool.QueryRow(ctx, `SELECT COUNT(*) FROM users`).Scan(&total); err != nil {
		return nil, 0, err
	}
	rows, err := u.pool.Query(ctx,
		`SELECT id, email, password_hash, COALESCE(name, ''), role, COALESCE(totp_secret, ''), COALESCE(totp_enabled, false), created_at, updated_at FROM users ORDER BY created_at ASC,id LIMIT $1 OFFSET $2`,
		limit, offset,
	)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	list := []User{}
	for rows.Next() {
		var user User
		if err := rows.Scan(&user.ID, &user.Email, &user.PasswordHash, &user.Name, &user.Role, &user.TOTPSecret, &user.TOTPEnabled, &user.CreatedAt, &user.UpdatedAt); err != nil {
			return nil, 0, err
		}
		list = append(list, user)
	}
	return list, total, rows.Err()
}

func (u *UserRepo) CreateWithRole(ctx context.Context, email, passwordHash, name, role string) (*User, error) {
	user, err := insertUser(ctx, u.pool, email, passwordHash, name, role)
	if err != nil {
		return nil, err
	}
	u.decryptTOTP(user)
	return user, nil
}

// insertUser creates a user through q (the pool or a transaction). A new
// user has no TOTP secret, so there is nothing to decrypt.
func insertUser(ctx context.Context, q dbtx, email, passwordHash, name, role string) (*User, error) {
	row := q.QueryRow(ctx,
		`INSERT INTO users (email, password_hash, name, role) VALUES ($1, $2, $3, $4)
		 RETURNING id, email, password_hash, COALESCE(name, ''), role, COALESCE(totp_secret, ''), COALESCE(totp_enabled, false), created_at, updated_at`,
		email, passwordHash, name, role,
	)
	var user User
	err := row.Scan(&user.ID, &user.Email, &user.PasswordHash, &user.Name, &user.Role, &user.TOTPSecret, &user.TOTPEnabled, &user.CreatedAt, &user.UpdatedAt)
	if err != nil {
		return nil, err
	}
	return &user, nil
}

// UpdateRole changes the system role. When the role actually changes,
// token_version is bumped in the same statement so tokens issued under the
// old role stop working; changed reports whether that happened. Setting
// the role a user already has is a no-op and logs nobody out.
func (u *UserRepo) UpdateRole(ctx context.Context, id, role string) (changed bool, err error) {
	tag, err := u.pool.Exec(ctx,
		`UPDATE users SET role = $1, token_version = token_version + 1, updated_at = NOW()
		 WHERE id = $2 AND role <> $1`,
		role, id,
	)
	if err != nil {
		return false, err
	}
	return tag.RowsAffected() > 0, nil
}

// UserAuthState is what RequireJWT re-reads for every token: the
// current system role and the minimum token version. Exists is false when the
// user was deleted (or the id is not a user id at all).
type UserAuthState struct {
	Exists       bool
	Role         string
	TokenVersion int
}

// AuthState loads the user's current role and token version. A missing user
// is not an error: it returns Exists=false.
func (u *UserRepo) AuthState(ctx context.Context, id string) (UserAuthState, error) {
	// users.id is a UUID; a non-UUID id can never name a user, and passing it
	// to Postgres would surface as a query error (22P02) instead of "absent".
	if _, err := uuid.Parse(id); err != nil {
		return UserAuthState{}, nil
	}
	st := UserAuthState{Exists: true}
	err := u.pool.QueryRow(ctx,
		`SELECT role, token_version FROM users WHERE id = $1`, id,
	).Scan(&st.Role, &st.TokenVersion)
	if errors.Is(err, pgx.ErrNoRows) {
		return UserAuthState{}, nil
	}
	if err != nil {
		return UserAuthState{}, err
	}
	return st, nil
}

// BumpTokenVersion revokes every token issued to the user so far ("log out
// everywhere") and returns the new version. pgx.ErrNoRows means the user
// does not exist.
func (u *UserRepo) BumpTokenVersion(ctx context.Context, id string) (int, error) {
	var version int
	err := u.pool.QueryRow(ctx,
		`UPDATE users SET token_version = token_version + 1, updated_at = NOW()
		 WHERE id = $1 RETURNING token_version`, id,
	).Scan(&version)
	return version, err
}

// AcceptTOTPStep records step as the user's last accepted TOTP time step and
// reports whether it was fresh. A step that is not greater than the stored
// one is a replay of a code already used (or of an older one) and is refused
// (RFC 6238 §5.2). The compare-and-set is one statement, so two
// concurrent requests with the same code cannot both succeed.
func (u *UserRepo) AcceptTOTPStep(ctx context.Context, id string, step int64) (bool, error) {
	tag, err := u.pool.Exec(ctx,
		`UPDATE users SET totp_last_step = $2 WHERE id = $1 AND totp_last_step < $2`,
		id, step,
	)
	if err != nil {
		return false, err
	}
	return tag.RowsAffected() > 0, nil
}

func (u *UserRepo) Delete(ctx context.Context, id string) error {
	_, err := u.pool.Exec(ctx, `DELETE FROM users WHERE id = $1`, id)
	return err
}

// SearchByEmail was removed with GET /api/users/search: it let
// any authenticated user enumerate every account across tenants.

// TOTP enrolment errors. The handler maps them to client errors.
var (
	// ErrTOTPAlreadyEnabled: 2FA is on; a new secret is never issued or
	// activated over it.
	ErrTOTPAlreadyEnabled = errors.New("totp already enabled")
	// ErrTOTPNoPendingSecret: no server-issued secret awaits confirmation
	// (setup was not called, or its ciphertext cannot be decrypted).
	ErrTOTPNoPendingSecret = errors.New("no pending totp secret")
	// ErrTOTPInvalidCode: the code does not match the pending secret.
	ErrTOTPInvalidCode = errors.New("invalid totp code")
)

// SetPendingTOTP stores a server-generated secret awaiting confirmation,
// encrypted like totp_secret. It replaces any earlier pending secret and
// refuses (ErrTOTPAlreadyEnabled) while 2FA is on.
func (u *UserRepo) SetPendingTOTP(ctx context.Context, id, secret string) error {
	stored, err := u.TOTPCrypto.Encrypt(secret)
	if err != nil {
		return err
	}
	tag, err := u.pool.Exec(ctx,
		`UPDATE users SET totp_pending_secret = $1, updated_at = NOW()
		 WHERE id = $2 AND NOT COALESCE(totp_enabled, false)`,
		stored, id,
	)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrTOTPAlreadyEnabled
	}
	return nil
}

// ConfirmPendingTOTP enables 2FA with the pending server-issued secret when
// verify accepts it. verify returns the TOTP time step the code matched,
// which becomes totp_last_step, so the confirmation code cannot be replayed
// at the login 2FA step. Enabling also bumps token_version and
// returns the new version: sessions opened with the password alone end once
// the account requires a second factor. The row is locked for the check and the
// switch, so a concurrent setup cannot swap the secret between verification
// and activation, and two confirmations cannot both succeed.
func (u *UserRepo) ConfirmPendingTOTP(ctx context.Context, id string, verify func(secret string) (step int64, ok bool)) (int, error) {
	tx, err := u.pool.Begin(ctx)
	if err != nil {
		return 0, err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	var enabled bool
	var pending string
	if err := tx.QueryRow(ctx,
		`SELECT COALESCE(totp_enabled, false), totp_pending_secret FROM users WHERE id = $1 FOR UPDATE`,
		id,
	).Scan(&enabled, &pending); err != nil {
		return 0, err
	}
	if enabled {
		return 0, ErrTOTPAlreadyEnabled
	}
	if pending == "" {
		return 0, ErrTOTPNoPendingSecret
	}
	secret, err := u.TOTPCrypto.Decrypt(pending)
	if err != nil || secret == "" {
		return 0, ErrTOTPNoPendingSecret
	}
	step, ok := verify(secret)
	if !ok {
		return 0, ErrTOTPInvalidCode
	}
	var version int
	if err := tx.QueryRow(ctx,
		`UPDATE users SET totp_secret = totp_pending_secret, totp_pending_secret = '',
		 totp_enabled = true, totp_last_step = $2, token_version = token_version + 1, updated_at = NOW()
		 WHERE id = $1 RETURNING token_version`,
		id, step,
	).Scan(&version); err != nil {
		return 0, err
	}
	return version, tx.Commit(ctx)
}

// DisableTOTP turns 2FA off, clears both the active and any pending secret,
// and revokes every token issued so far: a session that could switch
// the second factor off must not outlive it. It returns the new token
// version; pgx.ErrNoRows means the user does not exist.
func (u *UserRepo) DisableTOTP(ctx context.Context, id string) (int, error) {
	var version int
	err := u.pool.QueryRow(ctx,
		`UPDATE users SET totp_secret = '', totp_pending_secret = '', totp_enabled = false,
		 token_version = token_version + 1, updated_at = NOW() WHERE id = $1 RETURNING token_version`,
		id,
	).Scan(&version)
	return version, err
}
