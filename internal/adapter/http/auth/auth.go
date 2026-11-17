package auth

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

var ErrTokenExpired = errors.New("token expired")

const UserIDKey = "user_id"
const UserEmailKey = "user_email"
const UserRoleKey = "user_role"

// TokenVersionKey holds the tv claim of the request's JWT (int).
const TokenVersionKey = "token_version"

type Claims struct {
	UserID string `json:"user_id"`
	Email  string `json:"email"`
	// Role is the system role when the token was issued. It is informational
	// only: RequireJWT puts the role from the users row in Locals.
	Role string `json:"role"`
	// TokenVersion ("tv") is users.token_version when the token was issued.
	// RequireJWT rejects a token whose tv is lower than the row's current
	// value. A token issued before the claim existed decodes as 0.
	TokenVersion int  `json:"tv"`
	PreAuth      bool `json:"pre_auth,omitempty"`
	jwt.RegisteredClaims
}

// PreAuthTTL is how long a pre-auth token can be exchanged at
// POST /api/login/2fa.
const PreAuthTTL = 10 * time.Minute

// SignJWT signs a session token with token version 0. Handlers issuing a
// token for a stored user use SignJWTVersion with the user's TokenVersion;
// this form is for callers that know the version is 0 (tests, fixtures).
func SignJWT(userID, email, role, secret string, expireHours int) (string, error) {
	return SignJWTVersion(userID, email, role, 0, secret, expireHours)
}

// SignJWTVersion signs a session token carrying tokenVersion as the tv claim.
func SignJWTVersion(userID, email, role string, tokenVersion int, secret string, expireHours int) (string, error) {
	if expireHours <= 0 {
		expireHours = 72
	}
	now := time.Now()
	claims := Claims{
		UserID:       userID,
		Email:        email,
		Role:         role,
		TokenVersion: tokenVersion,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(now.Add(time.Duration(expireHours) * time.Hour)),
			IssuedAt:  jwt.NewNumericDate(now),
		},
	}
	t := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return t.SignedString([]byte(secret))
}

// SignPreAuthJWT signs the token Login returns when the account has 2FA. It
// proves the password only and is valid for PreAuthTTL. It carries a random
// jti so POST /api/login/2fa can exchange it once, and the user's
// token version so a password reset or logout-all in between voids it.
func SignPreAuthJWT(userID, email, role string, tokenVersion int, secret string) (string, error) {
	jti := make([]byte, 16)
	if _, err := rand.Read(jti); err != nil {
		return "", err
	}
	now := time.Now()
	claims := Claims{
		UserID:       userID,
		Email:        email,
		Role:         role,
		TokenVersion: tokenVersion,
		PreAuth:      true,
		RegisteredClaims: jwt.RegisteredClaims{
			ID:        hex.EncodeToString(jti),
			ExpiresAt: jwt.NewNumericDate(now.Add(PreAuthTTL)),
			IssuedAt:  jwt.NewNumericDate(now),
		},
	}
	t := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return t.SignedString([]byte(secret))
}

func ParseJWT(tokenString, secret string) (*Claims, error) {
	tokenString = strings.TrimSpace(tokenString)
	// Client may send token wrapped in quotes
	if strings.HasPrefix(tokenString, `"`) && strings.HasSuffix(tokenString, `"`) {
		tokenString = strings.Trim(tokenString, `"`)
	}
	t, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(t *jwt.Token) (interface{}, error) {
		if t.Method != jwt.SigningMethodHS256 {
			return nil, jwt.ErrTokenSignatureInvalid
		}
		return []byte(secret), nil
	})
	if err != nil {
		if errors.Is(err, jwt.ErrTokenExpired) {
			return nil, ErrTokenExpired
		}
		return nil, err
	}
	if c, ok := t.Claims.(*Claims); ok && t.Valid {
		return c, nil
	}
	return nil, jwt.ErrTokenInvalidClaims
}
