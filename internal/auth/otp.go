package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"time"

	"github.com/redis/go-redis/v9"
)

var (
	ErrLoginSessionNotFound = errors.New("login session not found or expired")
	ErrInvalidCode          = errors.New("invalid code")
	ErrTooManyAttempts      = errors.New("too many attempts, request a new code")
)

// loginSession is what we keep in Redis between "password verified" and
// "OTP verified". The code is stored hashed, never in plain text.
type loginSession struct {
	UserID      string `json:"user_id"`
	APIClientID string `json:"api_client_id"`
	Email       string `json:"email"`
	CodeHash    string `json:"code_hash"`
	Attempts    int    `json:"attempts"`
}

// OTPStore manages short-lived login sessions and their one-time codes in
// Redis. This is intentionally separate from the Postgres user store: OTPs
// are high-churn, short-lived data that don't belong in the durable DB.
type OTPStore struct {
	rdb      *redis.Client
	ttl      time.Duration
	maxTries int
	codeLen  int
}

func NewOTPStore(rdb *redis.Client, ttl time.Duration, maxTries, codeLen int) *OTPStore {
	return &OTPStore{rdb: rdb, ttl: ttl, maxTries: maxTries, codeLen: codeLen}
}

// StartSession generates a new numeric code, stores its hash under a fresh
// random login token, and returns both the login token (to hand back to the
// client) and the plain code (to email to the user — never returned to the
// caller of this API).
func (s *OTPStore) StartSession(ctx context.Context, userID, apiClientID, email string) (loginToken, code string, err error) {
	code, err = generateNumericCode(s.codeLen)
	if err != nil {
		return "", "", fmt.Errorf("generating otp code: %w", err)
	}

	loginToken, err = generateToken(32)
	if err != nil {
		return "", "", fmt.Errorf("generating login token: %w", err)
	}

	sess := loginSession{
		UserID:      userID,
		APIClientID: apiClientID,
		Email:       email,
		CodeHash:    hashCode(code),
		Attempts:    0,
	}
	data, err := json.Marshal(sess)
	if err != nil {
		return "", "", fmt.Errorf("marshaling login session: %w", err)
	}

	if err := s.rdb.Set(ctx, sessionKey(loginToken), data, s.ttl).Err(); err != nil {
		return "", "", fmt.Errorf("storing login session: %w", err)
	}

	return loginToken, code, nil
}

// verifyCodeScript does the whole read-compare-increment-write in one
// atomic Redis operation. Doing this as separate GET/SET calls (as an
// earlier version of this code did) is a lost-update race: concurrent wrong
// guesses against the same login_token can all read the same stale Attempts
// value before any of them writes back the increment, letting an attacker
// who already knows the password (and so already has a login_token) exceed
// maxTries by firing guesses in parallel instead of sequentially.
var verifyCodeScript = redis.NewScript(`
local raw = redis.call('GET', KEYS[1])
if not raw then
	return {'not_found'}
end
local sess = cjson.decode(raw)
if sess.code_hash == ARGV[1] then
	redis.call('DEL', KEYS[1])
	return {'ok', sess.user_id, sess.api_client_id, sess.email}
end
sess.attempts = sess.attempts + 1
if sess.attempts >= tonumber(ARGV[2]) then
	redis.call('DEL', KEYS[1])
	return {'too_many'}
end
local ttl = redis.call('PTTL', KEYS[1])
if ttl <= 0 then
	ttl = tonumber(ARGV[3])
end
redis.call('SET', KEYS[1], cjson.encode(sess), 'PX', ttl)
return {'invalid'}
`)

// VerifyCode checks the provided code against the stored session. On
// success the session is deleted (one-time use). On a wrong code the
// attempt counter is incremented; after maxTries the session is invalidated.
func (s *OTPStore) VerifyCode(ctx context.Context, loginToken, code string) (userID, apiClientID, email string, err error) {
	key := sessionKey(loginToken)

	res, err := verifyCodeScript.Run(ctx, s.rdb, []string{key}, hashCode(code), s.maxTries, s.ttl.Milliseconds()).Slice()
	if err != nil {
		return "", "", "", fmt.Errorf("running verify-code script: %w", err)
	}
	if len(res) == 0 {
		return "", "", "", fmt.Errorf("verify-code script: empty response")
	}

	status, _ := res[0].(string)
	switch status {
	case "not_found":
		return "", "", "", ErrLoginSessionNotFound
	case "too_many":
		return "", "", "", ErrTooManyAttempts
	case "invalid":
		return "", "", "", ErrInvalidCode
	case "ok":
		if len(res) != 4 {
			return "", "", "", fmt.Errorf("verify-code script: malformed \"ok\" response %v", res)
		}
		userID, _ = res[1].(string)
		apiClientID, _ = res[2].(string)
		email, _ = res[3].(string)
		return userID, apiClientID, email, nil
	default:
		return "", "", "", fmt.Errorf("verify-code script: unexpected status %q", status)
	}
}

func sessionKey(loginToken string) string {
	return "otp:login:" + loginToken
}

func hashCode(code string) string {
	sum := sha256.Sum256([]byte(code))
	return hex.EncodeToString(sum[:])
}

func generateNumericCode(length int) (string, error) {
	const digits = "0123456789"
	b := make([]byte, length)
	for i := range b {
		n, err := rand.Int(rand.Reader, big.NewInt(int64(len(digits))))
		if err != nil {
			return "", err
		}
		b[i] = digits[n.Int64()]
	}
	return string(b), nil
}

func generateToken(numBytes int) (string, error) {
	b := make([]byte, numBytes)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
