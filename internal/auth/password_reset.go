package auth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
)

var (
	ErrPasswordResetNotFound     = errors.New("password reset session not found or expired")
	ErrPasswordResetInvalidCode  = errors.New("invalid password reset code")
	ErrPasswordResetTooManyTries = errors.New("too many attempts, request a new code")
)

// passwordResetSession is what we keep in Redis between "reset requested"
// and "reset confirmed". The code is stored hashed, never in plain text —
// same as loginSession.
type passwordResetSession struct {
	UserID   string `json:"user_id"`
	CodeHash string `json:"code_hash"`
	Attempts int    `json:"attempts"`
}

// PasswordResetStore manages short-lived, single-use password reset codes
// in Redis — same rationale as OTPStore: high-churn, short-lived data that
// doesn't belong in the durable DB.
//
// The code is a short numeric string the user types by hand, not a
// high-entropy token — mirroring OTPStore's login code rather than the
// opaque login_token/device_token pattern used elsewhere in this package.
// Unlike the login OTP, this code is reachable by anyone who knows the
// account's email (no password check gates it), so it's backed by the same
// hashed-code + attempt-limited verification as the login OTP, keyed by
// api client + email since there's no separate opaque session id handed
// back to the client to look the session up by (the request response must
// stay identical whether or not the account exists).
type PasswordResetStore struct {
	rdb      *redis.Client
	ttl      time.Duration
	maxTries int
	codeLen  int
}

func NewPasswordResetStore(rdb *redis.Client, ttl time.Duration, maxTries, codeLen int) *PasswordResetStore {
	return &PasswordResetStore{rdb: rdb, ttl: ttl, maxTries: maxTries, codeLen: codeLen}
}

// StartReset generates a fresh numeric code and stores its hash, scoped to
// apiClientID/email, for ttl. A new call for the same account overwrites
// any still-pending code — only the most recently emailed one is valid, the
// same way requesting a new login OTP invalidates an older one.
func (s *PasswordResetStore) StartReset(ctx context.Context, userID, apiClientID, email string) (code string, err error) {
	code, err = generateNumericCode(s.codeLen)
	if err != nil {
		return "", fmt.Errorf("generating password reset code: %w", err)
	}

	sess := passwordResetSession{UserID: userID, CodeHash: hashCode(code)}
	data, err := json.Marshal(sess)
	if err != nil {
		return "", fmt.Errorf("marshaling password reset session: %w", err)
	}

	if err := s.rdb.Set(ctx, resetKey(apiClientID, email), data, s.ttl).Err(); err != nil {
		return "", fmt.Errorf("storing password reset session: %w", err)
	}

	return code, nil
}

// verifyResetCodeScript mirrors verifyCodeScript in otp.go: one atomic
// read-compare-increment-write, for the same reason — separate GET/SET
// calls would let parallel guesses against the same session all read the
// same stale Attempts value and exceed maxTries.
var verifyResetCodeScript = redis.NewScript(`
local raw = redis.call('GET', KEYS[1])
if not raw then
	return {'not_found'}
end
local sess = cjson.decode(raw)
if sess.code_hash == ARGV[1] then
	redis.call('DEL', KEYS[1])
	return {'ok', sess.user_id}
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

// ConsumeCode checks code against the pending reset session for
// apiClientID/email. On success the session is deleted (single-use). On a
// wrong code the attempt counter is incremented; after maxTries the session
// is invalidated and the user has to request a new code.
func (s *PasswordResetStore) ConsumeCode(ctx context.Context, apiClientID, email, code string) (userID string, err error) {
	key := resetKey(apiClientID, email)

	res, err := verifyResetCodeScript.Run(ctx, s.rdb, []string{key}, hashCode(code), s.maxTries, s.ttl.Milliseconds()).Slice()
	if err != nil {
		return "", fmt.Errorf("running verify-reset-code script: %w", err)
	}
	if len(res) == 0 {
		return "", fmt.Errorf("verify-reset-code script: empty response")
	}

	status, _ := res[0].(string)
	switch status {
	case "not_found":
		return "", ErrPasswordResetNotFound
	case "too_many":
		return "", ErrPasswordResetTooManyTries
	case "invalid":
		return "", ErrPasswordResetInvalidCode
	case "ok":
		if len(res) != 2 {
			return "", fmt.Errorf("verify-reset-code script: malformed \"ok\" response %v", res)
		}
		userID, _ = res[1].(string)
		return userID, nil
	default:
		return "", fmt.Errorf("verify-reset-code script: unexpected status %q", status)
	}
}

func resetKey(apiClientID, email string) string {
	return "password_reset:" + apiClientID + ":" + email
}
