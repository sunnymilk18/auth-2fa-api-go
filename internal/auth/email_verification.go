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
	ErrEmailVerificationNotFound     = errors.New("email verification session not found or expired")
	ErrEmailVerificationInvalidCode  = errors.New("invalid email verification code")
	ErrEmailVerificationTooManyTries = errors.New("too many attempts, request a new code")
)

// emailVerificationSession is what we keep in Redis between "registered"
// and "email confirmed". The code is stored hashed, never in plain text —
// same as loginSession/passwordResetSession.
type emailVerificationSession struct {
	UserID   string `json:"user_id"`
	CodeHash string `json:"code_hash"`
	Attempts int    `json:"attempts"`
}

// EmailVerificationStore manages short-lived, single-use email
// confirmation codes in Redis — same shape as PasswordResetStore: a short
// numeric code, hashed + attempt-limited, keyed by api client + email
// rather than an opaque session token, since there's no earlier step that
// hands the client one to carry forward (Register's response must stay the
// same whether or not the email send succeeds from the caller's point of
// view — resending is how a lost/expired code gets recovered).
type EmailVerificationStore struct {
	rdb      *redis.Client
	ttl      time.Duration
	maxTries int
	codeLen  int
}

func NewEmailVerificationStore(rdb *redis.Client, ttl time.Duration, maxTries, codeLen int) *EmailVerificationStore {
	return &EmailVerificationStore{rdb: rdb, ttl: ttl, maxTries: maxTries, codeLen: codeLen}
}

// StartVerification generates a fresh numeric code and stores its hash,
// scoped to apiClientID/email, for ttl. A new call for the same account
// (e.g. a resend) overwrites any still-pending code — only the most
// recently emailed one is valid.
func (s *EmailVerificationStore) StartVerification(ctx context.Context, userID, apiClientID, email string) (code string, err error) {
	code, err = generateNumericCode(s.codeLen)
	if err != nil {
		return "", fmt.Errorf("generating email verification code: %w", err)
	}

	sess := emailVerificationSession{UserID: userID, CodeHash: hashCode(code)}
	data, err := json.Marshal(sess)
	if err != nil {
		return "", fmt.Errorf("marshaling email verification session: %w", err)
	}

	if err := s.rdb.Set(ctx, verificationKey(apiClientID, email), data, s.ttl).Err(); err != nil {
		return "", fmt.Errorf("storing email verification session: %w", err)
	}

	return code, nil
}

// verifyEmailCodeScript mirrors verifyCodeScript/verifyResetCodeScript: one
// atomic read-compare-increment-write, for the same reason — separate
// GET/SET calls would let parallel guesses against the same session all
// read the same stale Attempts value and exceed maxTries.
var verifyEmailCodeScript = redis.NewScript(`
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

// ConsumeCode checks code against the pending verification session for
// apiClientID/email. On success the session is deleted (single-use). On a
// wrong code the attempt counter is incremented; after maxTries the session
// is invalidated and the user has to request a new code (resend).
func (s *EmailVerificationStore) ConsumeCode(ctx context.Context, apiClientID, email, code string) (userID string, err error) {
	key := verificationKey(apiClientID, email)

	res, err := verifyEmailCodeScript.Run(ctx, s.rdb, []string{key}, hashCode(code), s.maxTries, s.ttl.Milliseconds()).Slice()
	if err != nil {
		return "", fmt.Errorf("running verify-email-code script: %w", err)
	}
	if len(res) == 0 {
		return "", fmt.Errorf("verify-email-code script: empty response")
	}

	status, _ := res[0].(string)
	switch status {
	case "not_found":
		return "", ErrEmailVerificationNotFound
	case "too_many":
		return "", ErrEmailVerificationTooManyTries
	case "invalid":
		return "", ErrEmailVerificationInvalidCode
	case "ok":
		if len(res) != 2 {
			return "", fmt.Errorf("verify-email-code script: malformed \"ok\" response %v", res)
		}
		userID, _ = res[1].(string)
		return userID, nil
	default:
		return "", fmt.Errorf("verify-email-code script: unexpected status %q", status)
	}
}

func verificationKey(apiClientID, email string) string {
	return "email_verification:" + apiClientID + ":" + email
}
