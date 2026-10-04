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
	ErrChangeEmailNotFound     = errors.New("change-email session not found or expired")
	ErrChangeEmailInvalidCode  = errors.New("invalid change-email code")
	ErrChangeEmailTooManyTries = errors.New("too many attempts, request a new code")
)

// changeEmailSession is what we keep in Redis between an admin starting an
// email correction and the account confirming it. The code is stored
// hashed, never in plain text — same as every other code-based session in
// this package. OldEmail rides along so ConfirmChangeEmail can notify that
// address once the change applies, without a second Postgres round trip.
type changeEmailSession struct {
	UserID   string `json:"user_id"`
	OldEmail string `json:"old_email"`
	CodeHash string `json:"code_hash"`
	Attempts int    `json:"attempts"`
}

// ChangeEmailStore manages short-lived, single-use codes for an
// admin-initiated email correction — same shape as EmailVerificationStore/
// PasswordResetStore, but keyed by the NEW email rather than the account's
// current one: the whole point is that the account proves control of the
// new address, not the old (typo'd, possibly unreachable) one.
type ChangeEmailStore struct {
	rdb      *redis.Client
	ttl      time.Duration
	maxTries int
	codeLen  int
}

func NewChangeEmailStore(rdb *redis.Client, ttl time.Duration, maxTries, codeLen int) *ChangeEmailStore {
	return &ChangeEmailStore{rdb: rdb, ttl: ttl, maxTries: maxTries, codeLen: codeLen}
}

// StartChange generates a fresh numeric code and stores its hash, scoped to
// apiClientID/newEmail, for ttl. Only one change stays pending per account:
// unlike EmailVerificationStore/PasswordResetStore (keyed by the account's
// own, fixed email, so a second call naturally overwrites the same Redis
// key), this is keyed by the NEW email — two requests naming two different
// target addresses would otherwise land on two independent keys and both
// stay valid. A per-user pointer tracks which target email is the current
// one, so a second request can delete the previous target's now-superseded
// session before starting the new one.
func (s *ChangeEmailStore) StartChange(ctx context.Context, userID, apiClientID, oldEmail, newEmail string) (code string, err error) {
	if err := s.supersedePending(ctx, apiClientID, userID, newEmail); err != nil {
		return "", err
	}

	code, err = generateNumericCode(s.codeLen)
	if err != nil {
		return "", fmt.Errorf("generating change-email code: %w", err)
	}

	sess := changeEmailSession{UserID: userID, OldEmail: oldEmail, CodeHash: hashCode(code)}
	data, err := json.Marshal(sess)
	if err != nil {
		return "", fmt.Errorf("marshaling change-email session: %w", err)
	}

	if err := s.rdb.Set(ctx, changeEmailKey(apiClientID, newEmail), data, s.ttl).Err(); err != nil {
		return "", fmt.Errorf("storing change-email session: %w", err)
	}
	if err := s.rdb.Set(ctx, changeEmailPointerKey(apiClientID, userID), newEmail, s.ttl).Err(); err != nil {
		return "", fmt.Errorf("storing change-email pointer: %w", err)
	}

	return code, nil
}

// supersedePending deletes userID's previous pending change, if it named a
// DIFFERENT target email than newEmail — a no-op when there was none, or
// when it's the same target being re-requested (that case is already
// handled by StartChange's own overwrite of the same key right after).
func (s *ChangeEmailStore) supersedePending(ctx context.Context, apiClientID, userID, newEmail string) error {
	prevEmail, err := s.rdb.Get(ctx, changeEmailPointerKey(apiClientID, userID)).Result()
	if errors.Is(err, redis.Nil) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("reading previous change-email pointer: %w", err)
	}
	if prevEmail == newEmail {
		return nil
	}
	if err := s.rdb.Del(ctx, changeEmailKey(apiClientID, prevEmail)).Err(); err != nil {
		return fmt.Errorf("deleting superseded change-email session: %w", err)
	}
	return nil
}

// verifyChangeEmailCodeScript mirrors verifyEmailCodeScript/
// verifyResetCodeScript: one atomic read-compare-increment-write, for the
// same reason — separate GET/SET calls would let parallel guesses against
// the same session all read the same stale Attempts value and exceed
// maxTries.
var verifyChangeEmailCodeScript = redis.NewScript(`
local raw = redis.call('GET', KEYS[1])
if not raw then
	return {'not_found'}
end
local sess = cjson.decode(raw)
if sess.code_hash == ARGV[1] then
	redis.call('DEL', KEYS[1])
	return {'ok', sess.user_id, sess.old_email}
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

// ConsumeCode checks code against the pending change for apiClientID/
// newEmail. On success the session is deleted (single-use) and the old
// email is returned alongside the user id — ConfirmChangeEmail needs it to
// notify the previous address that the change happened. On a wrong code the
// attempt counter is incremented; after maxTries the session is invalidated
// and a new change has to be started from scratch.
func (s *ChangeEmailStore) ConsumeCode(ctx context.Context, apiClientID, newEmail, code string) (userID, oldEmail string, err error) {
	key := changeEmailKey(apiClientID, newEmail)

	res, err := verifyChangeEmailCodeScript.Run(ctx, s.rdb, []string{key}, hashCode(code), s.maxTries, s.ttl.Milliseconds()).Slice()
	if err != nil {
		return "", "", fmt.Errorf("running verify-change-email-code script: %w", err)
	}
	if len(res) == 0 {
		return "", "", fmt.Errorf("verify-change-email-code script: empty response")
	}

	status, _ := res[0].(string)
	switch status {
	case "not_found":
		return "", "", ErrChangeEmailNotFound
	case "too_many":
		return "", "", ErrChangeEmailTooManyTries
	case "invalid":
		return "", "", ErrChangeEmailInvalidCode
	case "ok":
		if len(res) != 3 {
			return "", "", fmt.Errorf("verify-change-email-code script: malformed \"ok\" response %v", res)
		}
		userID, _ = res[1].(string)
		oldEmail, _ = res[2].(string)
		// Best-effort: the pointer has its own TTL and will expire on its
		// own even if this fails, and a stale pointer only ever causes a
		// harmless no-op delete the next time StartChange checks it.
		_ = s.rdb.Del(ctx, changeEmailPointerKey(apiClientID, userID)).Err()
		return userID, oldEmail, nil
	default:
		return "", "", fmt.Errorf("verify-change-email-code script: unexpected status %q", status)
	}
}

func changeEmailKey(apiClientID, newEmail string) string {
	return "change_email:" + apiClientID + ":" + newEmail
}

// changeEmailPointerKey maps an account to whichever new email its current
// pending change (if any) targets — see StartChange/supersedePending.
func changeEmailPointerKey(apiClientID, userID string) string {
	return "change_email_pointer:" + apiClientID + ":" + userID
}
