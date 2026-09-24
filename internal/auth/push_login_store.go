package auth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
)

// pushLoginStatus tracks a pending push-approval request through its one
// possible transition: pending -> approved or pending -> rejected, never
// back, and never a second time (see answerScript). Deliberately not an
// enum backed by iota — the string form goes straight into Redis/JSON, and
// PollPushLogin hands it back to the HTTP layer almost verbatim.
type pushLoginStatus string

const (
	pushLoginPending  pushLoginStatus = "pending"
	pushLoginApproved pushLoginStatus = "approved"
	pushLoginRejected pushLoginStatus = "rejected"
)

type pushLoginSession struct {
	UserID        string          `json:"user_id"`
	APIClientID   string          `json:"api_client_id"`
	Email         string          `json:"email"`
	CorrectNumber int             `json:"correct_number"`
	Status        pushLoginStatus `json:"status"`
}

// PushLoginStore holds pending push-notification login approvals — the
// window between "PC asked for approval" and "phone answered" (or the
// request simply expiring, same TTL-based lifetime as the OTP/TOTP login
// sessions this sits alongside; see pendingLoginStore's own doc comment for
// why this kind of data lives in Redis, not Postgres).
type PushLoginStore struct {
	rdb    *redis.Client
	ttl    time.Duration
	prefix string
}

func NewPushLoginStore(rdb *redis.Client, ttl time.Duration) *PushLoginStore {
	return &PushLoginStore{rdb: rdb, ttl: ttl, prefix: "push-login:"}
}

// TTL is how long a request this store creates stays answerable — exposed
// so startPushLogin can tell the phone's push notification when the
// request it's about to show actually expires, instead of the phone having
// no idea and just failing opaquely if the person takes too long to decide.
func (s *PushLoginStore) TTL() time.Duration {
	return s.ttl
}

func (s *PushLoginStore) key(requestID string) string {
	return s.prefix + requestID
}

// Start creates a pending push-approval request under loginToken — the
// SAME token LoginStep1 already returned for the OTP/TOTP session it
// started for this login (not a token this store generates itself): a
// client that gets both back can poll push status and, if the user picks
// "usar otro método" instead, call /auth/verify-otp with that identical
// token without needing a second round trip to get one. correctNumber is
// the one of the three displayed numbers (chosen and shuffled by the
// caller — see auth.Service.StartPushLogin) that actually counts as
// approval.
func (s *PushLoginStore) Start(ctx context.Context, loginToken, userID, apiClientID, email string, correctNumber int) error {
	sess := pushLoginSession{
		UserID:        userID,
		APIClientID:   apiClientID,
		Email:         email,
		CorrectNumber: correctNumber,
		Status:        pushLoginPending,
	}
	data, err := json.Marshal(sess)
	if err != nil {
		return fmt.Errorf("marshaling push login session: %w", err)
	}

	if err := s.rdb.Set(ctx, s.key(loginToken), data, s.ttl).Err(); err != nil {
		return fmt.Errorf("storing push login session: %w", err)
	}
	return nil
}

// Peek reports whether requestID belongs to a pending (or already-answered
// but not yet consumed) push login, without consuming it — used both by
// the PC's poll endpoint and by the phone's answer endpoint to resolve
// which account/session it's acting on.
func (s *PushLoginStore) Peek(ctx context.Context, requestID string) (sess pushLoginSession, found bool, err error) {
	raw, err := s.rdb.Get(ctx, s.key(requestID)).Bytes()
	if errors.Is(err, redis.Nil) {
		return pushLoginSession{}, false, nil
	}
	if err != nil {
		return pushLoginSession{}, false, fmt.Errorf("reading push login session: %w", err)
	}
	if err := json.Unmarshal(raw, &sess); err != nil {
		return pushLoginSession{}, false, fmt.Errorf("decoding push login session: %w", err)
	}
	return sess, true, nil
}

// answerScript does the whole read-compare-write in one atomic Redis
// operation, same reasoning as otp.go's verifyCodeScript: without this, two
// concurrent answers (a genuine double-tap, or an attacker racing a guess
// against the real answer) could both read the still-"pending" status
// before either writes back — letting a request be answered more than
// once, which defeats the entire point of the number-matching check.
var answerPushLoginScript = redis.NewScript(`
local raw = redis.call('GET', KEYS[1])
if not raw then
	return {'not_found'}
end
local sess = cjson.decode(raw)
if sess.status ~= 'pending' then
	return {sess.status}
end
if tonumber(ARGV[1]) == sess.correct_number then
	sess.status = 'approved'
else
	sess.status = 'rejected'
end
local ttl = redis.call('PTTL', KEYS[1])
if ttl <= 0 then
	ttl = tonumber(ARGV[2])
end
redis.call('SET', KEYS[1], cjson.encode(sess), 'PX', ttl)
return {sess.status}
`)

// Answer records the phone's tap — chosenNumber is whichever of the three
// displayed numbers the user picked. Resolves to "approved" only if it
// matches the correct one; anything else (including a wrong tap) resolves
// to "rejected", permanently — see answerPushLoginScript for why a second
// call can't overturn the first.
func (s *PushLoginStore) Answer(ctx context.Context, requestID string, chosenNumber int) (status pushLoginStatus, err error) {
	res, err := answerPushLoginScript.Run(ctx, s.rdb, []string{s.key(requestID)}, chosenNumber, s.ttl.Milliseconds()).Slice()
	if err != nil {
		return "", fmt.Errorf("running answer-push-login script: %w", err)
	}
	if len(res) == 0 {
		return "", fmt.Errorf("answer-push-login script: empty response")
	}
	raw, _ := res[0].(string)
	if raw == "not_found" {
		return "", ErrLoginSessionNotFound
	}
	return pushLoginStatus(raw), nil
}

// Consume deletes the session — called once the PC has picked up a final
// approved/rejected status (or given up on it), so the same request can't
// be polled or answered again after it's already been acted on.
func (s *PushLoginStore) Consume(ctx context.Context, requestID string) error {
	return s.rdb.Del(ctx, s.key(requestID)).Err()
}
