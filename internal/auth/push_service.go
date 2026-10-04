package auth

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"math/big"
	"time"

	"github.com/redis/go-redis/v9"
)

// ErrPushNotConfigured is returned by every push-approval method when this
// deployment never set FIREBASE_CREDENTIALS_PATH — same reasoning as
// ErrTOTPNotConfigured: an opt-in feature with no credentials configured
// should not exist, not silently no-op.
var ErrPushNotConfigured = errors.New("push approval is not configured on this server")

// PushRequestLimiter caps how many push-approval requests can be started
// for one account within a rolling window — separate from
// LoginAttemptLimiter (which only tracks *failed* passwords): an attacker
// who already has the correct password can call LoginStep1 successfully as
// many times as they like, and every success would otherwise trigger a
// fresh push notification. This is the actual defense against "MFA
// fatigue" spam; the number-matching challenge (see push_login_store.go)
// is what makes any individual notification hard to approve blindly, but
// doesn't by itself stop someone from just sending a lot of them.
type PushRequestLimiter struct {
	rdb    *redis.Client
	limit  int64
	window int64 // seconds
}

func NewPushRequestLimiter(rdb *redis.Client, limit int, windowSeconds int) *PushRequestLimiter {
	return &PushRequestLimiter{rdb: rdb, limit: int64(limit), window: int64(windowSeconds)}
}

// Allow increments userID's counter and reports whether it's still within
// the limit for the current window — same fixed-window-counter shape as
// middleware.RateLimiter, reimplemented locally rather than imported: that
// package already imports auth (for TokenManager), so the reverse import
// would cycle.
func (l *PushRequestLimiter) Allow(ctx context.Context, userID string) (bool, error) {
	key := "push_requests:" + userID
	count, err := l.rdb.Incr(ctx, key).Result()
	if err != nil {
		return false, fmt.Errorf("incrementing push request count: %w", err)
	}
	if count == 1 {
		if err := l.rdb.Expire(ctx, key, time.Duration(l.window)*time.Second).Err(); err != nil {
			return false, fmt.Errorf("setting push request limit ttl: %w", err)
		}
	}
	return count <= l.limit, nil
}

// EnablePushApproval opts an already-trusted device into receiving
// push-notification login-approval requests — the user must already be
// authenticated (this is called from the Security screen, or the same
// opportunistic banner as PIN setup, never during registration/first
// login: see README's design notes on why push can only ever be a
// later opt-in, not a first-login choice). deviceRowID is the trusted
// device's own id (see ListDevices), not its client-generated device_id.
func (s *Service) EnablePushApproval(ctx context.Context, userID, deviceRowID, pushToken string) error {
	if s.push == nil {
		return ErrPushNotConfigured
	}
	return s.devices.EnablePush(ctx, userID, deviceRowID, pushToken)
}

// DisablePushApproval turns push back off for deviceRowID — the device
// itself (PIN unlock, trust) is untouched, this is the "turn it back off"
// counterpart to EnablePushApproval, letting someone opt out of push
// without losing their PIN shortcut the way revoking the whole device
// would.
func (s *Service) DisablePushApproval(ctx context.Context, userID, deviceRowID string) error {
	if s.push == nil {
		return ErrPushNotConfigured
	}
	return s.devices.DisablePush(ctx, userID, deviceRowID)
}

// startPushLogin is called from LoginStep1, after it already has a
// verified, TwoFactorMethodChosen account and has started its normal
// email-OTP or TOTP session — never on its own, and never for a first-ever
// login (see LoginStep1's doc comment for why). If the account has no
// push-capable device, or push isn't configured on this deployment, or the
// account already hit PushRequestLimiter's cap, this is a silent no-op:
// LoginStep1's existing email/TOTP session is still perfectly valid either
// way, so a failure here should never block login, only skip offering the
// faster option.
func (s *Service) startPushLogin(ctx context.Context, loginToken string, u pushLoginCandidate) (offered bool) {
	if s.push == nil || s.pushLogin == nil {
		return false
	}

	devices, err := s.devices.PushCapableDevices(ctx, u.ID)
	if err != nil {
		s.logger.Warn("push: listing push-capable devices failed, skipping push offer", "user_id", u.ID, "error", err)
		return false
	}
	if len(devices) == 0 {
		return false
	}

	allowed, err := s.pushRequestLimiter.Allow(ctx, u.ID)
	if err != nil {
		s.logger.Warn("push: request limiter check failed, skipping push offer", "user_id", u.ID, "error", err)
		return false
	}
	if !allowed {
		return false
	}

	numbers, correct, err := generatePushNumbers()
	if err != nil {
		s.logger.Error("push: generating challenge numbers failed, skipping push offer", "user_id", u.ID, "error", err)
		return false
	}

	if err := s.pushLogin.Start(ctx, loginToken, u.ID, u.APIClientID, u.Email, correct); err != nil {
		s.logger.Warn("push: starting login session failed, skipping push offer", "user_id", u.ID, "error", err)
		return false
	}

	// Best-effort fan-out to every push-capable device this account has —
	// whichever one the user actually has in hand answers first (see
	// PushLoginStore.Answer's single-shot semantics: only the first answer,
	// from whichever device, ever counts). A device whose token FCM now
	// rejects as stale doesn't block the others — logged (not returned),
	// since one bad token among several devices shouldn't look like the
	// whole push offer failed.
	expiresAt := time.Now().Add(s.pushLogin.TTL())
	for _, d := range devices {
		if err := s.push.SendLoginApproval(ctx, d.PushToken, loginToken, numbers, expiresAt); err != nil {
			s.logger.Warn("push: sending login approval to device failed", "user_id", u.ID, "device_id", d.ID, "error", err)
		}
	}

	return true
}

// pushLoginCandidate is the subset of user.User that startPushLogin needs —
// kept as its own tiny type instead of importing user.User directly here,
// since this file otherwise has no reason to know about that package (the
// one caller, LoginStep1 in service.go, already has a full user.User and
// just passes the three fields through).
type pushLoginCandidate struct {
	ID          string
	APIClientID string
	Email       string
}

// generatePushNumbers picks three distinct 2-digit numbers (00-99) and
// designates one of them (at a random position) as correct — see
// push_login_store.go's own doc comments for why three indistinguishable
// choices, not a single "tap to approve" button, is the actual point.
func generatePushNumbers() (numbers [3]int, correctValue int, err error) {
	seen := make(map[int]bool, 3)
	for i := 0; i < 3; i++ {
		for {
			n, err := randInt(100)
			if err != nil {
				return [3]int{}, 0, err
			}
			if !seen[n] {
				seen[n] = true
				numbers[i] = n
				break
			}
		}
	}
	correctIdx, err := randInt(3)
	if err != nil {
		return [3]int{}, 0, err
	}
	return numbers, numbers[correctIdx], nil
}

func randInt(n int) (int, error) {
	max := big.NewInt(int64(n))
	v, err := rand.Int(rand.Reader, max)
	if err != nil {
		return 0, fmt.Errorf("generating random number: %w", err)
	}
	return int(v.Int64()), nil
}

// PushLoginStatus reports a pending push-approval request's current state,
// for the PC side's polling loop (see README's design notes: ~2s interval,
// nothing fancier like WebSockets — the same pattern OAuth's own Device
// Authorization Grant, RFC 8628, uses for this exact kind of "waiting on a
// human to act on another device" wait). On "approved", also returns a
// fresh token pair and consumes the request — a second poll after that
// returns ErrLoginSessionNotFound, same one-time-use rule as
// /auth/verify-otp.
//
// displayNumber is the SAME number startPushLogin designated as correct —
// this is the PC's only way to ever learn it, and it has to: the whole
// number-matching mechanism only works if the human can compare what's on
// the PC's screen against the three choices the phone got. Handing it back
// here to whoever already holds loginToken isn't a downgrade — an attacker
// impersonating "the PC" necessarily already has that token (they're the
// one who triggered the login), and still can't act on it without the real
// phone owner independently choosing the same number on their own device.
func (s *Service) PollPushLogin(ctx context.Context, loginToken string) (status string, displayNumber int, result LoginResult, err error) {
	if s.pushLogin == nil {
		return "", 0, LoginResult{}, ErrPushNotConfigured
	}

	sess, found, err := s.pushLogin.Peek(ctx, loginToken)
	if err != nil {
		return "", 0, LoginResult{}, err
	}
	if !found {
		return "", 0, LoginResult{}, ErrLoginSessionNotFound
	}

	if sess.Status != pushLoginApproved {
		return string(sess.Status), sess.CorrectNumber, LoginResult{}, nil
	}

	if err := s.pushLogin.Consume(ctx, loginToken); err != nil {
		return "", 0, LoginResult{}, err
	}
	result, err = s.finishLogin(ctx, sess.UserID, sess.APIClientID, sess.Email)
	if err != nil {
		return "", 0, LoginResult{}, err
	}
	return string(pushLoginApproved), sess.CorrectNumber, result, nil
}

// AnswerPushLogin records the phone's tap. Unlike PollPushLogin (called by
// the PC, identified only by loginToken — it isn't logged in yet, that's
// the whole point), this is called from the phone's own already-
// authenticated session (a Bearer token), so callerUserID comes from that
// session, not from the request body — a phone can only ever answer a
// request addressed to its own account, never anyone else's, even if it
// somehow guessed another account's loginToken.
//
// Returns the resolved status ("approved" or "rejected") — the phone's own
// UI needs this: tapping the wrong number should tell the user their
// session was rejected (and, implicitly, that someone else tried to log in
// as them), not show the same generic "sent" confirmation a correct tap
// gets.
func (s *Service) AnswerPushLogin(ctx context.Context, callerUserID, loginToken string, chosenNumber int) (status string, err error) {
	if s.pushLogin == nil {
		return "", ErrPushNotConfigured
	}

	sess, found, err := s.pushLogin.Peek(ctx, loginToken)
	if err != nil {
		return "", err
	}
	if !found {
		return "", ErrLoginSessionNotFound
	}
	if sess.UserID != callerUserID {
		return "", ErrLoginSessionNotFound
	}

	resolved, err := s.pushLogin.Answer(ctx, loginToken, chosenNumber)
	if err != nil {
		return "", err
	}
	return string(resolved), nil
}

// RequestLoginEmailCode is the "usar otro método" / "no me llegó el push"
// escape hatch for a login that only offered push — see LoginStep1's doc
// comment for why the OTP isn't emailed automatically in that case. Sends
// it now, under the SAME loginToken: LoginStep2/VerifyOTP works against it
// exactly like any other email login from here on, no second token to
// juggle. Safe to call more than once (e.g. "reenviar código") — each call
// just overwrites the pending code, same as ResendEmailVerification.
//
// Reads the account's identity off the pending push session rather than
// looking the user up again — loginToken only ever reaches here because
// startPushLogin already resolved and stored it there.
func (s *Service) RequestLoginEmailCode(ctx context.Context, loginToken string) error {
	if s.pushLogin == nil {
		return ErrPushNotConfigured
	}

	sess, found, err := s.pushLogin.Peek(ctx, loginToken)
	if err != nil {
		return err
	}
	if !found {
		return ErrLoginSessionNotFound
	}

	code, err := s.otp.StartSessionWithToken(ctx, loginToken, sess.UserID, sess.APIClientID, sess.Email)
	if err != nil {
		return err
	}
	body := fmt.Sprintf(
		"Tu código de verificación es: %s\n\nExpira en %s. Si no solicitaste este código, ignora este correo.",
		code, humanDuration(s.otpTTL),
	)
	if err := s.mailer.Send(ctx, sess.Email, "Tu código de verificación", body); err != nil {
		return fmt.Errorf("sending otp email: %w", err)
	}
	return nil
}
