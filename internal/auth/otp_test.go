package auth_test

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"auth-2fa-api/internal/auth"
	"auth-2fa-api/internal/testutil"
)

func newTestOTPStore(t *testing.T, maxTries int) *auth.OTPStore {
	t.Helper()
	rdb := testutil.RedisClient(t)
	return auth.NewOTPStore(rdb, 5*time.Minute, maxTries, 6)
}

func TestOTPStore_VerifyCode_Success(t *testing.T) {
	store := newTestOTPStore(t, 5)
	loginToken, code, err := store.StartSession(t.Context(), "user1", "client1", "a@b.com")
	if err != nil {
		t.Fatalf("StartSession: %v", err)
	}

	userID, apiClientID, email, err := store.VerifyCode(t.Context(), loginToken, code)
	if err != nil {
		t.Fatalf("VerifyCode: %v", err)
	}
	if userID != "user1" || apiClientID != "client1" || email != "a@b.com" {
		t.Fatalf("VerifyCode = (%q, %q, %q), want (user1, client1, a@b.com)", userID, apiClientID, email)
	}

	// Single-use: the same code doesn't work a second time.
	if _, _, _, err := store.VerifyCode(t.Context(), loginToken, code); err != auth.ErrLoginSessionNotFound {
		t.Fatalf("second VerifyCode: err = %v, want %v", err, auth.ErrLoginSessionNotFound)
	}
}

func TestOTPStore_VerifyCode_UnknownToken(t *testing.T) {
	store := newTestOTPStore(t, 5)
	if _, _, _, err := store.VerifyCode(t.Context(), "does-not-exist", "123456"); err != auth.ErrLoginSessionNotFound {
		t.Fatalf("err = %v, want %v", err, auth.ErrLoginSessionNotFound)
	}
}

func TestOTPStore_VerifyCode_WrongCodeThenSuccess(t *testing.T) {
	store := newTestOTPStore(t, 5)
	loginToken, code, err := store.StartSession(t.Context(), "user1", "client1", "a@b.com")
	if err != nil {
		t.Fatalf("StartSession: %v", err)
	}

	if _, _, _, err := store.VerifyCode(t.Context(), loginToken, "000000"); err != auth.ErrInvalidCode {
		t.Fatalf("wrong code: err = %v, want %v", err, auth.ErrInvalidCode)
	}
	if _, _, _, err := store.VerifyCode(t.Context(), loginToken, code); err != nil {
		t.Fatalf("correct code after one wrong attempt: unexpected error %v", err)
	}
}

// Regression test for a lost-update race: VerifyCode used to GET the
// session, increment Attempts in Go, then SET it back — non-atomic, so
// concurrent wrong guesses against the same login_token could all read the
// same stale Attempts value and only count as one increment, letting an
// attacker exceed maxTries by guessing in parallel instead of sequentially.
// Fires far more concurrent wrong guesses than maxTries and asserts the
// number that actually got "counted" (ErrInvalidCode, before the session
// was invalidated) never exceeds maxTries — i.e. exactly maxTries-1 succeed
// as ErrInvalidCode and the rest see ErrTooManyAttempts or (once deleted)
// ErrLoginSessionNotFound, with no lost updates.
func TestOTPStore_VerifyCode_ConcurrentGuessesRespectMaxTries(t *testing.T) {
	const maxTries = 5
	const concurrency = 50

	store := newTestOTPStore(t, maxTries)
	loginToken, _, err := store.StartSession(t.Context(), "user1", "client1", "a@b.com")
	if err != nil {
		t.Fatalf("StartSession: %v", err)
	}

	var invalidCount, tooManyCount, notFoundCount, otherCount atomic.Int64
	var wg sync.WaitGroup
	wg.Add(concurrency)
	for i := 0; i < concurrency; i++ {
		go func() {
			defer wg.Done()
			_, _, _, err := store.VerifyCode(t.Context(), loginToken, "000000")
			switch err {
			case auth.ErrInvalidCode:
				invalidCount.Add(1)
			case auth.ErrTooManyAttempts:
				tooManyCount.Add(1)
			case auth.ErrLoginSessionNotFound:
				notFoundCount.Add(1)
			default:
				otherCount.Add(1)
				t.Errorf("unexpected error from concurrent VerifyCode: %v", err)
			}
		}()
	}
	wg.Wait()

	if otherCount.Load() != 0 {
		t.Fatalf("got %d unexpected errors", otherCount.Load())
	}
	// Exactly maxTries-1 wrong guesses should ever be accepted as merely
	// "invalid" (the Nth one that crosses maxTries deletes the session and
	// reports "too many" instead) — a lost-update race would let this
	// exceed maxTries-1.
	if invalidCount.Load() != maxTries-1 {
		t.Fatalf("invalidCount = %d, want exactly %d (maxTries-1) — a value above this means the attempt counter lost updates under concurrency", invalidCount.Load(), maxTries-1)
	}
	// Exactly one goroutine should be the one that pushes it over the edge.
	if tooManyCount.Load() != 1 {
		t.Fatalf("tooManyCount = %d, want exactly 1", tooManyCount.Load())
	}
	// Everyone else arrives after the session was already deleted.
	if got, want := invalidCount.Load()+tooManyCount.Load()+notFoundCount.Load(), int64(concurrency); got != want {
		t.Fatalf("invalid+tooMany+notFound = %d, want %d (total requests)", got, want)
	}
}
