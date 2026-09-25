package auth_test

import (
	"testing"
	"time"

	"auth-2fa-api/internal/auth"
	"auth-2fa-api/internal/testutil"
)

func TestLoginAttemptLimiter_LocksAfterMaxFailures(t *testing.T) {
	rdb := testutil.RedisClient(t)
	l := auth.NewLoginAttemptLimiter(rdb, 3, 15*time.Minute)

	for i := 1; i <= 2; i++ {
		locked, _, err := l.IsLocked(t.Context(), "client1", "a@b.com")
		if err != nil || locked {
			t.Fatalf("before failure %d: locked=%v err=%v, want false, nil", i, locked, err)
		}
		if err := l.RecordFailure(t.Context(), "client1", "a@b.com"); err != nil {
			t.Fatalf("RecordFailure %d: %v", i, err)
		}
	}

	// Still under the limit (2 failures, maxFails=3).
	locked, _, err := l.IsLocked(t.Context(), "client1", "a@b.com")
	if err != nil || locked {
		t.Fatalf("after 2 failures: locked=%v err=%v, want false, nil", locked, err)
	}

	// The 3rd failure crosses maxFails=3.
	if err := l.RecordFailure(t.Context(), "client1", "a@b.com"); err != nil {
		t.Fatalf("RecordFailure 3: %v", err)
	}
	locked, _, err = l.IsLocked(t.Context(), "client1", "a@b.com")
	if err != nil || !locked {
		t.Fatalf("after 3 failures: locked=%v err=%v, want true, nil", locked, err)
	}
}

func TestLoginAttemptLimiter_IsolatedPerAccount(t *testing.T) {
	rdb := testutil.RedisClient(t)
	l := auth.NewLoginAttemptLimiter(rdb, 1, 15*time.Minute)

	if err := l.RecordFailure(t.Context(), "client1", "victim@example.com"); err != nil {
		t.Fatalf("RecordFailure: %v", err)
	}
	locked, _, err := l.IsLocked(t.Context(), "client1", "victim@example.com")
	if err != nil || !locked {
		t.Fatalf("victim@example.com: locked=%v err=%v, want true, nil", locked, err)
	}

	// A different email, and the same email under a different tenant, are
	// unaffected.
	if locked, _, err := l.IsLocked(t.Context(), "client1", "someone-else@example.com"); err != nil || locked {
		t.Fatalf("different email: locked=%v err=%v, want false, nil", locked, err)
	}
	if locked, _, err := l.IsLocked(t.Context(), "client2", "victim@example.com"); err != nil || locked {
		t.Fatalf("same email, different tenant: locked=%v err=%v, want false, nil", locked, err)
	}
}

func TestLoginAttemptLimiter_EmailNormalization(t *testing.T) {
	rdb := testutil.RedisClient(t)
	l := auth.NewLoginAttemptLimiter(rdb, 1, 15*time.Minute)

	if err := l.RecordFailure(t.Context(), "client1", "  User@Example.COM  "); err != nil {
		t.Fatalf("RecordFailure: %v", err)
	}
	// Same account, differently-cased/spaced — must be recognized as the
	// same key, or the lockout is trivially bypassed by varying case.
	locked, _, err := l.IsLocked(t.Context(), "client1", "user@example.com")
	if err != nil || !locked {
		t.Fatalf("normalized email: locked=%v err=%v, want true, nil", locked, err)
	}
}

func TestLoginAttemptLimiter_Reset(t *testing.T) {
	rdb := testutil.RedisClient(t)
	l := auth.NewLoginAttemptLimiter(rdb, 1, 15*time.Minute)

	if err := l.RecordFailure(t.Context(), "client1", "a@b.com"); err != nil {
		t.Fatalf("RecordFailure: %v", err)
	}
	if err := l.Reset(t.Context(), "client1", "a@b.com"); err != nil {
		t.Fatalf("Reset: %v", err)
	}
	locked, _, err := l.IsLocked(t.Context(), "client1", "a@b.com")
	if err != nil || locked {
		t.Fatalf("after Reset: locked=%v err=%v, want false, nil", locked, err)
	}
}

// IsLocked's retryAfter must reflect how much of the window is actually
// left, not always the full configured window — otherwise a user locked
// out near the end of the window gets told to wait far longer than
// necessary.
func TestLoginAttemptLimiter_IsLocked_ReturnsRealRemainingTime(t *testing.T) {
	rdb, mr := testutil.RedisClientAndServer(t)
	l := auth.NewLoginAttemptLimiter(rdb, 1, 10*time.Minute)

	if err := l.RecordFailure(t.Context(), "client1", "a@b.com"); err != nil {
		t.Fatalf("RecordFailure: %v", err)
	}

	// 6 of the 10 minutes have already passed — at most 4 should remain.
	mr.FastForward(6 * time.Minute)

	locked, retryAfter, err := l.IsLocked(t.Context(), "client1", "a@b.com")
	if err != nil || !locked {
		t.Fatalf("IsLocked: locked=%v err=%v, want true, nil", locked, err)
	}
	if retryAfter <= 0 || retryAfter > 4*time.Minute {
		t.Fatalf("retryAfter = %v, want something in (0, 4m] (real remaining time, not the full 10m window)", retryAfter)
	}
}

func TestLoginAttemptLimiter_WindowExpires(t *testing.T) {
	rdb, mr := testutil.RedisClientAndServer(t)
	l := auth.NewLoginAttemptLimiter(rdb, 1, time.Minute)

	if err := l.RecordFailure(t.Context(), "client1", "a@b.com"); err != nil {
		t.Fatalf("RecordFailure: %v", err)
	}
	if locked, _, err := l.IsLocked(t.Context(), "client1", "a@b.com"); err != nil || !locked {
		t.Fatalf("before window expiry: locked=%v err=%v, want true, nil", locked, err)
	}

	mr.FastForward(time.Minute + time.Second)

	if locked, _, err := l.IsLocked(t.Context(), "client1", "a@b.com"); err != nil || locked {
		t.Fatalf("after window expiry: locked=%v err=%v, want false, nil", locked, err)
	}
}
