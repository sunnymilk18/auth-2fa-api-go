package auth_test

import (
	"sync"
	"testing"
	"time"

	"auth-2fa-api/internal/auth"
	"auth-2fa-api/internal/testutil"
)

func newTestPushLoginStore(t *testing.T) *auth.PushLoginStore {
	t.Helper()
	rdb := testutil.RedisClient(t)
	return auth.NewPushLoginStore(rdb, time.Minute)
}

func TestPushLoginStore_Answer_Correct(t *testing.T) {
	store := newTestPushLoginStore(t)
	const loginToken = "tok-1"
	if err := store.Start(t.Context(), loginToken, "user1", "client1", "a@b.com", 42); err != nil {
		t.Fatalf("Start: %v", err)
	}

	sess, found, err := store.Peek(t.Context(), loginToken)
	if err != nil || !found {
		t.Fatalf("Peek: found=%v err=%v", found, err)
	}
	if sess.UserID != "user1" || sess.APIClientID != "client1" || sess.Email != "a@b.com" {
		t.Fatalf("Peek session = %+v, want matching user1/client1/a@b.com", sess)
	}

	status, err := store.Answer(t.Context(), loginToken, 42)
	if err != nil {
		t.Fatalf("Answer: %v", err)
	}
	if status != "approved" {
		t.Fatalf("status = %q, want approved", status)
	}
}

func TestPushLoginStore_Answer_Wrong(t *testing.T) {
	store := newTestPushLoginStore(t)
	const loginToken = "tok-2"
	if err := store.Start(t.Context(), loginToken, "user1", "client1", "a@b.com", 42); err != nil {
		t.Fatalf("Start: %v", err)
	}

	status, err := store.Answer(t.Context(), loginToken, 7)
	if err != nil {
		t.Fatalf("Answer: %v", err)
	}
	if status != "rejected" {
		t.Fatalf("status = %q, want rejected", status)
	}
}

// A wrong tap must be final — retrying with the correct number afterwards
// must not flip a rejected request back to approved. This is the entire
// point of the number-matching mitigation (see push_login_store.go's own
// doc comments): without it, an attacker who doesn't know the real number
// could just try all three.
func TestPushLoginStore_Answer_WrongThenCorrectDoesNotOverturn(t *testing.T) {
	store := newTestPushLoginStore(t)
	const loginToken = "tok-3"
	if err := store.Start(t.Context(), loginToken, "user1", "client1", "a@b.com", 42); err != nil {
		t.Fatalf("Start: %v", err)
	}

	if status, err := store.Answer(t.Context(), loginToken, 7); err != nil || status != "rejected" {
		t.Fatalf("first Answer: status=%q err=%v, want rejected", status, err)
	}
	status, err := store.Answer(t.Context(), loginToken, 42)
	if err != nil {
		t.Fatalf("second Answer: %v", err)
	}
	if status != "rejected" {
		t.Fatalf("second Answer status = %q, want still rejected (first answer is final)", status)
	}
}

func TestPushLoginStore_Answer_UnknownRequest(t *testing.T) {
	store := newTestPushLoginStore(t)
	if _, err := store.Answer(t.Context(), "does-not-exist", 42); err != auth.ErrLoginSessionNotFound {
		t.Fatalf("err = %v, want %v", err, auth.ErrLoginSessionNotFound)
	}
}

func TestPushLoginStore_Peek_UnknownRequest(t *testing.T) {
	store := newTestPushLoginStore(t)
	_, found, err := store.Peek(t.Context(), "does-not-exist")
	if err != nil {
		t.Fatalf("Peek: %v", err)
	}
	if found {
		t.Fatal("Peek found = true, want false for an unknown request id")
	}
}

func TestPushLoginStore_Consume_RemovesSession(t *testing.T) {
	store := newTestPushLoginStore(t)
	const loginToken = "tok-4"
	if err := store.Start(t.Context(), loginToken, "user1", "client1", "a@b.com", 42); err != nil {
		t.Fatalf("Start: %v", err)
	}
	if err := store.Consume(t.Context(), loginToken); err != nil {
		t.Fatalf("Consume: %v", err)
	}
	if _, found, err := store.Peek(t.Context(), loginToken); err != nil || found {
		t.Fatalf("Peek after Consume: found=%v err=%v, want false/nil", found, err)
	}
}

// Concurrent answers racing against each other must still resolve to
// exactly one final status — same reasoning as otp.go's own concurrent-guess
// test, but here the stakes are worse: this is specifically the mechanism
// meant to stop MFA-fatigue-style attacks, so it has to be genuinely atomic,
// not just "usually fine".
func TestPushLoginStore_Answer_ConcurrentRaceResolvesOnce(t *testing.T) {
	store := newTestPushLoginStore(t)
	const loginToken = "tok-5"
	if err := store.Start(t.Context(), loginToken, "user1", "client1", "a@b.com", 42); err != nil {
		t.Fatalf("Start: %v", err)
	}

	const n = 20
	results := make([]string, n)
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			// Half the racers guess correctly, half don't — whichever
			// answer lands first (correct or not) must be the one that
			// sticks for every other racer too.
			guess := 42
			if i%2 == 0 {
				guess = 7
			}
			status, err := store.Answer(t.Context(), loginToken, guess)
			if err != nil {
				t.Errorf("Answer: %v", err)
				return
			}
			results[i] = string(status)
		}(i)
	}
	wg.Wait()

	first := results[0]
	for i, r := range results {
		if r != first {
			t.Fatalf("result %d = %q, want %q (every racer must see the same final status)", i, r, first)
		}
	}
}
