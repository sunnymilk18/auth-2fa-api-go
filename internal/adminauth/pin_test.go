package adminauth_test

import (
	"errors"
	"testing"

	"auth-2fa-api/internal/adminauth"
)

func TestService_SetPin_CreatesWhenNoneExists(t *testing.T) {
	svc, pool := newTestService(t)
	ctx := t.Context()

	account, _ := createTestAccount(t, svc, pool, "correct-horse-battery")

	if has, err := svc.HasPin(ctx, account.Email); err != nil || has {
		t.Fatalf("HasPin before SetPin = (%v, %v), want (false, nil)", has, err)
	}

	created, err := svc.SetPin(ctx, account.Email, "correct-horse-battery", "", "123456")
	if err != nil {
		t.Fatalf("SetPin (create): %v", err)
	}
	if !created {
		t.Fatal("SetPin (create) reported created=false, want true — no PIN existed before this call")
	}

	if has, err := svc.HasPin(ctx, account.Email); err != nil || !has {
		t.Fatalf("HasPin after SetPin = (%v, %v), want (true, nil)", has, err)
	}
	if ok, notSet, _, err := svc.VerifyAdminPin(ctx, account.Email, "123456"); err != nil || notSet || !ok {
		t.Fatalf("VerifyAdminPin(correct) after create = (ok=%v, notSet=%v, err=%v), want (true, false, nil)", ok, notSet, err)
	}
}

func TestService_SetPin_WrongPasswordWhenCreating(t *testing.T) {
	svc, pool := newTestService(t)
	ctx := t.Context()

	account, _ := createTestAccount(t, svc, pool, "correct-horse-battery")

	if _, err := svc.SetPin(ctx, account.Email, "wrong-password", "", "123456"); !errors.Is(err, adminauth.ErrCurrentPasswordIncorrect) {
		t.Fatalf("SetPin (create, wrong password): err = %v, want ErrCurrentPasswordIncorrect", err)
	}
	if has, err := svc.HasPin(ctx, account.Email); err != nil || has {
		t.Fatalf("HasPin after a refused create = (%v, %v), want (false, nil)", has, err)
	}
}

func TestService_SetPin_ChangesExistingWithCurrentPin(t *testing.T) {
	svc, pool := newTestService(t)
	ctx := t.Context()

	account, _ := createTestAccount(t, svc, pool, "correct-horse-battery")
	if _, err := svc.SetPin(ctx, account.Email, "correct-horse-battery", "", "123456"); err != nil {
		t.Fatalf("SetPin (create): %v", err)
	}

	created, err := svc.SetPin(ctx, account.Email, "", "123456", "654321")
	if err != nil {
		t.Fatalf("SetPin (change): %v", err)
	}
	if created {
		t.Fatal("SetPin (change) reported created=true, want false — a PIN already existed")
	}

	if ok, _, _, err := svc.VerifyAdminPin(ctx, account.Email, "123456"); err != nil || ok {
		t.Fatalf("VerifyAdminPin(old pin) after change = (ok=%v, err=%v), want (false, nil)", ok, err)
	}
	if ok, notSet, _, err := svc.VerifyAdminPin(ctx, account.Email, "654321"); err != nil || notSet || !ok {
		t.Fatalf("VerifyAdminPin(new pin) after change = (ok=%v, notSet=%v, err=%v), want (true, false, nil)", ok, notSet, err)
	}
}

func TestService_SetPin_WrongCurrentPinWhenChanging(t *testing.T) {
	svc, pool := newTestService(t)
	ctx := t.Context()

	account, _ := createTestAccount(t, svc, pool, "correct-horse-battery")
	if _, err := svc.SetPin(ctx, account.Email, "correct-horse-battery", "", "123456"); err != nil {
		t.Fatalf("SetPin (create): %v", err)
	}

	if _, err := svc.SetPin(ctx, account.Email, "", "wrong-pin", "654321"); !errors.Is(err, adminauth.ErrCurrentPinIncorrect) {
		t.Fatalf("SetPin (change, wrong current pin): err = %v, want ErrCurrentPinIncorrect", err)
	}

	// Nothing changed — the original PIN still works.
	if ok, _, _, err := svc.VerifyAdminPin(ctx, account.Email, "123456"); err != nil || !ok {
		t.Fatalf("VerifyAdminPin(original pin) after a refused change = (ok=%v, err=%v), want (true, nil)", ok, err)
	}
}

func TestService_VerifyAdminPin_NotSetWhenNoPin(t *testing.T) {
	svc, pool := newTestService(t)
	ctx := t.Context()

	account, _ := createTestAccount(t, svc, pool, "correct-horse-battery")

	ok, notSet, retryAfter, err := svc.VerifyAdminPin(ctx, account.Email, "123456")
	if err != nil || ok || !notSet || retryAfter != 0 {
		t.Fatalf("VerifyAdminPin with no PIN configured = (ok=%v, notSet=%v, retryAfter=%v, err=%v), want (false, true, 0, nil)", ok, notSet, retryAfter, err)
	}
}

func TestService_VerifyAdminPin_WrongPin(t *testing.T) {
	svc, pool := newTestService(t)
	ctx := t.Context()

	account, _ := createTestAccount(t, svc, pool, "correct-horse-battery")
	if _, err := svc.SetPin(ctx, account.Email, "correct-horse-battery", "", "123456"); err != nil {
		t.Fatalf("SetPin (create): %v", err)
	}

	ok, notSet, retryAfter, err := svc.VerifyAdminPin(ctx, account.Email, "000000")
	if err != nil || ok || notSet || retryAfter != 0 {
		t.Fatalf("VerifyAdminPin(wrong pin) = (ok=%v, notSet=%v, retryAfter=%v, err=%v), want (false, false, 0, nil)", ok, notSet, retryAfter, err)
	}
}

// A stolen session shouldn't be able to exhaust the LOGIN or self-service
// counters by spamming wrong PIN guesses here, nor should repeated wrong
// PIN guesses lock out the password/TOTP self-service flows — see
// pinLimiterNamespace's doc comment. This proves the three counters are
// actually separate, not just separately named (mirrors
// TestService_ChangeOwnPassword_TooManyFailures_DoesNotLockLogin).
func TestService_VerifyAdminPin_TooManyFailures_IsolatedCounter(t *testing.T) {
	svc, pool := newTestService(t)
	ctx := t.Context()

	account, secret := createTestAccount(t, svc, pool, "correct-horse-battery")
	if _, err := svc.SetPin(ctx, account.Email, "correct-horse-battery", "", "123456"); err != nil {
		t.Fatalf("SetPin (create): %v", err)
	}

	var lastRetryAfter int64
	for i := 0; i < 5; i++ {
		_, _, retryAfter, err := svc.VerifyAdminPin(ctx, account.Email, "000000")
		if err != nil {
			t.Fatalf("VerifyAdminPin(wrong pin) attempt %d: %v", i, err)
		}
		lastRetryAfter = int64(retryAfter)
	}
	if lastRetryAfter <= 0 {
		t.Fatal("VerifyAdminPin after repeated wrong guesses never reported a lockout (retryAfter == 0)")
	}

	// Login, and the password self-service flow, are each a separate
	// counter and must still work.
	if _, _, err := svc.Login(ctx, account.Email, "correct-horse-battery", currentCode(t, secret)); err != nil {
		t.Fatalf("Login after the pin counter locked: %v, want it to still work (separate counter)", err)
	}
	if err := svc.ChangeOwnPassword(ctx, account.Email, "whatever-token", "correct-horse-battery", "new-password-1"); err != nil {
		t.Fatalf("ChangeOwnPassword after the pin counter locked: %v, want it to still work (separate counter)", err)
	}
}

func TestService_ResetPin_ClearsPin(t *testing.T) {
	svc, pool := newTestService(t)
	ctx := t.Context()

	account, _ := createTestAccount(t, svc, pool, "correct-horse-battery")
	if _, err := svc.SetPin(ctx, account.Email, "correct-horse-battery", "", "123456"); err != nil {
		t.Fatalf("SetPin (create): %v", err)
	}

	if err := svc.ResetPin(ctx, account.ID); err != nil {
		t.Fatalf("ResetPin: %v", err)
	}

	if has, err := svc.HasPin(ctx, account.Email); err != nil || has {
		t.Fatalf("HasPin after ResetPin = (%v, %v), want (false, nil)", has, err)
	}
	if ok, notSet, _, err := svc.VerifyAdminPin(ctx, account.Email, "123456"); err != nil || ok || !notSet {
		t.Fatalf("VerifyAdminPin after ResetPin = (ok=%v, notSet=%v, err=%v), want (false, true, nil)", ok, notSet, err)
	}
}

// A PIN lockout from guesses against the OLD PIN must not carry over to a
// brand-new one created right after ResetPin — same reasoning as
// ReactivateAccount resetting loginLimiterNamespace for fresh credentials.
func TestService_ResetPin_ThenSetPin_DoesNotInheritStaleLockout(t *testing.T) {
	svc, pool := newTestService(t)
	ctx := t.Context()

	account, _ := createTestAccount(t, svc, pool, "correct-horse-battery")
	if _, err := svc.SetPin(ctx, account.Email, "correct-horse-battery", "", "123456"); err != nil {
		t.Fatalf("SetPin (create): %v", err)
	}

	// Lock the pin counter out with wrong guesses against the OLD pin.
	var lastRetryAfter int64
	for i := 0; i < 5; i++ {
		_, _, retryAfter, err := svc.VerifyAdminPin(ctx, account.Email, "000000")
		if err != nil {
			t.Fatalf("VerifyAdminPin(wrong pin) attempt %d: %v", i, err)
		}
		lastRetryAfter = int64(retryAfter)
	}
	if lastRetryAfter <= 0 {
		t.Fatal("setup: never got locked out against the old pin")
	}

	if err := svc.ResetPin(ctx, account.ID); err != nil {
		t.Fatalf("ResetPin: %v", err)
	}
	if _, err := svc.SetPin(ctx, account.Email, "correct-horse-battery", "", "654321"); err != nil {
		t.Fatalf("SetPin (create, after reset): %v", err)
	}

	ok, notSet, retryAfter, err := svc.VerifyAdminPin(ctx, account.Email, "654321")
	if err != nil || notSet || retryAfter != 0 || !ok {
		t.Fatalf("VerifyAdminPin(new pin) right after reset+recreate = (ok=%v, notSet=%v, retryAfter=%v, err=%v), want (true, false, 0, nil) — must not inherit the old PIN's lockout", ok, notSet, retryAfter, err)
	}
}

func TestService_ResetPin_UnknownAccount(t *testing.T) {
	svc, _ := newTestService(t)
	ctx := t.Context()

	if err := svc.ResetPin(ctx, "00000000-0000-0000-0000-000000000000"); !errors.Is(err, adminauth.ErrNotFound) {
		t.Fatalf("ResetPin(unknown account): err = %v, want ErrNotFound", err)
	}
}

// ReactivateAccount clears the PIN as part of a full reactivation — same
// "start over with no PIN" rule as a brand-new account, see
// AccountRepository.Reprovision's doc comment.
func TestService_ReactivateAccount_ClearsPin(t *testing.T) {
	svc, pool := newTestService(t)
	ctx := t.Context()

	account, _ := createTestAccount(t, svc, pool, "old-password-1")
	if _, err := svc.SetPin(ctx, account.Email, "old-password-1", "", "123456"); err != nil {
		t.Fatalf("SetPin (create): %v", err)
	}
	if err := svc.RevokeAccount(ctx, "", account.ID); err != nil {
		t.Fatalf("RevokeAccount: %v", err)
	}

	if _, _, err := svc.ReactivateAccount(ctx, account.ID, "new-password-1"); err != nil {
		t.Fatalf("ReactivateAccount: %v", err)
	}

	if has, err := svc.HasPin(ctx, account.Email); err != nil || has {
		t.Fatalf("HasPin after reactivation = (%v, %v), want (false, nil) — reactivating must clear the old PIN", has, err)
	}
}
