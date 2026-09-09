package device_test

import (
	"testing"
	"time"

	"auth-2fa-api/internal/device"
	"auth-2fa-api/internal/testutil"
)

func newTestDeviceService(t *testing.T, maxPinTries int) (*device.Service, string) {
	t.Helper()
	pool := testutil.PostgresPool(t)
	client, _ := testutil.NewAPIClient(t, pool)
	u := testutil.NewUser(t, pool, client.ID, "correcthorsebattery")
	svc := device.NewService(device.NewRepository(pool), 30*24*time.Hour, maxPinTries)
	return svc, u.ID
}

func TestRegister_RejectsMalformedPin(t *testing.T) {
	svc, userID := newTestDeviceService(t, 3)
	deviceID := "device-" + testutil.UniqueSuffix(t)

	for _, pin := range []string{"", "12345", "1234567", "abcdef", "12 345"} {
		if _, err := svc.Register(t.Context(), userID, deviceID, "Test", pin); err != device.ErrInvalidPinFormat {
			t.Errorf("Register with pin %q: err = %v, want %v", pin, err, device.ErrInvalidPinFormat)
		}
	}
}

func TestVerifyPin_Success(t *testing.T) {
	svc, userID := newTestDeviceService(t, 3)
	deviceID := "device-" + testutil.UniqueSuffix(t)

	token, err := svc.Register(t.Context(), userID, deviceID, "Test", "123456")
	if err != nil {
		t.Fatalf("Register: %v", err)
	}

	gotUserID, newToken, err := svc.VerifyPin(t.Context(), deviceID, token, "123456")
	if err != nil {
		t.Fatalf("VerifyPin: %v", err)
	}
	if gotUserID != userID {
		t.Fatalf("VerifyPin userID = %q, want %q", gotUserID, userID)
	}
	if newToken == "" || newToken == token {
		t.Fatal("VerifyPin: expected a fresh device token distinct from the original")
	}
}

func TestVerifyPin_UnknownDevice(t *testing.T) {
	svc, _ := newTestDeviceService(t, 3)
	if _, _, err := svc.VerifyPin(t.Context(), "does-not-exist", "sometoken", "123456"); err != device.ErrDeviceNotTrusted {
		t.Fatalf("err = %v, want %v", err, device.ErrDeviceNotTrusted)
	}
}

func TestVerifyPin_WrongDeviceToken(t *testing.T) {
	svc, userID := newTestDeviceService(t, 3)
	deviceID := "device-" + testutil.UniqueSuffix(t)
	if _, err := svc.Register(t.Context(), userID, deviceID, "Test", "123456"); err != nil {
		t.Fatalf("Register: %v", err)
	}

	if _, _, err := svc.VerifyPin(t.Context(), deviceID, "wrong-token", "123456"); err != device.ErrDeviceNotTrusted {
		t.Fatalf("wrong device token: err = %v, want %v", err, device.ErrDeviceNotTrusted)
	}
}

func TestVerifyPin_TooManyFailuresRevokes(t *testing.T) {
	svc, userID := newTestDeviceService(t, 2)
	deviceID := "device-" + testutil.UniqueSuffix(t)
	token, err := svc.Register(t.Context(), userID, deviceID, "Test", "123456")
	if err != nil {
		t.Fatalf("Register: %v", err)
	}

	if _, _, err := svc.VerifyPin(t.Context(), deviceID, token, "000000"); err != device.ErrInvalidPin {
		t.Fatalf("attempt 1: err = %v, want %v", err, device.ErrInvalidPin)
	}
	if _, _, err := svc.VerifyPin(t.Context(), deviceID, token, "000000"); err != device.ErrTooManyPinTries {
		t.Fatalf("attempt 2 (maxPinTries=2): err = %v, want %v", err, device.ErrTooManyPinTries)
	}
	// Revoked now — even the right PIN with the right token is rejected.
	if _, _, err := svc.VerifyPin(t.Context(), deviceID, token, "123456"); err != device.ErrDeviceNotTrusted {
		t.Fatalf("correct pin after revocation: err = %v, want %v", err, device.ErrDeviceNotTrusted)
	}
}

func TestVerifyPin_SuccessResetsFailedAttempts(t *testing.T) {
	svc, userID := newTestDeviceService(t, 3)
	deviceID := "device-" + testutil.UniqueSuffix(t)
	token, err := svc.Register(t.Context(), userID, deviceID, "Test", "123456")
	if err != nil {
		t.Fatalf("Register: %v", err)
	}

	// One failed attempt, then a success — the counter must reset, so two
	// more failed attempts afterward shouldn't trip a maxPinTries=3 limit
	// on their own (1 failed + 2 failed = 3 total, but not consecutive
	// since a success happened in between).
	if _, _, err := svc.VerifyPin(t.Context(), deviceID, token, "000000"); err != device.ErrInvalidPin {
		t.Fatalf("first failed attempt: err = %v, want %v", err, device.ErrInvalidPin)
	}
	_, rotated, err := svc.VerifyPin(t.Context(), deviceID, token, "123456")
	if err != nil {
		t.Fatalf("successful attempt: %v", err)
	}
	if _, _, err := svc.VerifyPin(t.Context(), deviceID, rotated, "000000"); err != device.ErrInvalidPin {
		t.Fatalf("failed attempt after success: err = %v, want %v (counter should have reset)", err, device.ErrInvalidPin)
	}
}

func TestRegister_ReRegisteringSameDeviceIDResetsTrust(t *testing.T) {
	svc, userID := newTestDeviceService(t, 2)
	deviceID := "device-" + testutil.UniqueSuffix(t)

	firstToken, err := svc.Register(t.Context(), userID, deviceID, "Test", "111111")
	if err != nil {
		t.Fatalf("first Register: %v", err)
	}
	// Rack up a failed attempt so failed_pin_attempts > 0 before re-registering.
	if _, _, err := svc.VerifyPin(t.Context(), deviceID, firstToken, "000000"); err != device.ErrInvalidPin {
		t.Fatalf("failed attempt: err = %v, want %v", err, device.ErrInvalidPin)
	}

	secondToken, err := svc.Register(t.Context(), userID, deviceID, "Test", "222222")
	if err != nil {
		t.Fatalf("second Register (same device_id): %v", err)
	}
	if secondToken == firstToken {
		t.Fatal("re-registering must issue a fresh device token")
	}

	// The old token+pin no longer work; the new ones do, and the failed
	// attempt counter was reset by the upsert.
	if _, _, err := svc.VerifyPin(t.Context(), deviceID, firstToken, "111111"); err != device.ErrDeviceNotTrusted {
		t.Fatalf("stale token after re-register: err = %v, want %v", err, device.ErrDeviceNotTrusted)
	}
	if _, _, err := svc.VerifyPin(t.Context(), deviceID, secondToken, "222222"); err != nil {
		t.Fatalf("new token+pin after re-register: unexpected error %v", err)
	}
}

func TestListAndRevoke(t *testing.T) {
	svc, userID := newTestDeviceService(t, 3)
	deviceID := "device-" + testutil.UniqueSuffix(t)
	if _, err := svc.Register(t.Context(), userID, deviceID, "My Phone", "123456"); err != nil {
		t.Fatalf("Register: %v", err)
	}

	list, err := svc.List(t.Context(), userID)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(list) != 1 || list[0].DeviceName != "My Phone" {
		t.Fatalf("List = %+v, want exactly one device named %q", list, "My Phone")
	}

	// A different user can't revoke someone else's device.
	otherUserID := "00000000-0000-0000-0000-000000000000"
	if err := svc.Revoke(t.Context(), otherUserID, list[0].ID); err != device.ErrNotFound {
		t.Fatalf("Revoke by wrong owner: err = %v, want %v", err, device.ErrNotFound)
	}

	if err := svc.Revoke(t.Context(), userID, list[0].ID); err != nil {
		t.Fatalf("Revoke by owner: %v", err)
	}
	listAfter, err := svc.List(t.Context(), userID)
	if err != nil {
		t.Fatalf("List after revoke: %v", err)
	}
	if len(listAfter) != 0 {
		t.Fatalf("List after revoke = %+v, want empty (revoked devices aren't listed)", listAfter)
	}
}
