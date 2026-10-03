package device_test

import (
	"testing"
	"time"

	"auth-2fa-api/internal/device"
	"auth-2fa-api/internal/testutil"
)

func newTestDeviceService(t *testing.T) (*device.Service, string) {
	t.Helper()
	pool := testutil.PostgresPool(t)
	client, _ := testutil.NewAPIClient(t, pool)
	u := testutil.NewUser(t, pool, client.ID, "correcthorsebattery")
	svc := device.NewService(device.NewRepository(pool), 30*24*time.Hour)
	return svc, u.ID
}

// Register no longer takes a PIN — the account PIN that gates a device
// lives in user.Service now (see auth.Service.RegisterDevice, which checks
// it separately before calling this).
func TestRegister_IssuesTokenAndListsDevice(t *testing.T) {
	svc, userID := newTestDeviceService(t)
	deviceID := "device-" + testutil.UniqueSuffix(t)

	token, err := svc.Register(t.Context(), userID, deviceID, "Test")
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	if token == "" {
		t.Fatal("Register: want a non-empty device token")
	}

	list, err := svc.List(t.Context(), userID)
	if err != nil || len(list) != 1 {
		t.Fatalf("List: list=%v err=%v", list, err)
	}
}

func TestVerifyToken_Success(t *testing.T) {
	svc, userID := newTestDeviceService(t)
	deviceID := "device-" + testutil.UniqueSuffix(t)

	token, err := svc.Register(t.Context(), userID, deviceID, "Test")
	if err != nil {
		t.Fatalf("Register: %v", err)
	}

	d, err := svc.VerifyToken(t.Context(), deviceID, token)
	if err != nil {
		t.Fatalf("VerifyToken: %v", err)
	}
	if d.UserID != userID {
		t.Fatalf("VerifyToken userID = %q, want %q", d.UserID, userID)
	}
}

func TestVerifyToken_UnknownDevice(t *testing.T) {
	svc, _ := newTestDeviceService(t)
	if _, err := svc.VerifyToken(t.Context(), "does-not-exist", "sometoken"); err != device.ErrDeviceNotTrusted {
		t.Fatalf("err = %v, want %v", err, device.ErrDeviceNotTrusted)
	}
}

func TestVerifyToken_WrongToken(t *testing.T) {
	svc, userID := newTestDeviceService(t)
	deviceID := "device-" + testutil.UniqueSuffix(t)
	if _, err := svc.Register(t.Context(), userID, deviceID, "Test"); err != nil {
		t.Fatalf("Register: %v", err)
	}

	if _, err := svc.VerifyToken(t.Context(), deviceID, "wrong-token"); err != device.ErrDeviceNotTrusted {
		t.Fatalf("wrong device token: err = %v, want %v", err, device.ErrDeviceNotTrusted)
	}
}

// RotateToken issues a fresh token and invalidates the previous one — the
// shape auth.Service.DeviceLogin relies on after the account PIN checks out.
func TestRotateToken_IssuesFreshTokenAndInvalidatesOld(t *testing.T) {
	svc, userID := newTestDeviceService(t)
	deviceID := "device-" + testutil.UniqueSuffix(t)
	token, err := svc.Register(t.Context(), userID, deviceID, "Test")
	if err != nil {
		t.Fatalf("Register: %v", err)
	}

	d, err := svc.VerifyToken(t.Context(), deviceID, token)
	if err != nil {
		t.Fatalf("VerifyToken: %v", err)
	}
	newToken, err := svc.RotateToken(t.Context(), d.ID)
	if err != nil {
		t.Fatalf("RotateToken: %v", err)
	}
	if newToken == "" || newToken == token {
		t.Fatal("RotateToken: expected a fresh token distinct from the original")
	}

	if _, err := svc.VerifyToken(t.Context(), deviceID, token); err != device.ErrDeviceNotTrusted {
		t.Fatalf("old token after rotation: err = %v, want %v", err, device.ErrDeviceNotTrusted)
	}
	if _, err := svc.VerifyToken(t.Context(), deviceID, newToken); err != nil {
		t.Fatalf("new token after rotation: unexpected error %v", err)
	}
}

func TestRegister_ReRegisteringSameDeviceIDIssuesFreshToken(t *testing.T) {
	svc, userID := newTestDeviceService(t)
	deviceID := "device-" + testutil.UniqueSuffix(t)

	firstToken, err := svc.Register(t.Context(), userID, deviceID, "Test")
	if err != nil {
		t.Fatalf("first Register: %v", err)
	}
	secondToken, err := svc.Register(t.Context(), userID, deviceID, "Test")
	if err != nil {
		t.Fatalf("second Register (same device_id): %v", err)
	}
	if secondToken == firstToken {
		t.Fatal("re-registering must issue a fresh device token")
	}

	if _, err := svc.VerifyToken(t.Context(), deviceID, firstToken); err != device.ErrDeviceNotTrusted {
		t.Fatalf("stale token after re-register: err = %v, want %v", err, device.ErrDeviceNotTrusted)
	}
	if _, err := svc.VerifyToken(t.Context(), deviceID, secondToken); err != nil {
		t.Fatalf("new token after re-register: unexpected error %v", err)
	}
}

func TestListAndRevoke(t *testing.T) {
	svc, userID := newTestDeviceService(t)
	deviceID := "device-" + testutil.UniqueSuffix(t)
	if _, err := svc.Register(t.Context(), userID, deviceID, "My Phone"); err != nil {
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
