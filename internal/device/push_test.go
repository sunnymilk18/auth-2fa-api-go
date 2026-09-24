package device_test

import (
	"testing"

	"auth-2fa-api/internal/testutil"
)

func TestEnableDisablePush_RoundTrip(t *testing.T) {
	svc, userID := newTestDeviceService(t, 3)
	deviceID := "device-" + testutil.UniqueSuffix(t)

	if _, err := svc.Register(t.Context(), userID, deviceID, "Test", "123456"); err != nil {
		t.Fatalf("Register: %v", err)
	}

	infos, err := svc.List(t.Context(), userID)
	if err != nil || len(infos) != 1 {
		t.Fatalf("List: infos=%v err=%v", infos, err)
	}
	rowID := infos[0].ID
	if infos[0].PushEnabled {
		t.Fatal("newly registered device should not have push enabled yet")
	}

	if err := svc.EnablePush(t.Context(), userID, rowID, "fake-fcm-token"); err != nil {
		t.Fatalf("EnablePush: %v", err)
	}

	capable, err := svc.PushCapableDevices(t.Context(), userID)
	if err != nil || len(capable) != 1 || capable[0].ID != rowID {
		t.Fatalf("PushCapableDevices after enable: capable=%v err=%v", capable, err)
	}

	infos, err = svc.List(t.Context(), userID)
	if err != nil || len(infos) != 1 || !infos[0].PushEnabled {
		t.Fatalf("List after enable: infos=%v err=%v", infos, err)
	}

	if err := svc.DisablePush(t.Context(), userID, rowID); err != nil {
		t.Fatalf("DisablePush: %v", err)
	}

	capable, err = svc.PushCapableDevices(t.Context(), userID)
	if err != nil || len(capable) != 0 {
		t.Fatalf("PushCapableDevices after disable: capable=%v err=%v, want empty", capable, err)
	}

	infos, err = svc.List(t.Context(), userID)
	if err != nil || len(infos) != 1 || infos[0].PushEnabled {
		t.Fatalf("List after disable: infos=%v err=%v, want PushEnabled=false", infos, err)
	}
}
