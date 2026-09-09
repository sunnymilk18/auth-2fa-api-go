package auth_test

// These tests hit auth.Handlers directly over HTTP (httptest), the same
// contract the Flutter client's ApiClient depends on: status codes and the
// exact JSON shape of each response. They wire a real Service (real
// Postgres + in-memory Redis + a fake mailer) but skip the chi router and
// its middleware — API-client/user identity is injected into the request
// context directly, standing in for what RequireAPIKey/RequireAuth would
// have set.

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"

	"auth-2fa-api/internal/auth"
	"auth-2fa-api/internal/testutil"
)

func newTestHandlers(t *testing.T) (*auth.Handlers, *auth.Service, *auth.TokenManager, *testutil.FakeMailer, string) {
	t.Helper()
	svc, tokens, mailer, apiClientID := newTestService(t)
	return auth.NewHandlers(svc), svc, tokens, mailer, apiClientID
}

func withAPIClient(req *http.Request, apiClientID string) *http.Request {
	return req.WithContext(auth.ContextWithAPIClient(req.Context(), apiClientID))
}

func withUser(req *http.Request, userID, email string) *http.Request {
	return req.WithContext(auth.ContextWithUser(req.Context(), userID, email))
}

func jsonBody(t *testing.T, v any) *bytes.Buffer {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshaling request body: %v", err)
	}
	return bytes.NewBuffer(b)
}

func decodeJSON(t *testing.T, rec *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var out map[string]any
	if rec.Body.Len() == 0 {
		return out
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("decoding response body %q: %v", rec.Body.String(), err)
	}
	return out
}

// --- Register ---

func TestHandler_Register_InvalidBody(t *testing.T) {
	h, _, _, _, apiClientID := newTestHandlers(t)
	req := withAPIClient(httptest.NewRequest(http.MethodPost, "/auth/register", bytes.NewBufferString("not json")), apiClientID)
	rec := httptest.NewRecorder()

	h.Register(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusBadRequest)
	}
}

func TestHandler_Register_ShortPassword(t *testing.T) {
	h, _, _, _, apiClientID := newTestHandlers(t)
	body := jsonBody(t, map[string]string{"email": "a@example.com", "password": "short"})
	req := withAPIClient(httptest.NewRequest(http.MethodPost, "/auth/register", body), apiClientID)
	rec := httptest.NewRecorder()

	h.Register(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusBadRequest)
	}
	resp := decodeJSON(t, rec)
	if _, ok := resp["error"]; !ok {
		t.Fatalf("response %v missing \"error\" field", resp)
	}
}

func TestHandler_Register_MissingAPIClientContext(t *testing.T) {
	h, _, _, _, _ := newTestHandlers(t)
	body := jsonBody(t, map[string]string{"email": "a@example.com", "password": "correcthorsebattery"})
	req := httptest.NewRequest(http.MethodPost, "/auth/register", body) // no withAPIClient
	rec := httptest.NewRecorder()

	h.Register(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusUnauthorized)
	}
}

func TestHandler_Register_Success(t *testing.T) {
	h, _, _, _, apiClientID := newTestHandlers(t)
	email := "user-" + testutil.UniqueSuffix(t) + "@example.com"
	body := jsonBody(t, map[string]string{"email": email, "password": "correcthorsebattery"})
	req := withAPIClient(httptest.NewRequest(http.MethodPost, "/auth/register", body), apiClientID)
	rec := httptest.NewRecorder()

	h.Register(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, want %d, body=%s", rec.Code, http.StatusCreated, rec.Body.String())
	}
	resp := decodeJSON(t, rec)
	if resp["email"] != email {
		t.Fatalf("response email = %v, want %q", resp["email"], email)
	}
	if _, ok := resp["id"]; !ok {
		t.Fatalf("response %v missing \"id\" field", resp)
	}
}

func TestHandler_Register_DuplicateEmail(t *testing.T) {
	h, _, _, _, apiClientID := newTestHandlers(t)
	email := "user-" + testutil.UniqueSuffix(t) + "@example.com"
	body := func() *bytes.Buffer { return jsonBody(t, map[string]string{"email": email, "password": "correcthorsebattery"}) }

	h.Register(httptest.NewRecorder(), withAPIClient(httptest.NewRequest(http.MethodPost, "/auth/register", body()), apiClientID))

	rec := httptest.NewRecorder()
	h.Register(rec, withAPIClient(httptest.NewRequest(http.MethodPost, "/auth/register", body()), apiClientID))

	if rec.Code != http.StatusConflict {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusConflict)
	}
}

// --- Login (step 1) ---

func TestHandler_Login_WrongPassword(t *testing.T) {
	h, svc, _, _, apiClientID := newTestHandlers(t)
	email := "user-" + testutil.UniqueSuffix(t) + "@example.com"
	mustRegister(t, svc, apiClientID, email, "correcthorsebattery")

	body := jsonBody(t, map[string]string{"email": email, "password": "wrong"})
	req := withAPIClient(httptest.NewRequest(http.MethodPost, "/auth/login", body), apiClientID)
	rec := httptest.NewRecorder()

	h.Login(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusUnauthorized)
	}
}

func TestHandler_Login_Success(t *testing.T) {
	h, svc, _, _, apiClientID := newTestHandlers(t)
	email := "user-" + testutil.UniqueSuffix(t) + "@example.com"
	mustRegister(t, svc, apiClientID, email, "correcthorsebattery")

	body := jsonBody(t, map[string]string{"email": email, "password": "correcthorsebattery"})
	req := withAPIClient(httptest.NewRequest(http.MethodPost, "/auth/login", body), apiClientID)
	rec := httptest.NewRecorder()

	h.Login(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d, body=%s", rec.Code, http.StatusOK, rec.Body.String())
	}
	resp := decodeJSON(t, rec)
	if lt, _ := resp["login_token"].(string); lt == "" {
		t.Fatalf("response %v missing non-empty \"login_token\"", resp)
	}
}

// --- VerifyOTP (step 2) ---

func TestHandler_VerifyOTP_UnknownLoginToken(t *testing.T) {
	h, _, _, _, _ := newTestHandlers(t)
	body := jsonBody(t, map[string]string{"login_token": "does-not-exist", "code": "123456"})
	req := httptest.NewRequest(http.MethodPost, "/auth/verify-otp", body)
	rec := httptest.NewRecorder()

	h.VerifyOTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusUnauthorized)
	}
}

func TestHandler_VerifyOTP_Success(t *testing.T) {
	h, svc, _, mailer, apiClientID := newTestHandlers(t)
	email := "user-" + testutil.UniqueSuffix(t) + "@example.com"
	mustRegister(t, svc, apiClientID, email, "correcthorsebattery")

	loginToken, err := svc.LoginStep1(t.Context(), apiClientID, email, "correcthorsebattery")
	if err != nil {
		t.Fatalf("LoginStep1: %v", err)
	}
	sent, _ := mailer.Last()
	code := testutil.ExtractOTPCode(sent.Body)

	body := jsonBody(t, map[string]string{"login_token": loginToken, "code": code})
	req := httptest.NewRequest(http.MethodPost, "/auth/verify-otp", body)
	rec := httptest.NewRecorder()

	h.VerifyOTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d, body=%s", rec.Code, http.StatusOK, rec.Body.String())
	}
	resp := decodeJSON(t, rec)
	for _, field := range []string{"access_token", "refresh_token", "token_type"} {
		if s, _ := resp[field].(string); s == "" {
			t.Fatalf("response %v missing non-empty %q", resp, field)
		}
	}
}

// --- Refresh / Logout ---

func TestHandler_Refresh_InvalidToken(t *testing.T) {
	h, _, _, _, _ := newTestHandlers(t)
	body := jsonBody(t, map[string]string{"refresh_token": "garbage"})
	req := httptest.NewRequest(http.MethodPost, "/auth/refresh", body)
	rec := httptest.NewRecorder()

	h.Refresh(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusUnauthorized)
	}
}

func TestHandler_Logout_AlwaysNoContent(t *testing.T) {
	h, _, _, _, _ := newTestHandlers(t)
	// Logout revokes best-effort; even an unknown token returns 204, same
	// as the real Refresh.Revoke (an UPDATE matching zero rows isn't an
	// error) — matches the Flutter client's "best effort" logout comment.
	body := jsonBody(t, map[string]string{"refresh_token": "unknown-token"})
	req := httptest.NewRequest(http.MethodPost, "/auth/logout", body)
	rec := httptest.NewRecorder()

	h.Logout(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusNoContent)
	}
}

// --- Trusted device + PIN ---

func TestHandler_RegisterDevice_MissingUserContext(t *testing.T) {
	h, _, _, _, _ := newTestHandlers(t)
	body := jsonBody(t, map[string]string{"device_id": "d1", "device_name": "Phone", "pin": "123456"})
	req := httptest.NewRequest(http.MethodPost, "/auth/devices/register", body) // no withUser
	rec := httptest.NewRecorder()

	h.RegisterDevice(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusUnauthorized)
	}
}

func TestHandler_RegisterDevice_InvalidPinFormat(t *testing.T) {
	h, svc, _, _, apiClientID := newTestHandlers(t)
	email := "user-" + testutil.UniqueSuffix(t) + "@example.com"
	mustRegister(t, svc, apiClientID, email, "correcthorsebattery")

	// A bogus userID is fine: invalid pin format is rejected before the
	// handler ever touches the database.
	body := jsonBody(t, map[string]string{"device_id": "d1", "device_name": "Phone", "pin": "abc"})
	req := withUser(httptest.NewRequest(http.MethodPost, "/auth/devices/register", body), "some-user-id", email)
	rec := httptest.NewRecorder()

	h.RegisterDevice(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d, body=%s", rec.Code, http.StatusBadRequest, rec.Body.String())
	}
}

func TestHandler_DeviceLogin_And_List_And_Revoke(t *testing.T) {
	h, svc, tokens, mailer, apiClientID := newTestHandlers(t)
	email := "user-" + testutil.UniqueSuffix(t) + "@example.com"
	mustRegister(t, svc, apiClientID, email, "correcthorsebattery")

	loginToken, err := svc.LoginStep1(t.Context(), apiClientID, email, "correcthorsebattery")
	if err != nil {
		t.Fatalf("LoginStep1: %v", err)
	}
	sent, _ := mailer.Last()
	code := testutil.ExtractOTPCode(sent.Body)
	access, _, err := svc.LoginStep2(t.Context(), loginToken, code)
	if err != nil {
		t.Fatalf("LoginStep2: %v", err)
	}
	claims, err := tokens.ParseAccessToken(access)
	if err != nil {
		t.Fatalf("parsing access token: %v", err)
	}
	userID := claims.Subject

	// RegisterDevice
	deviceID := "d-" + testutil.UniqueSuffix(t)
	regBody := jsonBody(t, map[string]string{"device_id": deviceID, "device_name": "Phone", "pin": "123456"})
	regReq := withUser(httptest.NewRequest(http.MethodPost, "/auth/devices/register", regBody), userID, email)
	regRec := httptest.NewRecorder()
	h.RegisterDevice(regRec, regReq)
	if regRec.Code != http.StatusCreated {
		t.Fatalf("RegisterDevice status = %d, want %d, body=%s", regRec.Code, http.StatusCreated, regRec.Body.String())
	}
	deviceToken, _ := decodeJSON(t, regRec)["device_token"].(string)
	if deviceToken == "" {
		t.Fatal("RegisterDevice response missing device_token")
	}

	// DeviceLogin: wrong pin -> 401
	wrongBody := jsonBody(t, map[string]string{"device_id": deviceID, "device_token": deviceToken, "pin": "000000"})
	wrongReq := httptest.NewRequest(http.MethodPost, "/auth/devices/login", wrongBody)
	wrongRec := httptest.NewRecorder()
	h.DeviceLogin(wrongRec, wrongReq)
	if wrongRec.Code != http.StatusUnauthorized {
		t.Fatalf("DeviceLogin wrong pin status = %d, want %d", wrongRec.Code, http.StatusUnauthorized)
	}

	// DeviceLogin: success
	okBody := jsonBody(t, map[string]string{"device_id": deviceID, "device_token": deviceToken, "pin": "123456"})
	okReq := httptest.NewRequest(http.MethodPost, "/auth/devices/login", okBody)
	okRec := httptest.NewRecorder()
	h.DeviceLogin(okRec, okReq)
	if okRec.Code != http.StatusOK {
		t.Fatalf("DeviceLogin status = %d, want %d, body=%s", okRec.Code, http.StatusOK, okRec.Body.String())
	}
	loginResp := decodeJSON(t, okRec)
	for _, field := range []string{"access_token", "refresh_token", "device_token", "token_type"} {
		if s, _ := loginResp[field].(string); s == "" {
			t.Fatalf("DeviceLogin response %v missing non-empty %q", loginResp, field)
		}
	}

	// ListDevices
	listReq := withUser(httptest.NewRequest(http.MethodGet, "/auth/devices", nil), userID, email)
	listRec := httptest.NewRecorder()
	h.ListDevices(listRec, listReq)
	if listRec.Code != http.StatusOK {
		t.Fatalf("ListDevices status = %d, want %d", listRec.Code, http.StatusOK)
	}
	listResp := decodeJSON(t, listRec)
	devices, _ := listResp["devices"].([]any)
	if len(devices) != 1 {
		t.Fatalf("ListDevices returned %d devices, want 1 (body=%s)", len(devices), listRec.Body.String())
	}
	rowID, _ := devices[0].(map[string]any)["id"].(string)
	if rowID == "" {
		t.Fatalf("listed device missing \"id\": %v", devices[0])
	}

	// RevokeDevice — needs a chi URL param, so route it through a minimal
	// chi router instead of calling the handler directly.
	r := chi.NewRouter()
	r.Delete("/auth/devices/{id}", h.RevokeDevice)

	revokeReq := withUser(httptest.NewRequest(http.MethodDelete, "/auth/devices/"+rowID, nil), userID, email)
	revokeRec := httptest.NewRecorder()
	r.ServeHTTP(revokeRec, revokeReq)
	if revokeRec.Code != http.StatusNoContent {
		t.Fatalf("RevokeDevice status = %d, want %d, body=%s", revokeRec.Code, http.StatusNoContent, revokeRec.Body.String())
	}

	// Revoking an unknown id for this user -> 404.
	missingReq := withUser(httptest.NewRequest(http.MethodDelete, "/auth/devices/00000000-0000-0000-0000-000000000000", nil), userID, email)
	missingRec := httptest.NewRecorder()
	r.ServeHTTP(missingRec, missingReq)
	if missingRec.Code != http.StatusNotFound {
		t.Fatalf("RevokeDevice on unknown id status = %d, want %d", missingRec.Code, http.StatusNotFound)
	}
}
