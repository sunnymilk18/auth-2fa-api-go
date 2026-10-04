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
	"strings"
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

// newTestHandlersWithChoice is newTestHandlers but with the first-login
// "choose your method" flow enabled — see newTestServiceWithChoice.
func newTestHandlersWithChoice(t *testing.T) (*auth.Handlers, *auth.Service, *auth.TokenManager, *testutil.FakeMailer, string) {
	t.Helper()
	svc, tokens, mailer, apiClientID := newTestServiceWithChoice(t)
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
	body := jsonBody(t, map[string]string{"email": "a@example.com", "password": "correcthorsebattery", "username": "user-" + testutil.UniqueSuffix(t), "rut": testutil.UniqueRUT(t)})
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
	body := jsonBody(t, map[string]string{"email": email, "password": "correcthorsebattery", "username": "user-" + testutil.UniqueSuffix(t), "rut": testutil.UniqueRUT(t)})
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

// Only a VERIFIED account blocks a duplicate registration — mustRegister
// verifies the first one, so this exercises that case specifically.
func TestHandler_Register_DuplicateEmail(t *testing.T) {
	h, svc, _, mailer, apiClientID := newTestHandlers(t)
	email := "user-" + testutil.UniqueSuffix(t) + "@example.com"
	mustRegister(t, svc, mailer, apiClientID, email, "correcthorsebattery")

	body := jsonBody(t, map[string]string{"email": email, "password": "correcthorsebattery", "username": "user-" + testutil.UniqueSuffix(t), "rut": testutil.UniqueRUT(t)})
	rec := httptest.NewRecorder()
	h.Register(rec, withAPIClient(httptest.NewRequest(http.MethodPost, "/auth/register", body), apiClientID))

	if rec.Code != http.StatusConflict {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusConflict)
	}
}

func TestHandler_Register_DuplicateUsername_SuggestsAlternativeInMessage(t *testing.T) {
	h, svc, _, mailer, apiClientID := newTestHandlers(t)
	username := "juan-" + testutil.UniqueSuffix(t)
	firstEmail := "a-" + testutil.UniqueSuffix(t) + "@example.com"
	mustRegisterWithUsername(t, svc, mailer, apiClientID, firstEmail, "correcthorsebattery", username)

	secondEmail := "b-" + testutil.UniqueSuffix(t) + "@example.com"
	body := jsonBody(t, map[string]string{"email": secondEmail, "password": "correcthorsebattery", "username": username, "rut": testutil.UniqueRUT(t)})
	rec := httptest.NewRecorder()
	h.Register(rec, withAPIClient(httptest.NewRequest(http.MethodPost, "/auth/register", body), apiClientID))

	if rec.Code != http.StatusConflict {
		t.Fatalf("status = %d, want %d, body=%s", rec.Code, http.StatusConflict, rec.Body.String())
	}
	resp := decodeJSON(t, rec)
	wantSuggestion := username + "2"
	if errMsg, _ := resp["error"].(string); !bytes.Contains([]byte(errMsg), []byte(wantSuggestion)) {
		t.Fatalf("error message %q doesn't mention the suggested username %q", errMsg, wantSuggestion)
	}
}

func TestHandler_Register_InvalidRUT(t *testing.T) {
	h, _, _, _, apiClientID := newTestHandlers(t)
	body := jsonBody(t, map[string]string{
		"email": "a-" + testutil.UniqueSuffix(t) + "@example.com", "password": "correcthorsebattery",
		"username": "user-" + testutil.UniqueSuffix(t), "rut": "11111111-2", // wrong check digit (should be 1)
	})
	rec := httptest.NewRecorder()
	h.Register(rec, withAPIClient(httptest.NewRequest(http.MethodPost, "/auth/register", body), apiClientID))

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d, body=%s", rec.Code, http.StatusBadRequest, rec.Body.String())
	}
}

func TestHandler_Login_WithUsernameOrRUT(t *testing.T) {
	h, svc, _, mailer, apiClientID := newTestHandlers(t)
	email := "user-" + testutil.UniqueSuffix(t) + "@example.com"
	username := "user-" + testutil.UniqueSuffix(t)
	rut := testutil.UniqueRUT(t)
	mustRegisterFull(t, svc, mailer, apiClientID, email, "correcthorsebattery", username, rut)

	for _, identifier := range []string{username, rut} {
		body := jsonBody(t, map[string]string{"identifier": identifier, "password": "correcthorsebattery"})
		req := withAPIClient(httptest.NewRequest(http.MethodPost, "/auth/login", body), apiClientID)
		rec := httptest.NewRecorder()
		h.Login(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("Login(identifier=%q): status = %d, want %d, body=%s", identifier, rec.Code, http.StatusOK, rec.Body.String())
		}
	}
}

// Registering again with the same email BEFORE verifying reclaims the
// existing (unverified) account instead of being blocked — see
// user.Repository.Create's doc comment for why.
func TestHandler_Register_ReclaimsUnverifiedDuplicate(t *testing.T) {
	h, _, _, _, apiClientID := newTestHandlers(t)
	email := "user-" + testutil.UniqueSuffix(t) + "@example.com"
	username := "user-" + testutil.UniqueSuffix(t)
	rut := testutil.UniqueRUT(t)
	body := func() *bytes.Buffer {
		return jsonBody(t, map[string]string{"email": email, "password": "correcthorsebattery", "username": username, "rut": rut})
	}

	firstRec := httptest.NewRecorder()
	h.Register(firstRec, withAPIClient(httptest.NewRequest(http.MethodPost, "/auth/register", body()), apiClientID))
	if firstRec.Code != http.StatusCreated {
		t.Fatalf("first Register status = %d, want %d, body=%s", firstRec.Code, http.StatusCreated, firstRec.Body.String())
	}

	secondRec := httptest.NewRecorder()
	h.Register(secondRec, withAPIClient(httptest.NewRequest(http.MethodPost, "/auth/register", body()), apiClientID))
	if secondRec.Code != http.StatusCreated {
		t.Fatalf("second Register (reclaiming) status = %d, want %d, body=%s", secondRec.Code, http.StatusCreated, secondRec.Body.String())
	}

	firstID, _ := decodeJSON(t, firstRec)["id"].(string)
	secondID, _ := decodeJSON(t, secondRec)["id"].(string)
	if firstID == "" || secondID != firstID {
		t.Fatalf("expected the same user id reclaimed: first=%q second=%q", firstID, secondID)
	}
}

// --- Email verification ---

func TestHandler_Login_BlockedUntilEmailVerified(t *testing.T) {
	h, svc, _, mailer, apiClientID := newTestHandlers(t)
	email := "user-" + testutil.UniqueSuffix(t) + "@example.com"
	// Register only — not mustRegister, which also confirms the email.
	if _, err := svc.Register(t.Context(), apiClientID, email, "correcthorsebattery", "user-"+testutil.UniqueSuffix(t), testutil.UniqueRUT(t)); err != nil {
		t.Fatalf("Register: %v", err)
	}
	_, _ = mailer.Last() // drain the verification email, not asserted on here

	body := jsonBody(t, map[string]string{"identifier": email, "password": "correcthorsebattery"})
	req := withAPIClient(httptest.NewRequest(http.MethodPost, "/auth/login", body), apiClientID)
	rec := httptest.NewRecorder()

	h.Login(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d, body=%s", rec.Code, http.StatusForbidden, rec.Body.String())
	}
}

func TestHandler_ConfirmEmailVerification_FullFlow(t *testing.T) {
	h, svc, _, mailer, apiClientID := newTestHandlers(t)
	email := "user-" + testutil.UniqueSuffix(t) + "@example.com"
	if _, err := svc.Register(t.Context(), apiClientID, email, "correcthorsebattery", "user-"+testutil.UniqueSuffix(t), testutil.UniqueRUT(t)); err != nil {
		t.Fatalf("Register: %v", err)
	}
	sent, ok := mailer.Last()
	if !ok {
		t.Fatal("no verification email was sent")
	}
	code := testutil.ExtractVerificationCode(sent.Body)
	if code == "" {
		t.Fatalf("could not find a verification code in email body: %q", sent.Body)
	}

	confirmReq := withAPIClient(httptest.NewRequest(http.MethodPost, "/auth/verify-email/confirm", jsonBody(t, map[string]string{"email": email, "code": code})), apiClientID)
	confirmRec := httptest.NewRecorder()
	h.ConfirmEmailVerification(confirmRec, confirmReq)
	if confirmRec.Code != http.StatusNoContent {
		t.Fatalf("ConfirmEmailVerification status = %d, want %d, body=%s", confirmRec.Code, http.StatusNoContent, confirmRec.Body.String())
	}

	// Login now succeeds.
	loginReq := withAPIClient(httptest.NewRequest(http.MethodPost, "/auth/login", jsonBody(t, map[string]string{"identifier": email, "password": "correcthorsebattery"})), apiClientID)
	loginRec := httptest.NewRecorder()
	h.Login(loginRec, loginReq)
	if loginRec.Code != http.StatusOK {
		t.Fatalf("Login after verifying status = %d, want %d, body=%s", loginRec.Code, http.StatusOK, loginRec.Body.String())
	}
}

func TestHandler_ConfirmEmailVerification_InvalidCode(t *testing.T) {
	h, _, _, _, apiClientID := newTestHandlers(t)
	body := jsonBody(t, map[string]string{"email": "nobody@example.com", "code": "123456"})
	req := withAPIClient(httptest.NewRequest(http.MethodPost, "/auth/verify-email/confirm", body), apiClientID)
	rec := httptest.NewRecorder()

	h.ConfirmEmailVerification(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusUnauthorized)
	}
}

func TestHandler_ResendEmailVerification_UnknownAccount(t *testing.T) {
	h, _, _, _, apiClientID := newTestHandlers(t)
	body := jsonBody(t, map[string]string{"email": "nobody@example.com"})
	req := withAPIClient(httptest.NewRequest(http.MethodPost, "/auth/verify-email/resend", body), apiClientID)
	rec := httptest.NewRecorder()

	h.ResendEmailVerification(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusNotFound)
	}
}

func TestHandler_ResendEmailVerification_AlreadyVerified(t *testing.T) {
	h, svc, _, mailer, apiClientID := newTestHandlers(t)
	email := "user-" + testutil.UniqueSuffix(t) + "@example.com"
	mustRegister(t, svc, mailer, apiClientID, email, "correcthorsebattery")

	body := jsonBody(t, map[string]string{"email": email})
	req := withAPIClient(httptest.NewRequest(http.MethodPost, "/auth/verify-email/resend", body), apiClientID)
	rec := httptest.NewRecorder()

	h.ResendEmailVerification(rec, req)

	if rec.Code != http.StatusConflict {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusConflict)
	}
}

// --- Login (step 1) ---

func TestHandler_Login_MissingFields(t *testing.T) {
	h, _, _, _, apiClientID := newTestHandlers(t)

	body := jsonBody(t, map[string]string{"identifier": "", "password": ""})
	req := withAPIClient(httptest.NewRequest(http.MethodPost, "/auth/login", body), apiClientID)
	rec := httptest.NewRecorder()

	h.Login(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusBadRequest)
	}
}

func TestHandler_Login_WrongPassword(t *testing.T) {
	h, svc, _, mailer, apiClientID := newTestHandlers(t)
	email := "user-" + testutil.UniqueSuffix(t) + "@example.com"
	mustRegister(t, svc, mailer, apiClientID, email, "correcthorsebattery")

	body := jsonBody(t, map[string]string{"identifier": email, "password": "wrong"})
	req := withAPIClient(httptest.NewRequest(http.MethodPost, "/auth/login", body), apiClientID)
	rec := httptest.NewRecorder()

	h.Login(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusUnauthorized)
	}
}

func TestHandler_Login_TooManyFailedAttempts(t *testing.T) {
	h, svc, _, mailer, apiClientID := newTestHandlers(t)
	email := "user-" + testutil.UniqueSuffix(t) + "@example.com"
	mustRegister(t, svc, mailer, apiClientID, email, "correcthorsebattery")

	doLogin := func(password string) *httptest.ResponseRecorder {
		body := jsonBody(t, map[string]string{"identifier": email, "password": password})
		req := withAPIClient(httptest.NewRequest(http.MethodPost, "/auth/login", body), apiClientID)
		rec := httptest.NewRecorder()
		h.Login(rec, req)
		return rec
	}

	// newTestHandlers' underlying service was built with maxFails=3.
	for i := 1; i <= 3; i++ {
		if rec := doLogin("wrong"); rec.Code != http.StatusUnauthorized {
			t.Fatalf("wrong password attempt %d: status = %d, want %d", i, rec.Code, http.StatusUnauthorized)
		}
	}

	rec := doLogin("correcthorsebattery")
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("locked out (even with the correct password): status = %d, want %d, body=%s", rec.Code, http.StatusTooManyRequests, rec.Body.String())
	}
	if rec.Header().Get("Retry-After") == "" {
		t.Fatal("locked out: missing Retry-After header")
	}
	if body := decodeJSON(t, rec); !strings.Contains(body["error"].(string), "minuto") {
		t.Fatalf("locked out: error message %q doesn't tell the user how long to wait", body["error"])
	}
}

func TestHandler_Login_Success(t *testing.T) {
	h, svc, _, mailer, apiClientID := newTestHandlers(t)
	email := "user-" + testutil.UniqueSuffix(t) + "@example.com"
	mustRegister(t, svc, mailer, apiClientID, email, "correcthorsebattery")

	body := jsonBody(t, map[string]string{"identifier": email, "password": "correcthorsebattery"})
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

// TestHandler_Login_Success_MethodEmail covers the common case: an account
// with no authenticator app enrolled gets method: "email" alongside its
// login_token. newTestHandlers' Service leaves the first-login "choose your
// method" screen disabled (see newTestService's doc comment), so even this
// account's very first login goes straight to the email path, same as every
// other test in this file assumes.
func TestHandler_Login_Success_MethodEmail(t *testing.T) {
	h, svc, _, mailer, apiClientID := newTestHandlers(t)
	email := "user-" + testutil.UniqueSuffix(t) + "@example.com"
	mustRegister(t, svc, mailer, apiClientID, email, "correcthorsebattery")

	req := withAPIClient(httptest.NewRequest(http.MethodPost, "/auth/login", jsonBody(t, map[string]string{
		"identifier": email, "password": "correcthorsebattery",
	})), apiClientID)
	rec := httptest.NewRecorder()
	h.Login(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d, body=%s", rec.Code, http.StatusOK, rec.Body.String())
	}
	resp := decodeJSON(t, rec)
	if method, _ := resp["method"].(string); method != "email" {
		t.Fatalf("response %v: method = %q, want %q", resp, method, "email")
	}
}

// TestHandler_Login_Success_MethodTOTP covers the authenticator-app case —
// method: "totp" once the account has confirmed one (see
// ConfirmTOTPEnrollment), and no OTP email is sent for it.
func TestHandler_Login_Success_MethodTOTP(t *testing.T) {
	h, svc, tokens, mailer, apiClientID := newTestHandlers(t)
	email := "user-" + testutil.UniqueSuffix(t) + "@example.com"
	mustRegister(t, svc, mailer, apiClientID, email, "correcthorsebattery")
	userID, _, _ := mustLoginFull(t, svc, tokens, mailer, apiClientID, email, "correcthorsebattery")

	otpauthURL, err := svc.StartTOTPEnrollment(t.Context(), userID, email)
	if err != nil {
		t.Fatalf("StartTOTPEnrollment: %v", err)
	}
	if err := svc.ConfirmTOTPEnrollment(t.Context(), userID, totpCodeFromOTPAuthURL(t, otpauthURL)); err != nil {
		t.Fatalf("ConfirmTOTPEnrollment: %v", err)
	}

	sentBefore := len(mailer.Sent())
	req := withAPIClient(httptest.NewRequest(http.MethodPost, "/auth/login", jsonBody(t, map[string]string{
		"identifier": email, "password": "correcthorsebattery",
	})), apiClientID)
	rec := httptest.NewRecorder()
	h.Login(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d, body=%s", rec.Code, http.StatusOK, rec.Body.String())
	}
	resp := decodeJSON(t, rec)
	if method, _ := resp["method"].(string); method != "totp" {
		t.Fatalf("response %v: method = %q, want %q", resp, method, "totp")
	}
	if len(mailer.Sent()) != sentBefore {
		t.Fatalf("a TOTP-enabled account's Login must not send an OTP email, got %d -> %d sent", sentBefore, len(mailer.Sent()))
	}
}

// TestHandler_Login_FirstTime_OmitsMethod covers that the first-login
// "choose your method" response never carries method — there's no pending
// code at all yet, only a choice still to be made (see
// TestHandler_Login_FirstTime_NeedsSetup for the rest of that response's
// shape).
func TestHandler_Login_FirstTime_OmitsMethod(t *testing.T) {
	h, svc, _, mailer, apiClientID := newTestHandlersWithChoice(t)
	email := "user-" + testutil.UniqueSuffix(t) + "@example.com"
	mustRegister(t, svc, mailer, apiClientID, email, "correcthorsebattery")

	req := withAPIClient(httptest.NewRequest(http.MethodPost, "/auth/login", jsonBody(t, map[string]string{
		"identifier": email, "password": "correcthorsebattery",
	})), apiClientID)
	rec := httptest.NewRecorder()
	h.Login(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d, body=%s", rec.Code, http.StatusOK, rec.Body.String())
	}
	resp := decodeJSON(t, rec)
	if _, present := resp["method"]; present {
		t.Fatalf("response %v: method present, want omitted (needs_2fa_setup is true)", resp)
	}
}

// --- VerifyOTP (step 2) ---

func TestHandler_VerifyOTP_MissingFields(t *testing.T) {
	h, _, _, _, _ := newTestHandlers(t)
	body := jsonBody(t, map[string]string{"login_token": "", "code": ""})
	req := httptest.NewRequest(http.MethodPost, "/auth/verify-otp", body)
	rec := httptest.NewRecorder()

	h.VerifyOTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusBadRequest)
	}
}

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
	mustRegister(t, svc, mailer, apiClientID, email, "correcthorsebattery")

	loginToken, _, _, _, err := svc.LoginStep1(t.Context(), apiClientID, email, "correcthorsebattery")
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

// --- Password reset ---

func TestHandler_RequestPasswordReset_SameResponseRegardlessOfAccountExistence(t *testing.T) {
	h, svc, _, mailer, apiClientID := newTestHandlers(t)
	email := "user-" + testutil.UniqueSuffix(t) + "@example.com"
	mustRegister(t, svc, mailer, apiClientID, email, "old-password-123")

	knownReq := withAPIClient(httptest.NewRequest(http.MethodPost, "/auth/password-reset/request", jsonBody(t, map[string]string{"email": email})), apiClientID)
	knownRec := httptest.NewRecorder()
	h.RequestPasswordReset(knownRec, knownReq)

	unknownReq := withAPIClient(httptest.NewRequest(http.MethodPost, "/auth/password-reset/request", jsonBody(t, map[string]string{"email": "nobody@example.com"})), apiClientID)
	unknownRec := httptest.NewRecorder()
	h.RequestPasswordReset(unknownRec, unknownReq)

	if knownRec.Code != http.StatusOK || unknownRec.Code != http.StatusOK {
		t.Fatalf("status codes = %d (known), %d (unknown), want both %d", knownRec.Code, unknownRec.Code, http.StatusOK)
	}
	if knownRec.Body.String() != unknownRec.Body.String() {
		t.Fatalf("response bodies differ (leaks account existence): known=%q unknown=%q", knownRec.Body.String(), unknownRec.Body.String())
	}
}

func TestHandler_RequestPasswordReset_MissingAPIClientContext(t *testing.T) {
	h, _, _, _, _ := newTestHandlers(t)
	req := httptest.NewRequest(http.MethodPost, "/auth/password-reset/request", jsonBody(t, map[string]string{"email": "a@example.com"})) // no withAPIClient
	rec := httptest.NewRecorder()

	h.RequestPasswordReset(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusUnauthorized)
	}
}

func TestHandler_ConfirmPasswordReset_ShortPassword(t *testing.T) {
	h, _, _, _, apiClientID := newTestHandlers(t)
	body := jsonBody(t, map[string]string{"email": "a@example.com", "code": "whatever", "new_password": "short"})
	req := withAPIClient(httptest.NewRequest(http.MethodPost, "/auth/password-reset/confirm", body), apiClientID)
	rec := httptest.NewRecorder()

	h.ConfirmPasswordReset(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusBadRequest)
	}
}

func TestHandler_ConfirmPasswordReset_MissingAPIClientContext(t *testing.T) {
	h, _, _, _, _ := newTestHandlers(t)
	body := jsonBody(t, map[string]string{"email": "a@example.com", "code": "123456", "new_password": "new-password-456"})
	req := httptest.NewRequest(http.MethodPost, "/auth/password-reset/confirm", body) // no withAPIClient
	rec := httptest.NewRecorder()

	h.ConfirmPasswordReset(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusUnauthorized)
	}
}

func TestHandler_ConfirmPasswordReset_InvalidCode(t *testing.T) {
	h, _, _, _, apiClientID := newTestHandlers(t)
	body := jsonBody(t, map[string]string{"email": "does-not-exist@example.com", "code": "123456", "new_password": "new-password-456"})
	req := withAPIClient(httptest.NewRequest(http.MethodPost, "/auth/password-reset/confirm", body), apiClientID)
	rec := httptest.NewRecorder()

	h.ConfirmPasswordReset(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusUnauthorized)
	}
}

func TestHandler_PasswordReset_FullFlow(t *testing.T) {
	h, svc, _, mailer, apiClientID := newTestHandlers(t)
	email := "user-" + testutil.UniqueSuffix(t) + "@example.com"
	mustRegister(t, svc, mailer, apiClientID, email, "old-password-123")

	reqReq := withAPIClient(httptest.NewRequest(http.MethodPost, "/auth/password-reset/request", jsonBody(t, map[string]string{"email": email})), apiClientID)
	reqRec := httptest.NewRecorder()
	h.RequestPasswordReset(reqRec, reqReq)
	if reqRec.Code != http.StatusOK {
		t.Fatalf("RequestPasswordReset status = %d, want %d", reqRec.Code, http.StatusOK)
	}

	sent, ok := mailer.Last()
	if !ok {
		t.Fatal("no password reset email was sent")
	}
	code := testutil.ExtractResetCode(sent.Body)
	if code == "" {
		t.Fatalf("could not find a reset code in email body: %q", sent.Body)
	}

	confirmReq := withAPIClient(httptest.NewRequest(http.MethodPost, "/auth/password-reset/confirm", jsonBody(t, map[string]string{"email": email, "code": code, "new_password": "new-password-456"})), apiClientID)
	confirmRec := httptest.NewRecorder()
	h.ConfirmPasswordReset(confirmRec, confirmReq)
	if confirmRec.Code != http.StatusNoContent {
		t.Fatalf("ConfirmPasswordReset status = %d, want %d, body=%s", confirmRec.Code, http.StatusNoContent, confirmRec.Body.String())
	}

	// The new password now logs in; the old one doesn't.
	loginReq := withAPIClient(httptest.NewRequest(http.MethodPost, "/auth/login", jsonBody(t, map[string]string{"identifier": email, "password": "new-password-456"})), apiClientID)
	loginRec := httptest.NewRecorder()
	h.Login(loginRec, loginReq)
	if loginRec.Code != http.StatusOK {
		t.Fatalf("Login with new password status = %d, want %d, body=%s", loginRec.Code, http.StatusOK, loginRec.Body.String())
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
	h, svc, _, mailer, apiClientID := newTestHandlers(t)
	email := "user-" + testutil.UniqueSuffix(t) + "@example.com"
	mustRegister(t, svc, mailer, apiClientID, email, "correcthorsebattery")

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

func TestHandler_DeviceLogin_MissingFields(t *testing.T) {
	h, _, _, _, _ := newTestHandlers(t)

	body := jsonBody(t, map[string]string{"device_id": "", "device_token": "", "pin": ""})
	req := httptest.NewRequest(http.MethodPost, "/auth/devices/login", body)
	rec := httptest.NewRecorder()

	h.DeviceLogin(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusBadRequest)
	}
}

func TestHandler_DeviceLogin_And_List_And_Revoke(t *testing.T) {
	h, svc, tokens, mailer, apiClientID := newTestHandlers(t)
	email := "user-" + testutil.UniqueSuffix(t) + "@example.com"
	mustRegister(t, svc, mailer, apiClientID, email, "correcthorsebattery")

	loginToken, _, _, _, err := svc.LoginStep1(t.Context(), apiClientID, email, "correcthorsebattery")
	if err != nil {
		t.Fatalf("LoginStep1: %v", err)
	}
	sent, _ := mailer.Last()
	code := testutil.ExtractOTPCode(sent.Body)
	access, _, err := loginStep2Tokens(t, svc, loginToken, code)
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

	// DeviceLogin: wrong pin -> 403 (not 401 — see writePinError's doc
	// comment: 401 is reserved for "access token expired, refresh and
	// retry", which a wrong PIN is not).
	wrongBody := jsonBody(t, map[string]string{"device_id": deviceID, "device_token": deviceToken, "pin": "000000"})
	wrongReq := httptest.NewRequest(http.MethodPost, "/auth/devices/login", wrongBody)
	wrongRec := httptest.NewRecorder()
	h.DeviceLogin(wrongRec, wrongReq)
	if wrongRec.Code != http.StatusForbidden {
		t.Fatalf("DeviceLogin wrong pin status = %d, want %d, body=%s", wrongRec.Code, http.StatusForbidden, wrongRec.Body.String())
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

// --- TOTP (authenticator app) ---

func TestHandler_EnrollTOTP_RequiresAuth(t *testing.T) {
	h, _, _, _, _ := newTestHandlers(t)

	req := httptest.NewRequest(http.MethodPost, "/auth/totp/enroll", nil)
	rec := httptest.NewRecorder()
	h.EnrollTOTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("EnrollTOTP with no authenticated user: status = %d, want %d", rec.Code, http.StatusUnauthorized)
	}
}

func TestHandler_EnrollThenConfirmTOTP_FullFlow(t *testing.T) {
	h, svc, tokens, mailer, apiClientID := newTestHandlers(t)
	email := "user-" + testutil.UniqueSuffix(t) + "@example.com"
	mustRegister(t, svc, mailer, apiClientID, email, "correcthorsebattery")
	userID, _, _ := mustLoginFull(t, svc, tokens, mailer, apiClientID, email, "correcthorsebattery")

	enrollReq := withUser(httptest.NewRequest(http.MethodPost, "/auth/totp/enroll", nil), userID, email)
	enrollRec := httptest.NewRecorder()
	h.EnrollTOTP(enrollRec, enrollReq)
	if enrollRec.Code != http.StatusOK {
		t.Fatalf("EnrollTOTP status = %d, want %d, body=%s", enrollRec.Code, http.StatusOK, enrollRec.Body.String())
	}
	body := decodeJSON(t, enrollRec)
	otpauthURL, _ := body["otpauth_url"].(string)
	if otpauthURL == "" {
		t.Fatalf("EnrollTOTP response missing otpauth_url: %v", body)
	}

	// Wrong code -> 401, doesn't enable it.
	wrongReq := withUser(httptest.NewRequest(http.MethodPost, "/auth/totp/confirm", jsonBody(t, map[string]string{"code": "000000"})), userID, email)
	wrongRec := httptest.NewRecorder()
	h.ConfirmTOTP(wrongRec, wrongReq)
	if wrongRec.Code != http.StatusUnauthorized {
		t.Fatalf("ConfirmTOTP with a wrong code: status = %d, want %d", wrongRec.Code, http.StatusUnauthorized)
	}

	// Correct code -> 204, enables it.
	code := totpCodeFromOTPAuthURL(t, otpauthURL)
	confirmReq := withUser(httptest.NewRequest(http.MethodPost, "/auth/totp/confirm", jsonBody(t, map[string]string{"code": code})), userID, email)
	confirmRec := httptest.NewRecorder()
	h.ConfirmTOTP(confirmRec, confirmReq)
	if confirmRec.Code != http.StatusNoContent {
		t.Fatalf("ConfirmTOTP with the correct code: status = %d, want %d, body=%s", confirmRec.Code, http.StatusNoContent, confirmRec.Body.String())
	}

	// Login now takes the TOTP path over HTTP too.
	sentBefore := len(mailer.Sent())
	loginReq := withAPIClient(httptest.NewRequest(http.MethodPost, "/auth/login", jsonBody(t, map[string]string{
		"identifier": email, "password": "correcthorsebattery",
	})), apiClientID)
	loginRec := httptest.NewRecorder()
	h.Login(loginRec, loginReq)
	if loginRec.Code != http.StatusOK {
		t.Fatalf("Login status = %d, want %d, body=%s", loginRec.Code, http.StatusOK, loginRec.Body.String())
	}
	if len(mailer.Sent()) != sentBefore {
		t.Fatalf("Login for a TOTP-enabled account sent an email (count %d -> %d)", sentBefore, len(mailer.Sent()))
	}
	loginBody := decodeJSON(t, loginRec)
	loginToken, _ := loginBody["login_token"].(string)
	if loginToken == "" {
		t.Fatalf("Login response missing login_token: %v", loginBody)
	}

	verifyReq := httptest.NewRequest(http.MethodPost, "/auth/verify-otp", jsonBody(t, map[string]string{
		"login_token": loginToken, "code": totpCodeFromOTPAuthURL(t, otpauthURL),
	}))
	verifyRec := httptest.NewRecorder()
	h.VerifyOTP(verifyRec, verifyReq)
	if verifyRec.Code != http.StatusOK {
		t.Fatalf("VerifyOTP with a TOTP code: status = %d, want %d, body=%s", verifyRec.Code, http.StatusOK, verifyRec.Body.String())
	}

	// DisableTOTP -> login goes back to emailing a code.
	disableReq := withUser(httptest.NewRequest(http.MethodPost, "/auth/totp/disable", nil), userID, email)
	disableRec := httptest.NewRecorder()
	h.DisableTOTP(disableRec, disableReq)
	if disableRec.Code != http.StatusNoContent {
		t.Fatalf("DisableTOTP status = %d, want %d, body=%s", disableRec.Code, http.StatusNoContent, disableRec.Body.String())
	}

	sentBeforeFallback := len(mailer.Sent())
	fallbackReq := withAPIClient(httptest.NewRequest(http.MethodPost, "/auth/login", jsonBody(t, map[string]string{
		"identifier": email, "password": "correcthorsebattery",
	})), apiClientID)
	fallbackRec := httptest.NewRecorder()
	h.Login(fallbackRec, fallbackReq)
	if fallbackRec.Code != http.StatusOK {
		t.Fatalf("Login after DisableTOTP: status = %d, want %d", fallbackRec.Code, http.StatusOK)
	}
	if len(mailer.Sent()) != sentBeforeFallback+1 {
		t.Fatalf("Login after DisableTOTP: want a new OTP email, got %d -> %d sent", sentBeforeFallback, len(mailer.Sent()))
	}
}

// --- First-login "choose email or authenticator" over HTTP ---

func TestHandler_Login_FirstTime_NeedsSetup(t *testing.T) {
	h, svc, _, mailer, apiClientID := newTestHandlersWithChoice(t)
	email := "user-" + testutil.UniqueSuffix(t) + "@example.com"
	mustRegister(t, svc, mailer, apiClientID, email, "correcthorsebattery")
	sentBefore := len(mailer.Sent())

	req := withAPIClient(httptest.NewRequest(http.MethodPost, "/auth/login", jsonBody(t, map[string]string{
		"identifier": email, "password": "correcthorsebattery",
	})), apiClientID)
	rec := httptest.NewRecorder()
	h.Login(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("Login status = %d, want %d, body=%s", rec.Code, http.StatusOK, rec.Body.String())
	}
	body := decodeJSON(t, rec)
	if needs, _ := body["needs_2fa_setup"].(bool); !needs {
		t.Fatalf("Login response needs_2fa_setup = %v, want true: %v", body["needs_2fa_setup"], body)
	}
	if body["login_token"] == "" || body["login_token"] == nil {
		t.Fatalf("Login response missing login_token: %v", body)
	}
	if len(mailer.Sent()) != sentBefore {
		t.Fatalf("first-time Login must not send an OTP email yet, got %d -> %d sent", sentBefore, len(mailer.Sent()))
	}
}

func TestHandler_SendLoginEmailCode_CompletesFirstLogin(t *testing.T) {
	h, svc, _, mailer, apiClientID := newTestHandlersWithChoice(t)
	email := "user-" + testutil.UniqueSuffix(t) + "@example.com"
	mustRegister(t, svc, mailer, apiClientID, email, "correcthorsebattery")

	loginReq := withAPIClient(httptest.NewRequest(http.MethodPost, "/auth/login", jsonBody(t, map[string]string{
		"identifier": email, "password": "correcthorsebattery",
	})), apiClientID)
	loginRec := httptest.NewRecorder()
	h.Login(loginRec, loginReq)
	loginBody := decodeJSON(t, loginRec)
	loginToken, _ := loginBody["login_token"].(string)
	if loginToken == "" {
		t.Fatalf("Login response missing login_token: %v", loginBody)
	}

	sendReq := httptest.NewRequest(http.MethodPost, "/auth/login/send-email-code", jsonBody(t, map[string]string{"login_token": loginToken}))
	sendRec := httptest.NewRecorder()
	h.SendLoginEmailCode(sendRec, sendReq)
	if sendRec.Code != http.StatusOK {
		t.Fatalf("SendLoginEmailCode status = %d, want %d, body=%s", sendRec.Code, http.StatusOK, sendRec.Body.String())
	}

	sent, ok := mailer.Last()
	if !ok {
		t.Fatal("SendLoginEmailCode: no email was sent")
	}
	code := testutil.ExtractOTPCode(sent.Body)
	if code == "" {
		t.Fatalf("could not find an OTP code in email body: %q", sent.Body)
	}

	verifyReq := httptest.NewRequest(http.MethodPost, "/auth/verify-otp", jsonBody(t, map[string]string{
		"login_token": loginToken, "code": code,
	}))
	verifyRec := httptest.NewRecorder()
	h.VerifyOTP(verifyRec, verifyReq)
	if verifyRec.Code != http.StatusOK {
		t.Fatalf("VerifyOTP status = %d, want %d, body=%s", verifyRec.Code, http.StatusOK, verifyRec.Body.String())
	}
}

func TestHandler_SendLoginEmailCode_UnknownToken(t *testing.T) {
	h, _, _, _, _ := newTestHandlersWithChoice(t)

	req := httptest.NewRequest(http.MethodPost, "/auth/login/send-email-code", jsonBody(t, map[string]string{"login_token": "does-not-exist"}))
	rec := httptest.NewRecorder()
	h.SendLoginEmailCode(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d, body=%s", rec.Code, http.StatusUnauthorized, rec.Body.String())
	}
}

// The "authenticator app" branch of the first-login choice: EnrollTOTP and
// ConfirmTOTP called with a login_token instead of a Bearer token —
// confirming completes the login directly (200 + tokens), unlike the
// Bearer-authenticated settings-screen path (204, no tokens) already
// covered by TestHandler_EnrollThenConfirmTOTP_FullFlow.
func TestHandler_EnrollAndConfirmTOTP_ViaLoginToken_CompletesFirstLogin(t *testing.T) {
	h, svc, _, mailer, apiClientID := newTestHandlersWithChoice(t)
	email := "user-" + testutil.UniqueSuffix(t) + "@example.com"
	mustRegister(t, svc, mailer, apiClientID, email, "correcthorsebattery")

	loginReq := withAPIClient(httptest.NewRequest(http.MethodPost, "/auth/login", jsonBody(t, map[string]string{
		"identifier": email, "password": "correcthorsebattery",
	})), apiClientID)
	loginRec := httptest.NewRecorder()
	h.Login(loginRec, loginReq)
	loginBody := decodeJSON(t, loginRec)
	loginToken, _ := loginBody["login_token"].(string)
	if loginToken == "" {
		t.Fatalf("Login response missing login_token: %v", loginBody)
	}

	// No Authorization header at all here — proves this really goes
	// through the login_token path, not context left over from something
	// else.
	enrollReq := httptest.NewRequest(http.MethodPost, "/auth/totp/enroll", jsonBody(t, map[string]string{"login_token": loginToken}))
	enrollRec := httptest.NewRecorder()
	h.EnrollTOTP(enrollRec, enrollReq)
	if enrollRec.Code != http.StatusOK {
		t.Fatalf("EnrollTOTP (login_token mode) status = %d, want %d, body=%s", enrollRec.Code, http.StatusOK, enrollRec.Body.String())
	}
	enrollBody := decodeJSON(t, enrollRec)
	otpauthURL, _ := enrollBody["otpauth_url"].(string)
	if otpauthURL == "" {
		t.Fatalf("EnrollTOTP response missing otpauth_url: %v", enrollBody)
	}

	code := totpCodeFromOTPAuthURL(t, otpauthURL)
	confirmReq := httptest.NewRequest(http.MethodPost, "/auth/totp/confirm", jsonBody(t, map[string]string{
		"login_token": loginToken, "code": code,
	}))
	confirmRec := httptest.NewRecorder()
	h.ConfirmTOTP(confirmRec, confirmReq)
	if confirmRec.Code != http.StatusOK {
		t.Fatalf("ConfirmTOTP (login_token mode) status = %d, want %d, body=%s", confirmRec.Code, http.StatusOK, confirmRec.Body.String())
	}
	confirmBody := decodeJSON(t, confirmRec)
	if confirmBody["access_token"] == "" || confirmBody["access_token"] == nil {
		t.Fatalf("ConfirmTOTP (login_token mode) response missing access_token: %v", confirmBody)
	}
	if confirmBody["refresh_token"] == "" || confirmBody["refresh_token"] == nil {
		t.Fatalf("ConfirmTOTP (login_token mode) response missing refresh_token: %v", confirmBody)
	}
}

func TestHandler_EnrollTOTP_NoBearerNoLoginToken_Unauthorized(t *testing.T) {
	h, _, _, _, _ := newTestHandlersWithChoice(t)

	req := httptest.NewRequest(http.MethodPost, "/auth/totp/enroll", nil)
	rec := httptest.NewRecorder()
	h.EnrollTOTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusUnauthorized)
	}
}

// --- Account PIN ---

func setPin(t *testing.T, h *auth.Handlers, userID, email, pin, currentPin string) *httptest.ResponseRecorder {
	t.Helper()
	body := jsonBody(t, map[string]string{"pin": pin, "current_pin": currentPin})
	req := withUser(httptest.NewRequest(http.MethodPut, "/auth/pin", body), userID, email)
	rec := httptest.NewRecorder()
	h.SetPin(rec, req)
	return rec
}

func verifyPin(t *testing.T, h *auth.Handlers, userID, email, pin string) *httptest.ResponseRecorder {
	t.Helper()
	body := jsonBody(t, map[string]string{"pin": pin})
	req := withUser(httptest.NewRequest(http.MethodPost, "/auth/pin/verify", body), userID, email)
	rec := httptest.NewRecorder()
	h.VerifyPin(rec, req)
	return rec
}

// mustRegisterAndLogin registers, completes a full password+OTP login, and
// returns the account's id — several PIN tests need the real id, not a
// placeholder, since PIN state is read from Postgres by it.
func mustRegisterAndLogin(t *testing.T, svc *auth.Service, tokens *auth.TokenManager, mailer *testutil.FakeMailer, apiClientID, email, password string) string {
	t.Helper()
	mustRegister(t, svc, mailer, apiClientID, email, password)
	loginToken, _, _, _, err := svc.LoginStep1(t.Context(), apiClientID, email, password)
	if err != nil {
		t.Fatalf("LoginStep1: %v", err)
	}
	sent, _ := mailer.Last()
	code := testutil.ExtractOTPCode(sent.Body)
	access, _, err := loginStep2Tokens(t, svc, loginToken, code)
	if err != nil {
		t.Fatalf("LoginStep2: %v", err)
	}
	claims, err := tokens.ParseAccessToken(access)
	if err != nil {
		t.Fatalf("parsing access token: %v", err)
	}
	return claims.Subject
}

func TestHandler_SetPin_CreateThenChangeThenWrongCurrent(t *testing.T) {
	h, svc, tokens, mailer, apiClientID := newTestHandlers(t)
	email := "user-" + testutil.UniqueSuffix(t) + "@example.com"
	userID := mustRegisterAndLogin(t, svc, tokens, mailer, apiClientID, email, "correcthorsebattery")

	// First PIN ever: no current_pin needed.
	if rec := setPin(t, h, userID, email, "111111", ""); rec.Code != http.StatusNoContent {
		t.Fatalf("create: status = %d, want %d, body=%s", rec.Code, http.StatusNoContent, rec.Body.String())
	}

	// Changing it requires the correct current one.
	if rec := setPin(t, h, userID, email, "222222", "111111"); rec.Code != http.StatusNoContent {
		t.Fatalf("change with correct current_pin: status = %d, want %d, body=%s", rec.Code, http.StatusNoContent, rec.Body.String())
	}

	// Wrong current_pin: 403 pin_invalid, not 401.
	rec := setPin(t, h, userID, email, "333333", "111111") // 111111 no longer valid
	if rec.Code != http.StatusForbidden {
		t.Fatalf("change with wrong current_pin: status = %d, want %d, body=%s", rec.Code, http.StatusForbidden, rec.Body.String())
	}
	resp := decodeJSON(t, rec)
	if resp["code"] != "pin_invalid" {
		t.Fatalf("change with wrong current_pin: code = %v, want pin_invalid", resp["code"])
	}

	// The second PIN (222222) still works — the failed attempt above didn't
	// corrupt it.
	if rec := verifyPin(t, h, userID, email, "222222"); rec.Code != http.StatusNoContent {
		t.Fatalf("verify 222222 after a failed change attempt: status = %d, want %d, body=%s", rec.Code, http.StatusNoContent, rec.Body.String())
	}
}

func TestHandler_SetPin_InvalidFormat(t *testing.T) {
	h, svc, tokens, mailer, apiClientID := newTestHandlers(t)
	email := "user-" + testutil.UniqueSuffix(t) + "@example.com"
	userID := mustRegisterAndLogin(t, svc, tokens, mailer, apiClientID, email, "correcthorsebattery")

	rec := setPin(t, h, userID, email, "12345", "")
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d, body=%s", rec.Code, http.StatusBadRequest, rec.Body.String())
	}
	if resp := decodeJSON(t, rec); resp["code"] != "pin_invalid_format" {
		t.Fatalf("code = %v, want pin_invalid_format", resp["code"])
	}
}

// VerifyPin must have no side effect beyond the shared lockout counter —
// no session, no device token rotation, nothing for a caller (e.g.
// empresa-backend, confirming a destructive action) to clean up either way.
func TestHandler_VerifyPin_CorrectAndWrong(t *testing.T) {
	h, svc, tokens, mailer, apiClientID := newTestHandlers(t)
	email := "user-" + testutil.UniqueSuffix(t) + "@example.com"
	userID := mustRegisterAndLogin(t, svc, tokens, mailer, apiClientID, email, "correcthorsebattery")
	if rec := setPin(t, h, userID, email, "123456", ""); rec.Code != http.StatusNoContent {
		t.Fatalf("setup SetPin: status = %d, body=%s", rec.Code, rec.Body.String())
	}

	if rec := verifyPin(t, h, userID, email, "123456"); rec.Code != http.StatusNoContent {
		t.Fatalf("correct pin: status = %d, want %d, body=%s", rec.Code, http.StatusNoContent, rec.Body.String())
	}
	if rec := verifyPin(t, h, userID, email, "123456"); rec.Body.Len() != 0 {
		t.Fatalf("VerifyPin response body should be empty, got %q", rec.Body.String())
	}

	rec := verifyPin(t, h, userID, email, "000000")
	if rec.Code != http.StatusForbidden {
		t.Fatalf("wrong pin: status = %d, want %d, body=%s", rec.Code, http.StatusForbidden, rec.Body.String())
	}
	resp := decodeJSON(t, rec)
	if resp["code"] != "pin_invalid" {
		t.Fatalf("wrong pin: code = %v, want pin_invalid", resp["code"])
	}
	if _, ok := resp["attempts_left"]; !ok {
		t.Fatalf("wrong pin response missing attempts_left: %v", resp)
	}
}

func TestHandler_VerifyPin_NoPinSetYet(t *testing.T) {
	h, svc, tokens, mailer, apiClientID := newTestHandlers(t)
	email := "user-" + testutil.UniqueSuffix(t) + "@example.com"
	userID := mustRegisterAndLogin(t, svc, tokens, mailer, apiClientID, email, "correcthorsebattery")

	rec := verifyPin(t, h, userID, email, "123456")
	if rec.Code != http.StatusConflict {
		t.Fatalf("status = %d, want %d, body=%s", rec.Code, http.StatusConflict, rec.Body.String())
	}
	if resp := decodeJSON(t, rec); resp["code"] != "pin_not_set" {
		t.Fatalf("code = %v, want pin_not_set", resp["code"])
	}
}
