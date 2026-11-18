package auth_test

// Un intento contra una cuenta señuelo nunca inicia sesión, se ve igual que
// una credencial incorrecta y queda en auth_events con is_decoy = TRUE.

import (
	"context"
	"errors"
	"testing"

	"auth-2fa-api/internal/authevents"
	"auth-2fa-api/internal/testutil"
	"auth-2fa-api/internal/user"
)

func TestLoginStep1_DecoyLooksLikeBadCredentialsAndIsFlagged(t *testing.T) {
	svc, pool, mailer, apiClientID := newTestServiceWithAuthEvents(t)
	decoy := testutil.NewDecoyUser(t, pool, apiClientID, "correcthorsebattery")
	real := mustRegisterWithEvents(t, svc, mailer, apiClientID, "events-real-"+testutil.UniqueSuffix(t)+"@example.com")

	// Referencia: una cuenta real con la contraseña mal.
	_, _, _, _, realErr := svc.LoginStep1(t.Context(), apiClientID, real.Email, "wrong-password", nil)
	if !errors.Is(realErr, user.ErrInvalidCredentials) {
		t.Fatalf("referencia: err = %v, want ErrInvalidCredentials", realErr)
	}
	sentBefore := len(mailer.Sent())

	// El señuelo, con la contraseña CORRECTA: igual de rechazado, mismo error.
	token, needsSetup, pushOffered, method, err := svc.LoginStep1(t.Context(), apiClientID, decoy.Email, "correcthorsebattery", nil)
	if err != realErr {
		t.Fatalf("error del señuelo = %v, want exactamente el de una credencial incorrecta (%v)", err, realErr)
	}
	if token != "" || needsSetup || pushOffered || method != "" {
		t.Fatalf("el señuelo devolvió algo de un inicio de sesión: token=%q setup=%v push=%v method=%q", token, needsSetup, pushOffered, method)
	}
	if len(mailer.Sent()) != sentBefore {
		t.Fatal("un intento contra un señuelo mandó un correo con código")
	}

	var result string
	var isDecoy bool
	if err := pool.QueryRow(context.Background(), `
		SELECT result, is_decoy FROM auth_events
		WHERE api_client_id = $1 AND kind = $2 AND user_id = $3
		ORDER BY id DESC LIMIT 1`, apiClientID, authevents.KindLogin, decoy.ID).Scan(&result, &isDecoy); err != nil {
		t.Fatalf("buscando el evento del señuelo: %v", err)
	}
	if !isDecoy || result != authevents.ResultBadCredentials {
		t.Fatalf("evento del señuelo: result=%q is_decoy=%v, want bad_credentials y TRUE", result, isDecoy)
	}

	// El intento contra la cuenta real NO queda marcado.
	var realFlagged bool
	if err := pool.QueryRow(context.Background(), `
		SELECT is_decoy FROM auth_events
		WHERE api_client_id = $1 AND kind = $2 AND user_id = $3
		ORDER BY id DESC LIMIT 1`, apiClientID, authevents.KindLogin, real.ID).Scan(&realFlagged); err != nil {
		t.Fatalf("buscando el evento de la cuenta real: %v", err)
	}
	if realFlagged {
		t.Fatal("un intento contra una cuenta real quedó marcado como señuelo")
	}
}

func TestRequestPasswordReset_DecoyGetsNoCodeButIsFlagged(t *testing.T) {
	svc, pool, mailer, apiClientID := newTestServiceWithAuthEvents(t)
	decoy := testutil.NewDecoyUser(t, pool, apiClientID, "correcthorsebattery")
	sentBefore := len(mailer.Sent())

	if err := svc.RequestPasswordReset(t.Context(), apiClientID, decoy.Email, nil); err != nil {
		t.Fatalf("la respuesta debe ser la de siempre (sin error): %v", err)
	}
	if len(mailer.Sent()) != sentBefore {
		t.Fatal("se mandó un código de recuperación a una cuenta señuelo")
	}
	var isDecoy bool
	if err := pool.QueryRow(context.Background(), `
		SELECT is_decoy FROM auth_events WHERE api_client_id = $1 AND kind = $2 AND user_id = $3`,
		apiClientID, authevents.KindPasswordResetRequest, decoy.ID).Scan(&isDecoy); err != nil || !isDecoy {
		t.Fatalf("el intento de recuperación contra el señuelo no quedó marcado: %v %v", isDecoy, err)
	}
}
