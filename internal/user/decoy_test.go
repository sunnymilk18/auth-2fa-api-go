package user_test

// Cuentas señuelo (users.is_decoy): nunca inician sesión con éxito, responden
// igual que unas credenciales incorrectas y no cuentan como usuarios reales.

import (
	"errors"
	"testing"
	"time"

	"auth-2fa-api/internal/testutil"
	"auth-2fa-api/internal/user"
)

func TestVerifyPassword_DecoyNeverSucceeds(t *testing.T) {
	pool := testutil.PostgresPool(t)
	client, _ := testutil.NewAPIClient(t, pool)
	svc := user.NewService(user.NewRepository(pool), 5, 15*time.Minute)

	decoy := testutil.NewDecoyUser(t, pool, client.ID, "correcthorsebattery")
	real := testutil.NewUser(t, pool, client.ID, "correcthorsebattery")

	// Con la contraseña CORRECTA, y por cualquiera de los tres identificadores.
	for _, identifier := range []string{decoy.Email, decoy.Username, decoy.RUT} {
		u, err := svc.VerifyPassword(t.Context(), client.ID, identifier, "correcthorsebattery")
		if u != nil || !errors.Is(err, user.ErrInvalidCredentials) {
			t.Fatalf("VerifyPassword(señuelo, %q, contraseña correcta) = (%v, %v), want (nil, ErrInvalidCredentials)", identifier, u, err)
		}
	}

	// Y el error es exactamente el mismo que el de una contraseña incorrecta
	// de una cuenta real: nada delata que es un señuelo.
	_, errDecoy := svc.VerifyPassword(t.Context(), client.ID, decoy.Email, "otra-contraseña")
	_, errReal := svc.VerifyPassword(t.Context(), client.ID, real.Email, "otra-contraseña")
	if errDecoy != errReal {
		t.Fatalf("error del señuelo (%v) distinto al de una cuenta real con mala contraseña (%v)", errDecoy, errReal)
	}

	// Una cuenta real, con la contraseña correcta, sigue entrando.
	if u, err := svc.VerifyPassword(t.Context(), client.ID, real.Email, "correcthorsebattery"); err != nil || u == nil || u.IsDecoy {
		t.Fatalf("la cuenta real dejó de poder iniciar sesión: (%v, %v)", u, err)
	}
}

func TestFindByIdentifier_ReportsDecoy(t *testing.T) {
	pool := testutil.PostgresPool(t)
	client, _ := testutil.NewAPIClient(t, pool)
	svc := user.NewService(user.NewRepository(pool), 5, 15*time.Minute)
	decoy := testutil.NewDecoyUser(t, pool, client.ID, "correcthorsebattery")
	real := testutil.NewUser(t, pool, client.ID, "correcthorsebattery")

	if u, err := svc.FindByIdentifier(t.Context(), client.ID, decoy.Email); err != nil || !u.IsDecoy {
		t.Fatalf("FindByIdentifier(señuelo) = (%+v, %v), want IsDecoy", u, err)
	}
	if u, err := svc.FindByIdentifier(t.Context(), client.ID, real.Email); err != nil || u.IsDecoy {
		t.Fatalf("FindByIdentifier(real) = (%+v, %v), want !IsDecoy", u, err)
	}
}

func TestListByAPIClient_DecoysOnlyWhenAsked(t *testing.T) {
	pool := testutil.PostgresPool(t)
	client, _ := testutil.NewAPIClient(t, pool)
	svc := user.NewService(user.NewRepository(pool), 5, 15*time.Minute)
	decoy := testutil.NewDecoyUser(t, pool, client.ID, "correcthorsebattery")
	real := testutil.NewUser(t, pool, client.ID, "correcthorsebattery")

	list := func(includeDecoys bool) map[string]bool {
		users, _, _, _, err := svc.ListByAPIClient(t.Context(), client.ID, 1, 100, "", includeDecoys)
		if err != nil {
			t.Fatalf("ListByAPIClient: %v", err)
		}
		ids := map[string]bool{}
		for _, u := range users {
			ids[u.ID] = u.IsDecoy
		}
		return ids
	}

	normal := list(false)
	if _, found := normal[decoy.ID]; found {
		t.Fatal("el listado normal incluyó una cuenta señuelo")
	}
	if _, found := normal[real.ID]; !found {
		t.Fatal("el listado normal perdió a la cuenta real")
	}

	with := list(true)
	if isDecoy, found := with[decoy.ID]; !found || !isDecoy {
		t.Fatalf("include_decoys no trajo el señuelo marcado como tal: found=%v isDecoy=%v", found, isDecoy)
	}
	if isDecoy, found := with[real.ID]; !found || isDecoy {
		t.Fatalf("include_decoys trajo mal a la cuenta real: found=%v isDecoy=%v", found, isDecoy)
	}
}

// Un registro nuevo con el correo de un señuelo sin verificar no lo "reclama"
// (ver user.Repository.Create): el señuelo sigue siendo señuelo.
func TestRegister_DoesNotReclaimDecoy(t *testing.T) {
	pool := testutil.PostgresPool(t)
	client, _ := testutil.NewAPIClient(t, pool)
	svc := user.NewService(user.NewRepository(pool), 5, 15*time.Minute)
	decoy := testutil.NewDecoyUser(t, pool, client.ID, "correcthorsebattery")
	if _, err := pool.Exec(t.Context(), `UPDATE users SET email_verified = FALSE WHERE id = $1`, decoy.ID); err != nil {
		t.Fatal(err)
	}

	_, err := svc.Register(t.Context(), client.ID, decoy.Email, "anotherpassword", "user-"+testutil.UniqueSuffix(t), testutil.UniqueRUT(t))
	if !errors.Is(err, user.ErrEmailTaken) {
		t.Fatalf("Register sobre el correo de un señuelo: err = %v, want ErrEmailTaken", err)
	}
	var isDecoy bool
	if err := pool.QueryRow(t.Context(), `SELECT is_decoy FROM users WHERE id = $1`, decoy.ID).Scan(&isDecoy); err != nil || !isDecoy {
		t.Fatalf("el señuelo dejó de serlo: %v %v", isDecoy, err)
	}
}
