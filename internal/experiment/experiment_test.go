package experiment

import (
	"strings"
	"testing"
)

func TestRequireLocal(t *testing.T) {
	ok := []string{
		"postgres://u:p@localhost:5432/db?sslmode=disable",
		"postgres://u:p@127.0.0.1:5432/db",
		"postgres://u:p@127.5.6.7/db",
		"postgres://u:p@[::1]:5432/db",
		"postgres://u:p@dev.localhost/db",
		"host=localhost user=u password=p dbname=db",
		"postgres://u:p@/db?host=/var/run/postgresql",
	}
	for _, dsn := range ok {
		if err := RequireLocal(dsn); err != nil {
			t.Errorf("RequireLocal(%q) = %v, want ok", dsn, err)
		}
	}

	bad := []string{
		"postgres://u:secreto@db.ejemplo.com:5432/db",
		"postgres://u:secreto@203.0.113.5/db",
		"postgres://u:secreto@10.0.0.4/db",
		"postgres://u:secreto@ep-cool-1234.neon.tech/db?sslmode=require",
		"postgres://u:secreto@localhost.evil.com/db",       // empieza como localhost, pero no lo es
		"postgres://u:secreto@localhost,db.ejemplo.com/db", // un servidor local y uno remoto de respaldo
	}
	for _, dsn := range bad {
		err := RequireLocal(dsn)
		if err == nil {
			t.Errorf("RequireLocal(%q) = nil, want rechazo", dsn)
			continue
		}
		if strings.Contains(err.Error(), "secreto") {
			t.Errorf("el mensaje de error filtra la contraseña: %v", err)
		}
	}

	if err := RequireLocal("esto no es una cadena de conexión ://"); err == nil {
		t.Error("una cadena inválida debe rechazarse")
	}
}

func TestRequireConfirmation(t *testing.T) {
	t.Setenv(ConfirmEnv, "")
	if err := RequireConfirmation(); err == nil {
		t.Fatal("sin la variable de confirmación debe negarse")
	}
	t.Setenv(ConfirmEnv, "si")
	if err := RequireConfirmation(); err == nil {
		t.Fatal("un valor distinto del exigido no cuenta como confirmación")
	}
	t.Setenv(ConfirmEnv, ConfirmValue)
	if err := RequireConfirmation(); err != nil {
		t.Fatalf("con la confirmación correcta debe permitir: %v", err)
	}
}

func TestDSN_Orden(t *testing.T) {
	t.Setenv("EXPERIMENT_POSTGRES_DSN", "")
	t.Setenv("TEST_POSTGRES_DSN", "")
	t.Setenv("POSTGRES_DSN", "")
	if DSN() != DefaultDSN {
		t.Fatalf("sin variables debe usar la base local por defecto, usó %q", DSN())
	}
	t.Setenv("POSTGRES_DSN", "postgres://a@localhost/p")
	t.Setenv("TEST_POSTGRES_DSN", "postgres://a@localhost/t")
	if DSN() != "postgres://a@localhost/t" {
		t.Fatalf("TEST_POSTGRES_DSN debe ganarle a POSTGRES_DSN, usó %q", DSN())
	}
	t.Setenv("EXPERIMENT_POSTGRES_DSN", "postgres://a@localhost/e")
	if DSN() != "postgres://a@localhost/e" {
		t.Fatalf("EXPERIMENT_POSTGRES_DSN debe ganar, usó %q", DSN())
	}
}
