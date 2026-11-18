// Package experiment reúne lo común de las herramientas del experimento del
// detector (cmd/simulate, cmd/train, cmd/evaluate): de qué base de datos
// leen y la garantía de que esa base es LOCAL.
//
// Ninguna de las tres carga el archivo .env de la API (a diferencia de
// config.Load): ese archivo puede apuntar a producción, y estas herramientas
// escriben datos simulados. La base sale solo del entorno del proceso, y aun
// así se rechaza cualquier servidor que no sea de esta máquina.
package experiment

import (
	"context"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// DefaultDSN es la misma base local que usan las pruebas (internal/testutil).
const DefaultDSN = "postgres://postgres:postgres@localhost:5432/auth2fa?sslmode=disable"

// DSN devuelve la cadena de conexión: EXPERIMENT_POSTGRES_DSN, y si no,
// TEST_POSTGRES_DSN, POSTGRES_DSN y por último la base local por defecto —
// el mismo orden de preferencia que las pruebas.
func DSN() string {
	for _, k := range []string{"EXPERIMENT_POSTGRES_DSN", "TEST_POSTGRES_DSN", "POSTGRES_DSN"} {
		if v := os.Getenv(k); v != "" {
			return v
		}
	}
	return DefaultDSN
}

// isLocalHost reporta si host es de esta máquina: localhost (y *.localhost),
// una dirección de loopback o un socket Unix (ruta absoluta).
func isLocalHost(host string) bool {
	h := strings.ToLower(strings.TrimSpace(host))
	switch {
	case h == "localhost", strings.HasSuffix(h, ".localhost"):
		return true
	case strings.HasPrefix(h, "/"):
		return true
	}
	ip := net.ParseIP(strings.Trim(h, "[]"))
	return ip != nil && ip.IsLoopback()
}

// RequireLocal falla si dsn apunta a cualquier servidor que no sea local —
// incluidos los servidores de respaldo de la cadena. El mensaje nombra solo el
// host, nunca el usuario ni la contraseña.
func RequireLocal(dsn string) error {
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return fmt.Errorf("la cadena de conexión no es válida")
	}
	hosts := []string{cfg.ConnConfig.Host}
	for _, fb := range cfg.ConnConfig.Fallbacks {
		hosts = append(hosts, fb.Host)
	}
	for _, h := range hosts {
		if !isLocalHost(h) {
			return fmt.Errorf("me niego a correr: el servidor de base de datos %q no es local (solo se permite localhost, 127.0.0.1 o ::1)", h)
		}
	}
	return nil
}

// Connect abre un pool contra la base del experimento después de comprobar
// con RequireLocal que es local.
func Connect(ctx context.Context) (*pgxpool.Pool, error) {
	dsn := DSN()
	if err := RequireLocal(dsn); err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		return nil, fmt.Errorf("conectando a la base local: %w", err)
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("la base local no responde (¿está Postgres encendido?): %w", err)
	}
	return pool, nil
}

// ConfirmEnv es la variable que cmd/simulate exige para escribir datos.
const ConfirmEnv = "SIMULATE_CONFIRM_LOCAL"

// ConfirmValue es el valor que debe tener ConfirmEnv.
const ConfirmValue = "yes"

// ParseTime lee una fecha como AAAA-MM-DD (UTC, a las 00:00) o RFC 3339.
func ParseTime(s string) (time.Time, error) {
	if t, err := time.Parse("2006-01-02", s); err == nil {
		return t, nil
	}
	if t, err := time.Parse(time.RFC3339, s); err == nil {
		return t, nil
	}
	return time.Time{}, fmt.Errorf("%q no es una fecha válida: usa AAAA-MM-DD o RFC 3339", s)
}

// RequireConfirmation falla si ConfirmEnv no vale ConfirmValue: escribir datos
// simulados en una base es algo que se pide de forma explícita, nunca un
// efecto de haber corrido el comando sin leer.
func RequireConfirmation() error {
	if os.Getenv(ConfirmEnv) != ConfirmValue {
		return fmt.Errorf("falta la confirmación explícita: define %s=%s para permitir que se escriban datos simulados en la base local", ConfirmEnv, ConfirmValue)
	}
	return nil
}
