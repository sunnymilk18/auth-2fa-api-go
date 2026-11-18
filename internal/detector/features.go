// Package detector detecta accesos anómalos sobre auth_events y deja alertas
// explicables en la tabla alerts. Tres fuentes, cada una con su propio valor
// de alerts.source:
//
//   - regla: umbrales fijos y configurables sobre las características de la
//     ventana (rules.go).
//   - isolation_forest: bosque de aislamiento propio, entrenado fuera de línea
//     con tráfico normal (iforest.go, model.go). Sin modelo cargado, esta
//     fuente simplemente no existe y la API funciona solo con reglas.
//   - senuelo: cualquier intento contra una cuenta señuelo (users.is_decoy).
//
// Las ventanas son de 10 minutos, alineadas al reloj en UTC, y se calculan por
// tenant y por IP (features.go). Solo se revisan ventanas ya completas.
//
// Hoja de dependencias: este paquete solo importa internal/authevents (para
// compartir la definición de "fallo" con Estadísticas) y nunca lee las
// etiquetas reales del experimento (cmd/simulate/ground_truth.json).
package detector

import (
	"sort"
	"time"

	"auth-2fa-api/internal/authevents"
)

// WindowSize es el largo de cada ventana de análisis.
const WindowSize = 10 * time.Minute

// Nombres de las seis características, tal como aparecen en alerts.features,
// en las explicaciones y en el modelo guardado.
const (
	FeatureFallos            = "fallos"
	FeatureCorrectos         = "correctos"
	FeatureIPsConFallos      = "ips_distintas_con_fallos"
	FeatureCuentasAtacadas   = "cuentas_distintas_atacadas"
	FeatureCuentaInexistente = "intentos_cuenta_inexistente"
	FeatureSenuelos          = "intentos_contra_senuelos"
)

// FeatureNames fija el orden del vector que ve el Isolation Forest.
var FeatureNames = []string{
	FeatureFallos,
	FeatureCorrectos,
	FeatureIPsConFallos,
	FeatureCuentasAtacadas,
	FeatureCuentaInexistente,
	FeatureSenuelos,
}

// Tipos de clave por la que se agrupa una ventana.
const (
	KeyTenant = "tenant"
	KeyIP     = "ip"
)

// Features son los valores de una ventana para una clave.
type Features struct {
	// Fallos: intentos con credenciales o códigos malos — misma definición
	// que Estadísticas (authevents.LoginFailureResults): excluye
	// pin_step_required, session_expired y email_not_verified.
	Fallos int `json:"fallos"`
	// Correctos: inicios de sesión completados con éxito.
	Correctos int `json:"correctos"`
	// IPsDistintasConFallos: IPs distintas entre los intentos fallidos.
	IPsDistintasConFallos int `json:"ips_distintas_con_fallos"`
	// CuentasDistintasAtacadas: cuentas distintas entre los intentos
	// fallidos; una cuenta que no existe cuenta por su hash de correo.
	CuentasDistintasAtacadas int `json:"cuentas_distintas_atacadas"`
	// IntentosCuentaInexistente: fallos cuyo identificador no resolvió a
	// ninguna cuenta.
	IntentosCuentaInexistente int `json:"intentos_cuenta_inexistente"`
	// IntentosContraSenuelos: intentos (de inicio de sesión o de
	// recuperación de contraseña) contra una cuenta señuelo.
	IntentosContraSenuelos int `json:"intentos_contra_senuelos"`
}

// Vector entrega los valores en el orden de FeatureNames.
func (f Features) Vector() []float64 {
	return []float64{
		float64(f.Fallos),
		float64(f.Correctos),
		float64(f.IPsDistintasConFallos),
		float64(f.CuentasDistintasAtacadas),
		float64(f.IntentosCuentaInexistente),
		float64(f.IntentosContraSenuelos),
	}
}

// Event es lo mínimo de una fila de auth_events que el detector necesita.
// Nunca trae correo, contraseña ni códigos: EmailHash es el HMAC que ya
// guarda auth_events para identificadores que no resolvieron a una cuenta.
type Event struct {
	At        time.Time
	Kind      string
	TenantID  string
	UserID    string
	EmailHash string
	IP        string
	Result    string
	IsDecoy   bool
}

// Unit es una ventana de 10 minutos para una clave (un tenant o una IP) con
// sus características. Es la unidad que se puntúa, se alerta y se evalúa.
type Unit struct {
	WindowStart time.Time
	KeyType     string
	// TenantID: en una unidad por tenant es el tenant; en una unidad por IP
	// es el tenant solo si todo el tráfico de esa IP en la ventana fue
	// contra uno (si tocó varios, queda vacío).
	TenantID string
	// IP: solo en las unidades por IP.
	IP       string
	Features Features
}

// WindowEnd es el fin (exclusivo) de la ventana.
func (u Unit) WindowEnd() time.Time { return u.WindowStart.Add(WindowSize) }

// WindowStartOf devuelve el inicio de la ventana que contiene t.
func WindowStartOf(t time.Time) time.Time { return t.UTC().Truncate(WindowSize) }

type unitKey struct {
	window time.Time
	typ    string
	id     string
}

type accumulator struct {
	f        Features
	failIPs  map[string]struct{}
	accounts map[string]struct{}
	tenants  map[string]struct{}
}

func newAccumulator() *accumulator {
	return &accumulator{
		failIPs:  map[string]struct{}{},
		accounts: map[string]struct{}{},
		tenants:  map[string]struct{}{},
	}
}

func (a *accumulator) add(e Event, fail, success bool) {
	if e.TenantID != "" {
		a.tenants[e.TenantID] = struct{}{}
	}
	if fail {
		a.f.Fallos++
		if e.IP != "" {
			a.failIPs[e.IP] = struct{}{}
		}
		if account := accountKey(e); account != "" {
			a.accounts[account] = struct{}{}
		}
		if e.UserID == "" && e.Result == authevents.ResultBadCredentials {
			a.f.IntentosCuentaInexistente++
		}
	}
	if success {
		a.f.Correctos++
	}
	if e.IsDecoy {
		a.f.IntentosContraSenuelos++
	}
}

// accountKey identifica la cuenta atacada: el id si resolvió a una cuenta, o
// el hash del correo si no (así una cuenta inexistente también cuenta como
// "cuenta distinta"). Vacío si no hay forma de distinguirla.
func accountKey(e Event) string {
	if e.UserID != "" {
		return "u:" + e.UserID
	}
	if e.EmailHash != "" {
		return "h:" + e.EmailHash
	}
	return ""
}

// Aggregate agrupa events en unidades (ventana × tenant y ventana × IP). Solo
// cuentan los eventos de inicio de sesión y, además, cualquier evento marcado
// como señuelo (por ejemplo, una recuperación de contraseña contra un
// señuelo). El resultado sale ordenado, así dos corridas sobre los mismos
// datos dan exactamente lo mismo.
func Aggregate(events []Event) []Unit {
	accs := map[unitKey]*accumulator{}
	get := func(k unitKey) *accumulator {
		a, ok := accs[k]
		if !ok {
			a = newAccumulator()
			accs[k] = a
		}
		return a
	}

	for _, e := range events {
		isLogin := e.Kind == authevents.KindLogin
		if !isLogin && !e.IsDecoy {
			continue
		}
		fail := isLogin && authevents.IsLoginFailure(e.Result)
		success := isLogin && e.Result == authevents.ResultSuccess
		w := WindowStartOf(e.At)
		if e.TenantID != "" {
			get(unitKey{w, KeyTenant, e.TenantID}).add(e, fail, success)
		}
		if e.IP != "" {
			get(unitKey{w, KeyIP, e.IP}).add(e, fail, success)
		}
	}

	units := make([]Unit, 0, len(accs))
	for k, a := range accs {
		u := Unit{WindowStart: k.window, KeyType: k.typ, Features: a.f}
		u.Features.IPsDistintasConFallos = len(a.failIPs)
		u.Features.CuentasDistintasAtacadas = len(a.accounts)
		switch k.typ {
		case KeyTenant:
			u.TenantID = k.id
		case KeyIP:
			u.IP = k.id
			if len(a.tenants) == 1 {
				for t := range a.tenants {
					u.TenantID = t
				}
			}
		}
		units = append(units, u)
	}
	SortUnits(units)
	return units
}

// SortUnits ordena por ventana, tipo de clave, tenant e IP.
func SortUnits(units []Unit) {
	sort.Slice(units, func(i, j int) bool {
		a, b := units[i], units[j]
		if !a.WindowStart.Equal(b.WindowStart) {
			return a.WindowStart.Before(b.WindowStart)
		}
		if a.KeyType != b.KeyType {
			return a.KeyType < b.KeyType
		}
		if a.TenantID != b.TenantID {
			return a.TenantID < b.TenantID
		}
		return a.IP < b.IP
	})
}
