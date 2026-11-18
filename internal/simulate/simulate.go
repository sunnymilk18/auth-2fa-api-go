// Package simulate genera tráfico de autenticación SIMULADO, con semilla
// fija, para el experimento del detector de accesos anómalos: tráfico normal
// (con su ruido: contraseñas olvidadas, oficinas enteras tras una misma IP) y
// cinco escenarios de ataque. Junto con los eventos produce las etiquetas
// reales (ground truth) de cada ventana atacada — un archivo aparte que el
// detector JAMÁS lee: solo cmd/evaluate lo usa, para calificar.
//
// Es puro: no toca la base de datos (eso es db.go) y con la misma
// configuración entrega siempre exactamente los mismos eventos, etiquetas e
// identificadores.
//
// Todas las IPs salen de rangos reservados para documentación y pruebas
// (198.18.0.0/15 para el tráfico normal; 203.0.113.0/24 y 100.64.0.0/10 para
// los atacantes), así que ningún dato apunta a una dirección real.
//
// Limitación a tener presente al leer los resultados: la simulación no
// modela el limitador de tasa por IP de la API (20 intentos de inicio de
// sesión cada 15 minutos por IP), que en producción recortaría varios de
// estos ataques; lo que se evalúa es la capacidad del detector de reconocer
// el patrón, no el efecto combinado con ese limitador.
package simulate

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math"
	"math/rand/v2"
	"net/netip"
	"sort"
	"time"

	"github.com/google/uuid"

	"auth-2fa-api/internal/authevents"
	"auth-2fa-api/internal/user"
)

// Escenarios de ataque — los valores que aparecen en ground_truth.json y en
// las tablas de resultados.
const (
	ScenarioStuffing    = "relleno_credenciales"
	ScenarioSpraying    = "pulverizado_contrasenas"
	ScenarioBruteForce  = "fuerza_bruta_cuenta"
	ScenarioDistributed = "ataque_distribuido"
	ScenarioDecoy       = "toque_senuelos"
)

// Scenarios fija el orden en que se generan y se reportan.
var Scenarios = []string{ScenarioStuffing, ScenarioSpraying, ScenarioBruteForce, ScenarioDistributed, ScenarioDecoy}

// TenantPrefix prefija el nombre de todo tenant simulado. Es lo que permite
// borrar la simulación anterior sin tocar nada más, y que train/evaluate se
// queden solo con estos tenants.
const TenantPrefix = "sim-"

const window = 10 * time.Minute

// Intensidad de los ataques. "actual" es la simulación original y no cambia
// nunca (hay una prueba con su huella): los resultados de la semilla 42 del
// informe tienen que seguir siendo comparables. "lento" vuelve más sigilosos
// el relleno de credenciales y el pulverizado: ver stuffingSlow y sprayingSlow.
const (
	IntensityActual = "actual"
	IntensityLento  = "lento"
)

// Intensities son los niveles válidos, en el orden en que se reportan.
var Intensities = []string{IntensityActual, IntensityLento}

// ValidIntensity reporta si s es un nivel conocido; la cadena vacía cuenta
// como "actual".
func ValidIntensity(s string) bool { return s == "" || s == IntensityActual || s == IntensityLento }

// Config define el tamaño y la forma de la simulación.
type Config struct {
	Seed uint64
	// Start es el inicio (00:00 UTC, de preferencia un lunes) del período de
	// entrenamiento. Es una fecha fija a propósito: así los datos no
	// dependen del día en que se corre.
	Start        time.Time
	TrainingDays int
	EvalDays     int
	// TenantSizes: un tenant por elemento, con esa cantidad de usuarios.
	TenantSizes []int
	// Incidents: cuántos incidentes de cada escenario hay en el período de
	// evaluación (un incidente dura entre 1 y 4 ventanas seguidas; en
	// intensidad "lento", el relleno y el pulverizado duran de 6 a 12).
	Incidents map[string]int
	// Intensity: IntensityActual (o vacío) o IntensityLento. Solo cambia el
	// relleno de credenciales y el pulverizado de contraseñas; el tráfico
	// normal es idéntico para una misma semilla.
	Intensity string
}

// DefaultConfig es la configuración del experimento documentado en MANUAL.md.
func DefaultConfig(seed uint64) Config {
	return Config{
		Seed:         seed,
		Start:        time.Date(2026, 10, 5, 0, 0, 0, 0, time.UTC), // lunes
		TrainingDays: 7,
		EvalDays:     4,
		TenantSizes:  []int{200, 350, 500, 800, 300, 450},
		Incidents: map[string]int{
			ScenarioStuffing:    8,
			ScenarioSpraying:    8,
			ScenarioBruteForce:  8,
			ScenarioDistributed: 8,
			ScenarioDecoy:       10,
		},
	}
}

var tenantNames = []string{"muni-norte", "muni-sur", "colegio", "hospital", "universidad", "intendencia", "biblioteca", "bomberos"}

// Account es una cuenta simulada.
type Account struct {
	ID       string
	Email    string
	Username string
	RUT      string
	IsDecoy  bool
	// IP habitual de la persona (la de su casa o la de su oficina).
	IP string
}

// Tenant es un sistema consumidor simulado con sus cuentas.
type Tenant struct {
	ID     string
	Name   string
	Users  []Account
	Decoys []Account
}

// Row es una fila de auth_events por insertar.
type Row struct {
	At        time.Time
	TenantID  string
	UserID    string
	Kind      string
	Method    string
	Result    string
	EmailHash string
	IP        string
	IsDecoy   bool
}

// Key es la clave que identifica el ataque de una ventana. IP vacía significa
// ataque distribuido: solo la unidad del tenant es positiva (cada IP, por
// separado, se ve como tráfico normal). En ese caso IPs lista las IPs que
// participaron en la ventana: sus unidades no se pueden distinguir del
// tráfico normal una a una, así que cmd/evaluate las deja fuera de la matriz
// de confusión en vez de contarlas como falsos positivos (o como positivos).
type Key struct {
	TenantID string   `json:"tenant_id"`
	Tenant   string   `json:"tenant"`
	IP       string   `json:"ip"`
	IPs      []string `json:"ips,omitempty"`
}

// Label es la etiqueta real de una ventana atacada.
type Label struct {
	Incident    int       `json:"incident"`
	Scenario    string    `json:"scenario"`
	WindowStart time.Time `json:"window_start"`
	WindowEnd   time.Time `json:"window_end"`
	Key         Key       `json:"key"`
}

// Meta describe los rangos de la simulación. NO son etiquetas: es lo que
// train y evaluate necesitan para saber qué rango de fechas usar.
type Meta struct {
	Seed uint64 `json:"seed"`
	// Intensity va solo cuando no es "actual", para que los archivos de la
	// simulación original sigan saliendo idénticos.
	Intensity    string    `json:"intensity,omitempty"`
	TrainingFrom time.Time `json:"training_from"`
	TrainingTo   time.Time `json:"training_to"`
	EvalFrom     time.Time `json:"eval_from"`
	EvalTo       time.Time `json:"eval_to"`
}

// Result es toda la simulación.
type Result struct {
	Tenants []Tenant
	Rows    []Row
	Labels  []Label
	Meta    Meta
}

// Generate produce la simulación completa. Determinista: no usa el reloj ni
// itera sobre mapas, y toda la aleatoriedad sale de cfg.Seed.
func Generate(cfg Config) *Result {
	g := &gen{
		cfg:     cfg,
		rng:     rand.New(rand.NewPCG(cfg.Seed, 0x5e17da7a)),
		nextNet: netip.MustParseAddr("198.18.0.0"),
		nextAtk: netip.MustParseAddr("203.0.113.1"),
		nextBot: netip.MustParseAddr("100.64.0.1"),
	}
	g.start = cfg.Start.UTC().Truncate(24 * time.Hour)
	g.trainEnd = g.start.AddDate(0, 0, cfg.TrainingDays)
	g.evalEnd = g.trainEnd.AddDate(0, 0, cfg.EvalDays)

	g.buildTenants()
	g.normalTraffic()
	g.attacks()

	sort.SliceStable(g.rows, func(i, j int) bool { return g.rows[i].At.Before(g.rows[j].At) })
	return &Result{
		Tenants: g.tenants,
		Rows:    g.rows,
		Labels:  g.labels,
		Meta: Meta{
			Seed: cfg.Seed, Intensity: g.slowOnly(), TrainingFrom: g.start, TrainingTo: g.trainEnd, EvalFrom: g.trainEnd, EvalTo: g.evalEnd,
		},
	}
}

type gen struct {
	cfg                      Config
	rng                      *rand.Rand
	start, trainEnd, evalEnd time.Time

	tenants []Tenant
	rows    []Row
	labels  []Label

	nextNet, nextAtk, nextBot netip.Addr
	ghosts                    int
	incident                  int
	busy                      map[string]bool // "tenant|ventana" ya ocupada por un incidente
	officeIPs                 map[string]int  // cuántas cuentas usan cada IP habitual
}

func (g *gen) newUUID() string {
	var b [16]byte
	for i := range b {
		b[i] = byte(g.rng.UintN(256))
	}
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return uuid.UUID(b).String()
}

// Las tres fuentes de IPs, siempre secuenciales (así nunca se repiten).
func (g *gen) normalIP() string   { ip := g.nextNet; g.nextNet = ip.Next(); return ip.String() }
func (g *gen) attackerIP() string { ip := g.nextAtk; g.nextAtk = ip.Next(); return ip.String() }
func (g *gen) botIP() string      { ip := g.nextBot; g.nextBot = ip.Next(); return ip.String() }

// ghostHash es el hash de correo de un identificador que no existe — el
// mismo formato (64 hex) que auth_events.email_hash.
func (g *gen) ghostHash() string {
	g.ghosts++
	sum := sha256.Sum256([]byte(fmt.Sprintf("sim-inexistente-%d-%d", g.cfg.Seed, g.ghosts)))
	return hex.EncodeToString(sum[:])
}

func (g *gen) buildTenants() {
	rut := 10000000
	for ti, size := range g.cfg.TenantSizes {
		name := TenantPrefix + tenantNames[ti%len(tenantNames)]
		if ti >= len(tenantNames) {
			name = fmt.Sprintf("%s%s-%d", TenantPrefix, tenantNames[ti%len(tenantNames)], ti)
		}
		t := Tenant{ID: g.newUUID(), Name: name}

		// ~55% de las personas trabajan desde una oficina: grupos de 15 a 40
		// detrás de una misma IP. El resto tiene su propia IP.
		officeUsers := size * 55 / 100
		var officeIP string
		left := 0
		for i := 0; i < size; i++ {
			rut++
			a := Account{
				ID:       g.newUUID(),
				Email:    fmt.Sprintf("u%04d@%s.sim.example", i, name[len(TenantPrefix):]),
				Username: fmt.Sprintf("u%04d", i),
				RUT:      user.NewRUT(fmt.Sprintf("%08d", rut)),
			}
			if i < officeUsers {
				if left == 0 {
					officeIP = g.normalIP()
					left = 15 + g.rng.IntN(26)
				}
				a.IP = officeIP
				left--
			} else {
				a.IP = g.normalIP()
			}
			t.Users = append(t.Users, a)
		}
		// Dos cuentas señuelo por tenant, con nombres creíbles.
		for d, handle := range []string{"respaldo.sistemas", "admin.soporte"} {
			rut++
			t.Decoys = append(t.Decoys, Account{
				ID:       g.newUUID(),
				Email:    fmt.Sprintf("%s@%s.sim.example", handle, name[len(TenantPrefix):]),
				Username: fmt.Sprintf("senuelo%d", d+1),
				RUT:      user.NewRUT(fmt.Sprintf("%08d", rut)),
				IsDecoy:  true,
			})
		}
		g.tenants = append(g.tenants, t)
	}
}

// hourWeights: cuánto de la actividad cae en cada hora del día (UTC).
var hourWeights = []float64{0.3, 0.2, 0.2, 0.2, 0.3, 0.8, 2, 6, 14, 12, 9, 8, 7, 9, 8, 6, 7, 6, 3, 2, 1.5, 1, 0.6, 0.4}

func (g *gen) loginTime(day time.Time, office bool) time.Time {
	if office && g.rng.Float64() < 0.45 {
		// La hora punta de la mañana: 08:30 con una cola de ~15 minutos.
		mins := 8*60 + 30 + int(math.Abs(g.rng.NormFloat64())*15)
		if mins > 10*60+30 {
			mins = 10*60 + 30
		}
		return day.Add(time.Duration(mins)*time.Minute + time.Duration(g.rng.IntN(60))*time.Second)
	}
	var total float64
	for _, w := range hourWeights {
		total += w
	}
	x := g.rng.Float64() * total
	hour := 0
	for h, w := range hourWeights {
		if x < w {
			hour = h
			break
		}
		x -= w
	}
	return day.Add(time.Duration(hour)*time.Hour + time.Duration(g.rng.IntN(3600))*time.Second)
}

func (g *gen) add(at time.Time, tenant, userID, kind, method, result, emailHash, ip string, decoy bool) {
	g.rows = append(g.rows, Row{At: at, TenantID: tenant, UserID: userID, Kind: kind, Method: method, Result: result, EmailHash: emailHash, IP: ip, IsDecoy: decoy})
}

func (g *gen) fail(at time.Time, tenant, userID, method, result, emailHash, ip string) {
	g.add(at, tenant, userID, authevents.KindLogin, method, result, emailHash, ip, false)
}

// normalTraffic: el uso cotidiano de todos los períodos (entrenamiento y
// evaluación por igual), con su ruido — las contraseñas mal escritas, las
// olvidadas y las oficinas que entran todas a la misma hora.
func (g *gen) normalTraffic() {
	totalDays := g.cfg.TrainingDays + g.cfg.EvalDays
	for d := 0; d < totalDays; d++ {
		day := g.start.AddDate(0, 0, d)
		p := 0.55
		if day.Weekday() == time.Saturday || day.Weekday() == time.Sunday {
			p = 0.12
		}
		for ti := range g.tenants {
			t := &g.tenants[ti]
			for ui := range t.Users {
				if g.rng.Float64() >= p {
					continue
				}
				logins := 1
				if g.rng.Float64() < 0.2 {
					logins = 2
				}
				for l := 0; l < logins; l++ {
					g.normalLogin(day, t, &t.Users[ui])
				}
			}
		}
	}
}

func (g *gen) normalLogin(day time.Time, t *Tenant, u *Account) {
	at := g.loginTime(day, g.isOfficeIP(u))
	ip := u.IP
	if g.rng.Float64() < 0.08 { // desde el celular, con otra IP
		ip = g.normalIP()
	}

	r := g.rng.Float64()
	switch {
	case r < 0.012:
		// Olvidó la contraseña: 3 a 5 intentos fallidos, pide un código de
		// recuperación, la cambia y entra un rato después.
		n := 3 + g.rng.IntN(3)
		for i := 0; i < n; i++ {
			g.fail(at.Add(-time.Duration(150-i*25)*time.Second), t.ID, u.ID, authevents.MethodPassword, authevents.ResultBadCredentials, "", ip)
		}
		g.add(at.Add(-60*time.Second), t.ID, u.ID, authevents.KindPasswordResetRequest, "", authevents.ResultCodeSent, "", ip, false)
		g.add(at.Add(-30*time.Second), t.ID, u.ID, authevents.KindPasswordResetConfirm, "", authevents.ResultSuccess, "", ip, false)
	case r < 0.012+0.065:
		// Se equivocó al escribir la contraseña una o dos veces.
		n := 1 + g.rng.IntN(2)
		for i := 0; i < n; i++ {
			g.fail(at.Add(-time.Duration(40*(n-i))*time.Second), t.ID, u.ID, authevents.MethodPassword, authevents.ResultBadCredentials, "", ip)
		}
	case r < 0.012+0.065+0.02:
		// Se equivocó con el código del segundo factor.
		g.fail(at.Add(-20*time.Second), t.ID, u.ID, authevents.MethodTOTP, authevents.ResultBadTOTP, "", ip)
	}
	if g.rng.Float64() < 0.004 {
		// Escribió mal su identificador: una cuenta que no existe.
		g.fail(at.Add(-90*time.Second), t.ID, "", authevents.MethodPassword, authevents.ResultBadCredentials, g.ghostHash(), ip)
	}

	method := authevents.MethodEmailCode
	switch m := g.rng.Float64(); {
	case m < 0.30:
		method = authevents.MethodTOTP
	case m < 0.40:
		method = authevents.MethodDeviceTrusted
	}
	g.add(at, t.ID, u.ID, authevents.KindLogin, method, authevents.ResultSuccess, "", ip, false)
}

// isOfficeIP: una IP compartida por más de una persona es una oficina. Se
// calcula perezosamente contando cuántas cuentas la usan.
func (g *gen) isOfficeIP(u *Account) bool {
	if g.officeIPs == nil {
		g.officeIPs = map[string]int{}
		for ti := range g.tenants {
			for _, a := range g.tenants[ti].Users {
				g.officeIPs[a.IP]++
			}
		}
	}
	return g.officeIPs[u.IP] > 1
}

// --- ataques ---

func (g *gen) windowIndexRange() (first, last int) {
	// Ventanas enteras del período de evaluación.
	return int(g.trainEnd.Sub(g.start) / window), int(g.evalEnd.Sub(g.start)/window) - 1
}

func (g *gen) at(win int) time.Time { return g.start.Add(time.Duration(win) * window) }

// planLen elige un tenant y un tramo de `length` ventanas seguidas, dentro del
// período de evaluación, que ningún otro incidente de ese tenant esté usando.
func (g *gen) planLen(length int) (tenant *Tenant, firstWin int) {
	if g.busy == nil {
		g.busy = map[string]bool{}
	}
	first, last := g.windowIndexRange()
	for attempt := 0; ; attempt++ {
		t := &g.tenants[g.rng.IntN(len(g.tenants))]
		w := first + g.rng.IntN(last-first-length+2)
		free := true
		for i := 0; i < length; i++ {
			if g.busy[fmt.Sprintf("%s|%d", t.ID, w+i)] {
				free = false
			}
		}
		if free || attempt > 500 {
			for i := 0; i < length; i++ {
				g.busy[fmt.Sprintf("%s|%d", t.ID, w+i)] = true
			}
			return t, w
		}
	}
}

func (g *gen) label(scenario string, win int, t *Tenant, ip string) {
	g.labels = append(g.labels, Label{
		Incident: g.incident, Scenario: scenario,
		WindowStart: g.at(win), WindowEnd: g.at(win).Add(window),
		Key: Key{TenantID: t.ID, Tenant: t.Name, IP: ip},
	})
}

// moment elige un instante cualquiera dentro de la ventana win.
func (g *gen) moment(win int) time.Time {
	return g.at(win).Add(time.Duration(g.rng.IntN(int(window/time.Second))) * time.Second)
}

func (g *gen) attacks() {
	for _, scenario := range Scenarios {
		for i := 0; i < g.cfg.Incidents[scenario]; i++ {
			g.incident++
			switch scenario {
			case ScenarioStuffing:
				g.stuffing()
			case ScenarioSpraying:
				g.spraying()
			case ScenarioBruteForce:
				g.bruteForce()
			case ScenarioDistributed:
				g.distributed()
			case ScenarioDecoy:
				g.decoyTouch()
			}
		}
	}
}

// pickUsers entrega n cuentas distintas del tenant, al azar.
func (g *gen) pickUsers(t *Tenant, n int) []*Account {
	perm := g.rng.Perm(len(t.Users))
	if n > len(perm) {
		n = len(perm)
	}
	out := make([]*Account, n)
	for i := 0; i < n; i++ {
		out[i] = &t.Users[perm[i]]
	}
	return out
}

// slow reporta si la simulación corre en intensidad "lento".
func (g *gen) slow() bool { return g.cfg.Intensity == IntensityLento }

// slowOnly devuelve la intensidad para los archivos: vacía si es la original.
func (g *gen) slowOnly() string {
	if g.slow() {
		return IntensityLento
	}
	return ""
}

// Relleno de credenciales: una IP prueba pares usuario/contraseña de una
// filtración contra muchas cuentas, una vez cada una. Algunas cuentas ni
// existen en este tenant; otras pasan la contraseña y tropiezan con el
// segundo factor.
func (g *gen) stuffing() {
	if g.slow() {
		g.stuffingSlow()
		return
	}
	length := 1 + g.rng.IntN(3)
	t, first := g.planLen(length)
	ip := g.attackerIP()
	for w := first; w < first+length; w++ {
		n := 25 + g.rng.IntN(46)
		existing := g.pickUsers(t, n*6/10)
		for _, a := range existing {
			if g.rng.Float64() < 0.05 {
				g.fail(g.moment(w), t.ID, a.ID, authevents.MethodTOTP, authevents.ResultBadTOTP, "", ip)
			} else {
				g.fail(g.moment(w), t.ID, a.ID, authevents.MethodPassword, authevents.ResultBadCredentials, "", ip)
			}
		}
		for i := len(existing); i < n; i++ {
			g.fail(g.moment(w), t.ID, "", authevents.MethodPassword, authevents.ResultBadCredentials, g.ghostHash(), ip)
		}
		g.label(ScenarioStuffing, w, t, ip)
	}
}

// Pulverizado de contraseñas: pocas contraseñas comunes probadas contra
// muchas cuentas, despacio, para quedar bajo los umbrales de cada ventana.
func (g *gen) spraying() {
	if g.slow() {
		g.sprayingSlow()
		return
	}
	length := 2 + g.rng.IntN(3)
	t, first := g.planLen(length)
	ip := g.attackerIP()
	for w := first; w < first+length; w++ {
		n := 8 + g.rng.IntN(21)
		existing := g.pickUsers(t, n*85/100)
		for _, a := range existing {
			g.fail(g.moment(w), t.ID, a.ID, authevents.MethodPassword, authevents.ResultBadCredentials, "", ip)
		}
		for i := len(existing); i < n; i++ {
			g.fail(g.moment(w), t.ID, "", authevents.MethodPassword, authevents.ResultBadCredentials, g.ghostHash(), ip)
		}
		g.label(ScenarioSpraying, w, t, ip)
	}
}

// stuffingSlow es el relleno de credenciales en intensidad "lento": en vez de
// 25 a 70 intentos en una o tres ventanas, de 5 a 9 por ventana durante 6 a 12
// ventanas seguidas. Cada ventana, vista sola, queda bajo todos los umbrales de
// las reglas por defecto (menos de 20 fallos, de 10 cuentas y de 10 intentos
// contra cuentas inexistentes); lo anómalo es la combinación: varias cuentas
// distintas, ningún inicio de sesión correcto y una parte contra cuentas que no
// existen, ventana tras ventana desde la misma IP.
func (g *gen) stuffingSlow() {
	length := 6 + g.rng.IntN(7)
	t, first := g.planLen(length)
	ip := g.attackerIP()
	for w := first; w < first+length; w++ {
		n := 5 + g.rng.IntN(5)
		existing := g.pickUsers(t, n*55/100)
		for _, a := range existing {
			if g.rng.Float64() < 0.05 {
				g.fail(g.moment(w), t.ID, a.ID, authevents.MethodTOTP, authevents.ResultBadTOTP, "", ip)
			} else {
				g.fail(g.moment(w), t.ID, a.ID, authevents.MethodPassword, authevents.ResultBadCredentials, "", ip)
			}
		}
		for i := len(existing); i < n; i++ {
			g.fail(g.moment(w), t.ID, "", authevents.MethodPassword, authevents.ResultBadCredentials, g.ghostHash(), ip)
		}
		g.label(ScenarioStuffing, w, t, ip)
	}
}

// sprayingSlow es el pulverizado en intensidad "lento": de 6 a 9 cuentas por
// ventana (en vez de 8 a 28) durante 6 a 12 ventanas. Igual que el relleno
// lento, ninguna ventana pasa un umbral de las reglas por defecto.
func (g *gen) sprayingSlow() {
	length := 6 + g.rng.IntN(7)
	t, first := g.planLen(length)
	ip := g.attackerIP()
	for w := first; w < first+length; w++ {
		n := 6 + g.rng.IntN(4)
		existing := g.pickUsers(t, n*85/100)
		for _, a := range existing {
			g.fail(g.moment(w), t.ID, a.ID, authevents.MethodPassword, authevents.ResultBadCredentials, "", ip)
		}
		for i := len(existing); i < n; i++ {
			g.fail(g.moment(w), t.ID, "", authevents.MethodPassword, authevents.ResultBadCredentials, g.ghostHash(), ip)
		}
		g.label(ScenarioSpraying, w, t, ip)
	}
}

// Fuerza bruta contra una cuenta: una IP, una cuenta, muchas contraseñas. La
// cuenta se bloquea tras 10 fallos (LOGIN_MAX_FAILED_ATTEMPTS) y el atacante
// sigue chocando contra el bloqueo.
func (g *gen) bruteForce() {
	length := 1 + g.rng.IntN(3)
	t, first := g.planLen(length)
	ip := g.attackerIP()
	target := g.pickUsers(t, 1)[0]
	k := 0
	for w := first; w < first+length; w++ {
		n := 20 + g.rng.IntN(41)
		times := make([]time.Time, n)
		for i := range times {
			times[i] = g.moment(w)
		}
		sort.Slice(times, func(i, j int) bool { return times[i].Before(times[j]) })
		for _, at := range times {
			result := authevents.ResultBadCredentials
			if k%25 >= 10 {
				result = authevents.ResultLockedOut
			}
			g.fail(at, t.ID, target.ID, authevents.MethodPassword, result, "", ip)
			k++
		}
		g.label(ScenarioBruteForce, w, t, ip)
	}
}

// Ataque distribuido: muchas IPs, cada una con uno o dos intentos, contra
// unas pocas cuentas. Visto IP por IP parece tráfico normal; solo el tenant
// lo delata — por eso la etiqueta no lleva IP.
func (g *gen) distributed() {
	length := 1 + g.rng.IntN(3)
	t, first := g.planLen(length)
	targets := g.pickUsers(t, 2+g.rng.IntN(3))
	bots := make([]string, 30+g.rng.IntN(41))
	for i := range bots {
		bots[i] = g.botIP()
	}
	for w := first; w < first+length; w++ {
		for _, ip := range bots {
			attempts := 1 + g.rng.IntN(2)
			for a := 0; a < attempts; a++ {
				target := targets[g.rng.IntN(len(targets))]
				g.fail(g.moment(w), t.ID, target.ID, authevents.MethodPassword, authevents.ResultBadCredentials, "", ip)
			}
		}
		g.label(ScenarioDistributed, w, t, "")
		g.labels[len(g.labels)-1].Key.IPs = bots
	}
}

// Toque a señuelos: alguien prueba una cuenta señuelo (1 a 3 veces, a veces
// también pidiendo recuperar su contraseña). Casi no hace ruido: ningún
// umbral estadístico lo vería, pero ninguna persona real tiene motivo para
// tocar un señuelo.
func (g *gen) decoyTouch() {
	t, w := g.planLen(1)
	ip := g.attackerIP()
	n := 1 + g.rng.IntN(3)
	for i := 0; i < n; i++ {
		d := t.Decoys[g.rng.IntN(len(t.Decoys))]
		g.add(g.moment(w), t.ID, d.ID, authevents.KindLogin, authevents.MethodPassword, authevents.ResultBadCredentials, "", ip, true)
	}
	if g.rng.Float64() < 0.3 {
		d := t.Decoys[g.rng.IntN(len(t.Decoys))]
		g.add(g.moment(w), t.ID, d.ID, authevents.KindPasswordResetRequest, "", authevents.ResultAccountNotFound, "", ip, true)
	}
	g.label(ScenarioDecoy, w, t, ip)
}
