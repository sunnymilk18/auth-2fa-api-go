package simulate_test

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"auth-2fa-api/internal/detector"
	"auth-2fa-api/internal/simulate"
)

// smallConfig es una simulación chica, para que las pruebas corran rápido.
func smallConfig(seed uint64) simulate.Config {
	cfg := simulate.DefaultConfig(seed)
	cfg.TrainingDays = 3
	cfg.EvalDays = 2
	cfg.TenantSizes = []int{120, 200, 150}
	cfg.Incidents = map[string]int{
		simulate.ScenarioStuffing: 4, simulate.ScenarioSpraying: 4, simulate.ScenarioBruteForce: 4,
		simulate.ScenarioDistributed: 4, simulate.ScenarioDecoy: 5,
	}
	return cfg
}

func asJSON(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestGenerate_MismaSemillaMismosDatos(t *testing.T) {
	a, b := simulate.Generate(smallConfig(42)), simulate.Generate(smallConfig(42))
	if asJSON(t, a) != asJSON(t, b) {
		t.Fatal("la misma semilla produjo simulaciones distintas")
	}
	if len(a.Rows) == 0 || len(a.Labels) == 0 {
		t.Fatalf("simulación vacía: %d eventos, %d etiquetas", len(a.Rows), len(a.Labels))
	}
	if asJSON(t, a.Labels) == asJSON(t, simulate.Generate(smallConfig(43)).Labels) {
		t.Fatal("semillas distintas produjeron las mismas etiquetas: la semilla no se usa")
	}
}

func TestGenerate_EstructuraYRangos(t *testing.T) {
	cfg := smallConfig(7)
	res := simulate.Generate(cfg)

	// Los períodos son contiguos y no se pisan.
	m := res.Meta
	if !m.TrainingFrom.Equal(cfg.Start) || !m.TrainingTo.Equal(m.EvalFrom) || !m.EvalTo.Equal(m.EvalFrom.AddDate(0, 0, cfg.EvalDays)) {
		t.Fatalf("rangos incoherentes: %+v", m)
	}

	// Eventos ordenados y dentro del rango total.
	for i, r := range res.Rows {
		if r.At.Before(m.TrainingFrom) || !r.At.Before(m.EvalTo) {
			t.Fatalf("evento fuera del rango de la simulación: %v", r.At)
		}
		if i > 0 && r.At.Before(res.Rows[i-1].At) {
			t.Fatal("los eventos no salen ordenados por fecha")
		}
	}

	// Etiquetas: una cantidad por escenario coherente, siempre en el período
	// de evaluación y con ventanas alineadas a 10 minutos.
	incidents := map[string]map[int]bool{}
	for _, l := range res.Labels {
		if l.WindowStart.Before(m.EvalFrom) || l.WindowEnd.After(m.EvalTo) {
			t.Fatalf("etiqueta fuera del período de evaluación: %+v", l)
		}
		if !l.WindowStart.Equal(detector.WindowStartOf(l.WindowStart)) || l.WindowEnd.Sub(l.WindowStart) != detector.WindowSize {
			t.Fatalf("ventana mal alineada: %+v", l)
		}
		if l.Key.TenantID == "" || l.Key.Tenant == "" || !strings.HasPrefix(l.Key.Tenant, simulate.TenantPrefix) {
			t.Fatalf("clave de etiqueta incompleta: %+v", l.Key)
		}
		if incidents[l.Scenario] == nil {
			incidents[l.Scenario] = map[int]bool{}
		}
		incidents[l.Scenario][l.Incident] = true
	}
	for scenario, want := range cfg.Incidents {
		if got := len(incidents[scenario]); got != want {
			t.Fatalf("incidentes de %s = %d, want %d", scenario, got, want)
		}
	}

	// Cada tenant: usuarios, señuelos con is_decoy y un id único.
	seen := map[string]bool{}
	for _, tn := range res.Tenants {
		if len(tn.Decoys) != 2 || !tn.Decoys[0].IsDecoy {
			t.Fatalf("tenant %s sin sus dos señuelos", tn.Name)
		}
		for _, a := range append(append([]simulate.Account{}, tn.Users...), tn.Decoys...) {
			if seen[a.ID] {
				t.Fatalf("id de cuenta repetido: %s", a.ID)
			}
			seen[a.ID] = true
		}
	}
}

// Solo el escenario de señuelos toca señuelos, y ninguna persona normal lo hace.
func TestGenerate_SoloLosSenuelosToqueteanSenuelos(t *testing.T) {
	res := simulate.Generate(smallConfig(11))
	decoyWindows := map[string]bool{}
	for _, l := range res.Labels {
		if l.Scenario == simulate.ScenarioDecoy {
			decoyWindows[l.Key.TenantID+l.WindowStart.String()] = true
		}
	}
	touches := 0
	for _, r := range res.Rows {
		if !r.IsDecoy {
			continue
		}
		touches++
		if !decoyWindows[r.TenantID+detector.WindowStartOf(r.At).String()] {
			t.Fatalf("un intento contra un señuelo fuera de un incidente de señuelos: %+v", r)
		}
	}
	if touches == 0 {
		t.Fatal("no hay ningún intento contra señuelos")
	}
}

// Los ataques no se pisan entre sí dentro de un mismo tenant, para que cada
// etiqueta describa un solo escenario.
func TestGenerate_IncidentesNoSePisanPorTenant(t *testing.T) {
	res := simulate.Generate(smallConfig(5))
	used := map[string]string{}
	for _, l := range res.Labels {
		k := l.Key.TenantID + l.WindowStart.String()
		if prev, dup := used[k]; dup {
			t.Fatalf("dos etiquetas en el mismo tenant y ventana: %s y %s", prev, l.Scenario)
		}
		used[k] = l.Scenario
	}
}

// Cada escenario deja la huella que su nombre promete, vista a través de las
// mismas características que usa el detector (detector.Aggregate).
func TestGenerate_CadaEscenarioDejaSuHuella(t *testing.T) {
	res := simulate.Generate(smallConfig(21))
	var events []detector.Event
	for _, r := range res.Rows {
		events = append(events, detector.Event{At: r.At, Kind: r.Kind, TenantID: r.TenantID, UserID: r.UserID, EmailHash: r.EmailHash, IP: r.IP, Result: r.Result, IsDecoy: r.IsDecoy})
	}
	units := detector.Aggregate(events)
	find := func(window time.Time, keyType, key string) detector.Unit {
		for _, u := range units {
			if u.WindowStart.Equal(window) && u.KeyType == keyType && (u.TenantID == key || u.IP == key) {
				return u
			}
		}
		t.Fatalf("no hay unidad %s=%s en %v", keyType, key, window)
		return detector.Unit{}
	}

	checked := map[string]int{}
	for _, l := range res.Labels {
		tenantUnit := find(l.WindowStart, detector.KeyTenant, l.Key.TenantID)
		var ipUnit detector.Unit
		if l.Key.IP != "" {
			ipUnit = find(l.WindowStart, detector.KeyIP, l.Key.IP)
		}
		switch l.Scenario {
		case simulate.ScenarioStuffing:
			if f := ipUnit.Features; f.Fallos < 25 || f.CuentasDistintasAtacadas < 20 || f.IPsDistintasConFallos != 1 || f.IntentosCuentaInexistente < 5 {
				t.Fatalf("relleno de credenciales sin su huella (muchas cuentas desde una IP): %+v", f)
			}
		case simulate.ScenarioSpraying:
			if f := ipUnit.Features; f.Fallos < 8 || f.Fallos > 28 || f.CuentasDistintasAtacadas < f.Fallos-1 || f.IPsDistintasConFallos != 1 {
				t.Fatalf("pulverizado sin su huella (pocos fallos, todos contra cuentas distintas): %+v", f)
			}
		case simulate.ScenarioBruteForce:
			if f := ipUnit.Features; f.Fallos < 20 || f.CuentasDistintasAtacadas != 1 || f.IPsDistintasConFallos != 1 {
				t.Fatalf("fuerza bruta sin su huella (muchos fallos, una sola cuenta): %+v", f)
			}
		case simulate.ScenarioDistributed:
			if l.Key.IP != "" {
				t.Fatalf("el ataque distribuido no debe llevar IP en su clave: %+v", l.Key)
			}
			if f := tenantUnit.Features; f.IPsDistintasConFallos < 30 || f.CuentasDistintasAtacadas > 4 || f.Fallos < 30 {
				t.Fatalf("ataque distribuido sin su huella (muchas IPs, pocas cuentas): %+v", f)
			}
			// La etiqueta lista las IPs participantes, y cada una tiene su unidad.
			if len(l.Key.IPs) < 30 {
				t.Fatalf("el ataque distribuido debe listar las IPs participantes en su etiqueta: %d", len(l.Key.IPs))
			}
			for _, ip := range l.Key.IPs {
				if u := find(l.WindowStart, detector.KeyIP, ip); u.Features.Fallos < 1 || u.Features.Fallos > 2 {
					t.Fatalf("una IP del ataque distribuido debe verse como tráfico normal (1 o 2 fallos): %+v", u.Features)
				}
			}
		case simulate.ScenarioDecoy:
			if tenantUnit.Features.IntentosContraSenuelos < 1 || ipUnit.Features.IntentosContraSenuelos < 1 || ipUnit.Features.Fallos > 3 {
				t.Fatalf("toque a señuelos sin su huella: tenant %+v, ip %+v", tenantUnit.Features, ipUnit.Features)
			}
		}
		checked[l.Scenario]++
	}
	for _, s := range simulate.Scenarios {
		if checked[s] == 0 {
			t.Fatalf("no se verificó ninguna ventana de %s", s)
		}
	}
}

// El tráfico normal incluye ruido, y ese ruido no se parece a un ataque: el
// 99,9% de las ventanas normales queda bajo los umbrales de las reglas por
// defecto, pero hay ventanas "ruidosas" (oficina en la hora punta, contraseña
// olvidada) con varios fallos o varios inicios de sesión juntos.
func TestGenerate_ElRuidoNormalExiste(t *testing.T) {
	res := simulate.Generate(smallConfig(33))
	attackWindows := map[string]bool{}
	for _, l := range res.Labels {
		attackWindows[l.Key.TenantID+l.WindowStart.String()] = true
		if l.Key.IP != "" {
			attackWindows[l.Key.IP+l.WindowStart.String()] = true
		}
	}
	var events []detector.Event
	for _, r := range res.Rows {
		events = append(events, detector.Event{At: r.At, Kind: r.Kind, TenantID: r.TenantID, UserID: r.UserID, EmailHash: r.EmailHash, IP: r.IP, Result: r.Result, IsDecoy: r.IsDecoy})
	}
	maxOfficeLogins, maxForgotten := 0, 0
	for _, u := range detector.Aggregate(events) {
		key := u.TenantID
		if u.KeyType == detector.KeyIP {
			key = u.IP
		}
		if attackWindows[key+u.WindowStart.String()] || u.KeyType != detector.KeyIP {
			continue
		}
		maxOfficeLogins = max(maxOfficeLogins, u.Features.Correctos)
		maxForgotten = max(maxForgotten, u.Features.Fallos)
	}
	if maxOfficeLogins < 8 {
		t.Fatalf("no hay ninguna oficina con varios inicios de sesión en una misma ventana (máximo %d)", maxOfficeLogins)
	}
	if maxForgotten < 3 {
		t.Fatalf("no hay ninguna ventana normal con varios fallos (máximo %d)", maxForgotten)
	}
}
