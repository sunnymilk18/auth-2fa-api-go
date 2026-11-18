package detector

// Pruebas sin base de datos: agregación por ventana, reglas, Isolation
// Forest, modelo y explicaciones. Todo con datos sintéticos.

import (
	"bytes"
	"math"
	"math/rand/v2"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"auth-2fa-api/internal/authevents"
)

var t0 = time.Date(2026, 11, 20, 14, 0, 0, 0, time.UTC)

func loginEvent(at time.Time, tenant, user, hash, ip, result string, decoy bool) Event {
	return Event{At: at, Kind: authevents.KindLogin, TenantID: tenant, UserID: user, EmailHash: hash, IP: ip, Result: result, IsDecoy: decoy}
}

func findUnit(t *testing.T, units []Unit, keyType, key string) Unit {
	t.Helper()
	for _, u := range units {
		if u.KeyType == keyType && (u.TenantID == key || u.IP == key) {
			return u
		}
	}
	t.Fatalf("no hay unidad %s=%s en %+v", keyType, key, units)
	return Unit{}
}

func TestAggregate_FeaturesPorTenant(t *testing.T) {
	bad := authevents.ResultBadCredentials
	events := []Event{
		// 3 fallos de 2 IPs contra 2 cuentas reales + 1 inexistente.
		loginEvent(t0.Add(1*time.Minute), "T1", "u1", "", "10.0.0.1", bad, false),
		loginEvent(t0.Add(2*time.Minute), "T1", "u1", "", "10.0.0.2", authevents.ResultBadTOTP, false),
		loginEvent(t0.Add(3*time.Minute), "T1", "u2", "", "10.0.0.2", bad, false),
		loginEvent(t0.Add(4*time.Minute), "T1", "", "hash-a", "10.0.0.2", bad, false),
		// Un éxito y tres resultados que NO son fallo (misma definición que Estadísticas).
		loginEvent(t0.Add(5*time.Minute), "T1", "u3", "", "10.0.0.3", authevents.ResultSuccess, false),
		loginEvent(t0.Add(5*time.Minute), "T1", "u3", "", "10.0.0.3", authevents.ResultPinStepRequired, false),
		loginEvent(t0.Add(5*time.Minute), "T1", "u3", "", "10.0.0.3", authevents.ResultSessionExpired, false),
		loginEvent(t0.Add(5*time.Minute), "T1", "u3", "", "10.0.0.3", authevents.ResultEmailNotVerified, false),
		// Otro kind: no cuenta (no es inicio de sesión ni señuelo).
		{At: t0.Add(6 * time.Minute), Kind: authevents.KindRegister, TenantID: "T1", IP: "10.0.0.9", Result: authevents.ResultEmailTaken},
	}
	u := findUnit(t, Aggregate(events), KeyTenant, "T1")
	want := Features{Fallos: 4, Correctos: 1, IPsDistintasConFallos: 2, CuentasDistintasAtacadas: 3, IntentosCuentaInexistente: 1}
	if u.Features != want {
		t.Fatalf("features = %+v, want %+v", u.Features, want)
	}
	if !u.WindowStart.Equal(t0) || !u.WindowEnd().Equal(t0.Add(WindowSize)) {
		t.Fatalf("ventana = %v–%v, want %v–%v", u.WindowStart, u.WindowEnd(), t0, t0.Add(WindowSize))
	}
}

func TestAggregate_SeparaVentanasDe10Minutos(t *testing.T) {
	bad := authevents.ResultBadCredentials
	events := []Event{
		loginEvent(t0.Add(9*time.Minute+59*time.Second), "T1", "u1", "", "10.0.0.1", bad, false),
		loginEvent(t0.Add(10*time.Minute), "T1", "u1", "", "10.0.0.1", bad, false),
	}
	var tenantUnits []Unit
	for _, u := range Aggregate(events) {
		if u.KeyType == KeyTenant {
			tenantUnits = append(tenantUnits, u)
		}
	}
	if len(tenantUnits) != 2 || tenantUnits[0].Features.Fallos != 1 || tenantUnits[1].Features.Fallos != 1 {
		t.Fatalf("se esperaban 2 ventanas con 1 fallo cada una, hay %+v", tenantUnits)
	}
	if !tenantUnits[1].WindowStart.Equal(t0.Add(10 * time.Minute)) {
		t.Fatalf("segunda ventana empieza en %v", tenantUnits[1].WindowStart)
	}
}

func TestAggregate_SenuelosCuentanEnCualquierKind(t *testing.T) {
	events := []Event{
		loginEvent(t0, "T1", "decoy1", "", "10.0.0.7", authevents.ResultBadCredentials, true),
		// Una recuperación de contraseña contra un señuelo no es un fallo de
		// inicio de sesión, pero sí un intento contra el señuelo.
		{At: t0.Add(time.Minute), Kind: authevents.KindPasswordResetRequest, TenantID: "T1", UserID: "decoy1", IP: "10.0.0.7", Result: authevents.ResultAccountNotFound, IsDecoy: true},
		// Esta no toca ningún señuelo: se ignora por completo.
		{At: t0.Add(time.Minute), Kind: authevents.KindPasswordResetRequest, TenantID: "T1", UserID: "u1", IP: "10.0.0.8", Result: authevents.ResultCodeSent},
	}
	units := Aggregate(events)
	u := findUnit(t, units, KeyIP, "10.0.0.7")
	if u.Features.IntentosContraSenuelos != 2 || u.Features.Fallos != 1 {
		t.Fatalf("features = %+v, want 2 intentos contra señuelos y 1 fallo", u.Features)
	}
	for _, other := range units {
		if other.IP == "10.0.0.8" {
			t.Fatalf("un evento ajeno a login y a señuelos generó una unidad: %+v", other)
		}
	}
}

func TestAggregate_UnidadPorIPTomaElTenantSoloSiEsUnico(t *testing.T) {
	bad := authevents.ResultBadCredentials
	events := []Event{
		loginEvent(t0, "T1", "u1", "", "10.0.0.1", bad, false),
		loginEvent(t0, "T1", "u2", "", "10.0.0.1", bad, false),
		loginEvent(t0, "T1", "u3", "", "10.0.0.2", bad, false),
		loginEvent(t0, "T2", "u4", "", "10.0.0.2", bad, false),
	}
	units := Aggregate(events)
	if got := findUnit(t, units, KeyIP, "10.0.0.1"); got.TenantID != "T1" {
		t.Fatalf("IP con un solo tenant: TenantID = %q, want T1", got.TenantID)
	}
	if got := findUnit(t, units, KeyIP, "10.0.0.2"); got.TenantID != "" {
		t.Fatalf("IP que tocó dos tenants: TenantID = %q, want vacío", got.TenantID)
	}
}

func TestAggregate_Determinista(t *testing.T) {
	var events []Event
	for i := 0; i < 200; i++ {
		events = append(events, loginEvent(t0.Add(time.Duration(i)*time.Minute), "T"+string(rune('A'+i%3)), "u", "", "10.0.0."+string(rune('1'+i%5)), authevents.ResultBadCredentials, false))
	}
	a, b := Aggregate(events), Aggregate(events)
	if len(a) != len(b) {
		t.Fatalf("largos distintos: %d vs %d", len(a), len(b))
	}
	for i := range a {
		if a[i] != b[i] {
			t.Fatalf("unidad %d distinta entre corridas: %+v vs %+v", i, a[i], b[i])
		}
	}
}

func TestRules_Umbrales(t *testing.T) {
	r := DefaultRules()
	if got := r.Evaluate(Features{Fallos: 19, CuentasDistintasAtacadas: 9, IPsDistintasConFallos: 9, IntentosCuentaInexistente: 9}); len(got) != 0 {
		t.Fatalf("justo bajo los umbrales no debe alertar: %v", got)
	}
	got := r.Evaluate(Features{Fallos: 42, CuentasDistintasAtacadas: 17})
	if len(got) != 2 {
		t.Fatalf("motivos = %v, want 2 (fallos y cuentas)", got)
	}
	if got[0] != "42 fallos en 10 min (umbral de la regla: 20)" {
		t.Fatalf("texto del primer motivo = %q", got[0])
	}
	if got := (Rules{Fallos: 0}).Evaluate(Features{Fallos: 1000}); len(got) != 0 {
		t.Fatalf("umbral 0 debe desactivar la regla: %v", got)
	}
}

func TestDecoyMotives(t *testing.T) {
	if got := DecoyMotives(Features{}); got != nil {
		t.Fatalf("sin intentos contra señuelos no hay motivos: %v", got)
	}
	got := DecoyMotives(Features{IntentosContraSenuelos: 1})
	if len(got) != 1 || got[0] != "1 intento contra una cuenta señuelo en 10 min" {
		t.Fatalf("motivo singular = %v", got)
	}
	if got := DecoyMotives(Features{IntentosContraSenuelos: 3}); got[0] != "3 intentos contra cuentas señuelo en 10 min" {
		t.Fatalf("motivo plural = %v", got)
	}
}

func TestAvgPathLength(t *testing.T) {
	if avgPathLength(1) != 0 || avgPathLength(2) != 1 {
		t.Fatalf("c(1)=%v c(2)=%v, want 0 y 1", avgPathLength(1), avgPathLength(2))
	}
	// Valor de referencia: c(256) = 2(ln 255 + γ) − 2·255/256 ≈ 10,2448.
	if got := avgPathLength(256); math.Abs(got-10.2448) > 1e-3 {
		t.Fatalf("c(256) = %v, want ≈ 10,2448", got)
	}
}

// syntheticNormal: tráfico normal de 6 características — mayormente ceros y
// unos, como en la realidad — más unos pocos valores medianos.
func syntheticNormal(n int, rng *rand.Rand) [][]float64 {
	data := make([][]float64, n)
	for i := range data {
		fallos := float64(rng.IntN(4))
		data[i] = []float64{fallos, float64(rng.IntN(20)), math.Min(fallos, 2), math.Min(fallos, 2), 0, 0}
		if rng.IntN(10) == 0 {
			data[i][0] += float64(rng.IntN(3))
		}
	}
	return data
}

func TestForest_AnomaliasPuntuanMasQueLoNormal(t *testing.T) {
	rng := rand.New(rand.NewPCG(1, 2))
	data := syntheticNormal(2000, rng)
	forest, err := trainForest(data, 100, 256, rand.New(rand.NewPCG(7, 7)))
	if err != nil {
		t.Fatalf("trainForest: %v", err)
	}

	var normalSum float64
	for _, x := range data[:500] {
		s := forest.Score(x)
		if s <= 0 || s >= 1 {
			t.Fatalf("puntaje fuera de (0,1): %v", s)
		}
		normalSum += s
	}
	normalAvg := normalSum / 500

	attack := []float64{60, 0, 1, 40, 12, 0}
	attackScore := forest.Score(attack)
	if attackScore <= normalAvg+0.15 {
		t.Fatalf("puntaje del ataque %.3f no se separa del promedio normal %.3f", attackScore, normalAvg)
	}
	if attackScore < DefaultIFThreshold {
		t.Fatalf("puntaje del ataque %.3f bajo el umbral por defecto %.2f", attackScore, DefaultIFThreshold)
	}
	if normalAvg >= DefaultIFThreshold {
		t.Fatalf("el promedio normal %.3f ya supera el umbral por defecto", normalAvg)
	}
}

func TestForest_MismaSemillaMismoBosque(t *testing.T) {
	data := syntheticNormal(1000, rand.New(rand.NewPCG(3, 4)))
	a, _ := trainForest(data, 20, 64, rand.New(rand.NewPCG(9, 9)))
	b, _ := trainForest(data, 20, 64, rand.New(rand.NewPCG(9, 9)))
	c, _ := trainForest(data, 20, 64, rand.New(rand.NewPCG(10, 10)))
	probe := []float64{30, 2, 1, 10, 3, 0}
	if a.Score(probe) != b.Score(probe) {
		t.Fatal("misma semilla dio puntajes distintos")
	}
	if a.Score(probe) == c.Score(probe) {
		t.Fatal("semillas distintas dieron exactamente el mismo puntaje: la semilla no se está usando")
	}
}

func TestForest_ParametrosYAlturaMaxima(t *testing.T) {
	data := syntheticNormal(500, rand.New(rand.NewPCG(5, 6)))
	f, err := trainForest(data, 10, 256, rand.New(rand.NewPCG(1, 1)))
	if err != nil {
		t.Fatalf("trainForest: %v", err)
	}
	if len(f.Trees) != 10 || f.SampleSize != 256 {
		t.Fatalf("árboles=%d submuestra=%d, want 10 y 256", len(f.Trees), f.SampleSize)
	}
	// Altura máxima ceil(log2 256) = 8 → a lo sumo 2^9 − 1 nodos por árbol.
	for i, tr := range f.Trees {
		if len(tr.Nodes) > 511 {
			t.Fatalf("árbol %d con %d nodos, pasa el máximo de 511 para altura 8", i, len(tr.Nodes))
		}
	}
	// Con menos datos que ψ, la submuestra se reduce a los datos disponibles.
	small, _ := trainForest(data[:40], 5, 256, rand.New(rand.NewPCG(1, 1)))
	if small.SampleSize != 40 {
		t.Fatalf("submuestra = %d, want 40", small.SampleSize)
	}
	if _, err := trainForest(data[:1], 5, 256, rand.New(rand.NewPCG(1, 1))); err == nil {
		t.Fatal("entrenar con 1 punto debe dar error")
	}
}

func unitsFrom(keyType string, data [][]float64) []Unit {
	units := make([]Unit, len(data))
	for i, d := range data {
		units[i] = Unit{
			WindowStart: t0.Add(time.Duration(i) * WindowSize), KeyType: keyType, TenantID: "T", IP: "1.1.1.1",
			Features: Features{Fallos: int(d[0]), Correctos: int(d[1]), IPsDistintasConFallos: int(d[2]), CuentasDistintasAtacadas: int(d[3]), IntentosCuentaInexistente: int(d[4]), IntentosContraSenuelos: int(d[5])},
		}
	}
	return units
}

func TestTrainModel_PocosDatosDaError(t *testing.T) {
	units := unitsFrom(KeyIP, syntheticNormal(MinTrainingUnits-1, rand.New(rand.NewPCG(1, 1))))
	if _, err := TrainModel(units, DefaultTrainParams()); err == nil {
		t.Fatal("con menos ventanas que el mínimo debe dar error")
	}
}

func TestTrainModel_OmiteElTipoDeClaveSinDatosSuficientes(t *testing.T) {
	units := unitsFrom(KeyIP, syntheticNormal(300, rand.New(rand.NewPCG(1, 1))))
	m, err := TrainModel(units, TrainParams{Trees: 10, SampleSize: 64, Seed: 1})
	if err != nil {
		t.Fatalf("TrainModel: %v", err)
	}
	if m.Keys[KeyIP] == nil || m.Keys[KeyTenant] != nil {
		t.Fatalf("claves del modelo = %v, want solo ip", m.Keys)
	}
	if _, ok := m.Score(KeyTenant, Features{Fallos: 100}); ok {
		t.Fatal("sin bosque de tenant, Score debe reportar ok=false")
	}
	if _, ok := m.Score(KeyIP, Features{Fallos: 100}); !ok {
		t.Fatal("con bosque de ip, Score debe reportar ok=true")
	}
}

func TestModel_NilNoRompe(t *testing.T) {
	var m *Model
	if _, ok := m.Score(KeyIP, Features{Fallos: 100}); ok {
		t.Fatal("un modelo nil no debe puntuar")
	}
	if got := m.Explain(KeyIP, Features{Fallos: 100}); len(got) != 1 {
		t.Fatalf("Explain sobre modelo nil = %v, want un motivo genérico", got)
	}
}

func TestModel_GuardarCargarYReproducible(t *testing.T) {
	data := syntheticNormal(400, rand.New(rand.NewPCG(11, 12)))
	units := append(unitsFrom(KeyTenant, data), unitsFrom(KeyIP, data)...)
	p := TrainParams{Trees: 15, SampleSize: 128, Seed: 99}

	m1, err := TrainModel(units, p)
	if err != nil {
		t.Fatalf("TrainModel: %v", err)
	}
	// Mismo entrenamiento con las unidades en otro orden: el resultado no
	// depende del orden en que llegaron.
	reversed := make([]Unit, len(units))
	for i, u := range units {
		reversed[len(units)-1-i] = u
	}
	m2, _ := TrainModel(reversed, p)

	dir := t.TempDir()
	p1, p2 := filepath.Join(dir, "a.json"), filepath.Join(dir, "b.json")
	if err := m1.Save(p1); err != nil {
		t.Fatalf("Save: %v", err)
	}
	if err := m2.Save(p2); err != nil {
		t.Fatalf("Save: %v", err)
	}
	b1, _ := os.ReadFile(p1)
	b2, _ := os.ReadFile(p2)
	if !bytes.Equal(b1, b2) {
		t.Fatal("mismos datos y misma semilla dieron archivos distintos")
	}

	loaded, err := LoadModel(p1)
	if err != nil {
		t.Fatalf("LoadModel: %v", err)
	}
	f := Features{Fallos: 50, CuentasDistintasAtacadas: 30, IPsDistintasConFallos: 1}
	for _, key := range []string{KeyTenant, KeyIP} {
		s1, _ := m1.Score(key, f)
		s2, _ := loaded.Score(key, f)
		if s1 != s2 {
			t.Fatalf("puntaje de %s cambió tras guardar y cargar: %v vs %v", key, s1, s2)
		}
	}
}

func TestLoadModel_RechazaArchivosDanados(t *testing.T) {
	dir := t.TempDir()
	write := func(name, content string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
		return p
	}
	if _, err := LoadModel(filepath.Join(dir, "no-existe.json")); !os.IsNotExist(err) && !strings.Contains(err.Error(), "cannot find") && !strings.Contains(err.Error(), "no such file") {
		t.Fatalf("un archivo inexistente debe reportar que no existe: %v", err)
	}
	cases := map[string]string{
		"no-json.json":    `esto no es json`,
		"version.json":    `{"version": 99}`,
		"features.json":   `{"version": 1, "features": ["otra"], "keys": {}}`,
		"sin-claves.json": `{"version": 1, "features": ["fallos","correctos","ips_distintas_con_fallos","cuentas_distintas_atacadas","intentos_cuenta_inexistente","intentos_contra_senuelos"], "keys": {}}`,
	}
	for name, content := range cases {
		if _, err := LoadModel(write(name, content)); err == nil {
			t.Fatalf("%s: LoadModel debió fallar", name)
		}
	}

	// Un árbol cuyos hijos apuntan hacia atrás (ciclo) no debe cargarse.
	cycle := `{"version":1,"features":["fallos","correctos","ips_distintas_con_fallos","cuentas_distintas_atacadas","intentos_cuenta_inexistente","intentos_contra_senuelos"],
		"keys":{"ip":{"training_units":100,"stats":[{},{},{},{},{},{}],"forest":{"sample_size":16,"trees":[{"nodes":[{"f":0,"s":1,"l":0,"r":0}]}]}}}}`
	if _, err := LoadModel(write("ciclo.json", cycle)); err == nil {
		t.Fatal("un árbol con ciclo debió rechazarse")
	}
}

func TestExplain_TextoYOrden(t *testing.T) {
	// Tráfico normal: 3 fallos, 2 cuentas, resto ~0, con algo de variación.
	rng := rand.New(rand.NewPCG(21, 22))
	data := make([][]float64, 300)
	for i := range data {
		data[i] = []float64{float64(2 + rng.IntN(3)), float64(8 + rng.IntN(5)), 1, float64(1 + rng.IntN(3)), 0, 0}
	}
	m, err := TrainModel(unitsFrom(KeyIP, data), TrainParams{Trees: 10, SampleSize: 64, Seed: 1})
	if err != nil {
		t.Fatalf("TrainModel: %v", err)
	}

	got := m.Explain(KeyIP, Features{Fallos: 42, Correctos: 10, IPsDistintasConFallos: 1, CuentasDistintasAtacadas: 17})
	if len(got) == 0 || len(got) > explainTopN {
		t.Fatalf("motivos = %v, want entre 1 y %d", got, explainTopN)
	}
	joined := strings.Join(got, " | ")
	if !strings.Contains(joined, "42 fallos en 10 min (lo normal es 3)") {
		t.Fatalf("falta el motivo de fallos con su valor normal: %v", got)
	}
	if !strings.Contains(joined, "17 cuentas distintas atacadas en 10 min (lo normal es 2)") {
		t.Fatalf("falta el motivo de cuentas con su valor normal: %v", got)
	}
	// Los correctos (10) están dentro de lo normal: no deben aparecer.
	if strings.Contains(joined, "inicios de sesión correctos") {
		t.Fatalf("una característica normal apareció como motivo: %v", got)
	}

	// Algo por debajo de lo normal tampoco es motivo; nunca queda vacío.
	got = m.Explain(KeyIP, Features{})
	if len(got) != 1 || !strings.Contains(got[0], "puntaje de aislamiento alto") {
		t.Fatalf("sin nada sobre lo normal debe dar el motivo genérico, dio %v", got)
	}
}

func TestFormatNumber(t *testing.T) {
	if formatNumber(3) != "3" || formatNumber(2.5) != "2,5" {
		t.Fatalf("formatNumber(3)=%q formatNumber(2,5)=%q", formatNumber(3), formatNumber(2.5))
	}
}

func TestLoadConfig_ValoresPorDefectoYValidacion(t *testing.T) {
	for _, k := range []string{"DETECTOR_IF_QUANTILE", "DETECTOR_ENABLED", "DETECTOR_INTERVAL", "DETECTOR_LOOKBACK", "DETECTOR_MODEL_PATH", "DETECTOR_IF_THRESHOLD",
		"DETECTOR_IF_TREES", "DETECTOR_IF_SUBSAMPLE", "DETECTOR_IF_SEED", "DETECTOR_RULE_FALLOS", "DETECTOR_RULE_CUENTAS", "DETECTOR_RULE_IPS", "DETECTOR_RULE_INEXISTENTES"} {
		t.Setenv(k, "")
	}
	cfg, err := LoadConfig()
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if cfg.Enabled {
		t.Fatal("el detector debe venir apagado por defecto")
	}
	if cfg.Train.Trees != 100 || cfg.Train.SampleSize != 256 || cfg.Train.ThresholdQuantile != 0.995 || cfg.Rules != DefaultRules() {
		t.Fatalf("valores por defecto inesperados: %+v", cfg)
	}
	if cfg.IFThreshold != 0 {
		t.Fatalf("sin DETECTOR_IF_THRESHOLD debe quedar en 0 (usar el umbral calibrado del modelo), quedó %v", cfg.IFThreshold)
	}

	t.Setenv("DETECTOR_ENABLED", "true")
	t.Setenv("DETECTOR_RULE_FALLOS", "7")
	t.Setenv("DETECTOR_IF_THRESHOLD", "0.7")
	cfg, err = LoadConfig()
	if err != nil || !cfg.Enabled || cfg.Rules.Fallos != 7 || cfg.IFThreshold != 0.7 {
		t.Fatalf("variables de entorno no aplicadas: %+v, %v", cfg, err)
	}

	t.Setenv("DETECTOR_IF_THRESHOLD", "1.5")
	if _, err := LoadConfig(); err == nil {
		t.Fatal("un umbral fuera de (0,1) debe dar error")
	}
	t.Setenv("DETECTOR_IF_THRESHOLD", "0.6")
	t.Setenv("DETECTOR_IF_QUANTILE", "1")
	if _, err := LoadConfig(); err == nil {
		t.Fatal("un cuantil fuera de (0,1) debe dar error")
	}
	t.Setenv("DETECTOR_IF_QUANTILE", "")
	t.Setenv("DETECTOR_IF_THRESHOLD", "0.6")
	t.Setenv("DETECTOR_RULE_FALLOS", "muchos")
	if _, err := LoadConfig(); err == nil {
		t.Fatal("un valor no numérico debe dar error")
	}
}

func TestTrainModel_UmbralCalibradoConElEntrenamiento(t *testing.T) {
	data := syntheticNormal(2000, rand.New(rand.NewPCG(41, 42)))
	units := unitsFrom(KeyIP, data)
	m, err := TrainModel(units, TrainParams{Trees: 50, SampleSize: 128, Seed: 3})
	if err != nil {
		t.Fatalf("TrainModel: %v", err)
	}
	km := m.Keys[KeyIP]
	if km.ThresholdQuantile != DefaultThresholdQuantile || km.Threshold <= 0 || km.Threshold >= 1 {
		t.Fatalf("umbral = %v (cuantil %v), want un puntaje en (0,1) calibrado con %v", km.Threshold, km.ThresholdQuantile, DefaultThresholdQuantile)
	}
	if m.Threshold(KeyIP) != km.Threshold {
		t.Fatalf("Model.Threshold = %v, want %v", m.Threshold(KeyIP), km.Threshold)
	}

	// Por construcción, a lo más el 0,5 % del propio tráfico de entrenamiento
	// alcanza el umbral (aunque muchas ventanas idénticas compartan puntaje).
	flagged := 0
	for _, x := range data {
		if s, _ := m.Score(KeyIP, unitsFrom(KeyIP, [][]float64{x})[0].Features); s >= km.Threshold {
			flagged++
		}
	}
	if max := int(math.Ceil(0.005 * float64(len(data)))); flagged > max {
		t.Fatalf("%d ventanas de entrenamiento alcanzan el umbral, más que el 0,5 %% esperado (%d)", flagged, max)
	}

	// Un ataque claro lo supera con holgura.
	if s, _ := m.Score(KeyIP, Features{Fallos: 60, CuentasDistintasAtacadas: 40, IntentosCuentaInexistente: 12}); s < km.Threshold {
		t.Fatalf("un ataque claro puntúa %.3f, bajo el umbral calibrado %.3f", s, km.Threshold)
	}

	// Sobrevive a guardar y cargar.
	path := filepath.Join(t.TempDir(), "m.json")
	if err := m.Save(path); err != nil {
		t.Fatal(err)
	}
	loaded, err := LoadModel(path)
	if err != nil || loaded.Threshold(KeyIP) != km.Threshold {
		t.Fatalf("umbral tras cargar = %v (%v), want %v", loaded.Threshold(KeyIP), err, km.Threshold)
	}

	if _, err := TrainModel(units, TrainParams{Trees: 5, SampleSize: 64, Seed: 1, ThresholdQuantile: 1.5}); err == nil {
		t.Fatal("un cuantil fuera de (0,1) debe dar error")
	}
}

func TestDetector_UmbralDelBosque(t *testing.T) {
	m, err := TrainModel(unitsFrom(KeyIP, syntheticNormal(300, rand.New(rand.NewPCG(1, 1)))), TrainParams{Trees: 10, SampleSize: 64, Seed: 1})
	if err != nil {
		t.Fatal(err)
	}
	if got := New(nil, DefaultRules(), m, 0, nil).IFThreshold(KeyIP); got != m.Threshold(KeyIP) {
		t.Fatalf("sin umbral configurado debe usar el calibrado del modelo: %v vs %v", got, m.Threshold(KeyIP))
	}
	if got := New(nil, DefaultRules(), m, 0.7, nil).IFThreshold(KeyIP); got != 0.7 {
		t.Fatalf("DETECTOR_IF_THRESHOLD debe pisar al calibrado: %v", got)
	}
	if got := New(nil, DefaultRules(), nil, 0, nil).IFThreshold(KeyIP); got != DefaultIFThreshold {
		t.Fatalf("sin modelo ni umbral configurado: %v, want el de respaldo %v", got, DefaultIFThreshold)
	}
}
