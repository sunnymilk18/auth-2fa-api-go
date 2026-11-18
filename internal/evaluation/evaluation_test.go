package evaluation_test

import (
	"strings"
	"testing"
	"time"

	"auth-2fa-api/internal/detector"
	"auth-2fa-api/internal/evaluation"
	"auth-2fa-api/internal/simulate"
)

var w0 = time.Date(2026, 10, 12, 10, 0, 0, 0, time.UTC)

func unit(win int, keyType, key string, f detector.Features) detector.Unit {
	u := detector.Unit{WindowStart: w0.Add(time.Duration(win) * detector.WindowSize), KeyType: keyType, Features: f}
	if keyType == detector.KeyTenant {
		u.TenantID = key
	} else {
		u.IP = key
	}
	return u
}

type opts struct{ rules, decoys, forest bool }

func analysis(u detector.Unit, o opts) detector.Analysis {
	a := detector.Analysis{Unit: u, ForestAlert: o.forest}
	if o.rules {
		a.RuleMotives = []string{"regla"}
	}
	if o.decoys {
		a.DecoyMotives = []string{"señuelo"}
	}
	return a
}

func label(incident int, scenario string, win int, tenant, ip string) simulate.Label {
	s := w0.Add(time.Duration(win) * detector.WindowSize)
	return simulate.Label{Incident: incident, Scenario: scenario, WindowStart: s, WindowEnd: s.Add(detector.WindowSize), Key: simulate.Key{TenantID: tenant, Tenant: "sim-" + tenant, IP: ip}}
}

func methodResult(t *testing.T, r *evaluation.Report, m string) evaluation.MethodResult {
	t.Helper()
	for _, mr := range r.Methods {
		if mr.Method == m {
			return mr
		}
	}
	t.Fatalf("falta el método %s", m)
	return evaluation.MethodResult{}
}

func TestEvaluate_MatrizDeConfusionYMetricas(t *testing.T) {
	// Ventana 0: relleno de credenciales de la IP "9.9.9.9" contra T1 → positivas: tenant T1 e IP 9.9.9.9.
	// Ventana 1: ataque distribuido contra T2 → positiva solo la unidad de T2 (sin IP en la etiqueta).
	// Ventana 2: toque a señuelos desde 8.8.8.8 contra T1.
	labels := []simulate.Label{
		label(1, simulate.ScenarioStuffing, 0, "T1", "9.9.9.9"),
		label(2, simulate.ScenarioDistributed, 1, "T2", ""),
		label(3, simulate.ScenarioDecoy, 2, "T1", "8.8.8.8"),
	}
	decoyF := detector.Features{IntentosContraSenuelos: 2}
	analyses := []detector.Analysis{
		// Positivas del relleno: las reglas ven la IP, el bosque ve las dos.
		analysis(unit(0, detector.KeyTenant, "T1", detector.Features{Fallos: 40}), opts{forest: true}),
		analysis(unit(0, detector.KeyIP, "9.9.9.9", detector.Features{Fallos: 40}), opts{rules: true, forest: true}),
		// Distribuido: la unidad del tenant solo la ve el bosque; una IP suelta del ataque es normal.
		analysis(unit(1, detector.KeyTenant, "T2", detector.Features{Fallos: 60}), opts{forest: true}),
		analysis(unit(1, detector.KeyIP, "7.7.7.7", detector.Features{Fallos: 1}), opts{}),
		// Señuelos: positivas tenant T1 e IP 8.8.8.8, solo la regla de señuelos las ve.
		analysis(unit(2, detector.KeyTenant, "T1", decoyF), opts{decoys: true}),
		analysis(unit(2, detector.KeyIP, "8.8.8.8", decoyF), opts{decoys: true}),
		// Normales: una falsa alarma de las reglas, una del bosque, y tres sin alerta.
		analysis(unit(3, detector.KeyIP, "1.1.1.1", detector.Features{Correctos: 30}), opts{rules: true}),
		analysis(unit(3, detector.KeyIP, "2.2.2.2", detector.Features{Correctos: 3}), opts{forest: true}),
		analysis(unit(3, detector.KeyIP, "3.3.3.3", detector.Features{}), opts{}),
		analysis(unit(3, detector.KeyTenant, "T3", detector.Features{}), opts{}),
		analysis(unit(4, detector.KeyIP, "4.4.4.4", detector.Features{}), opts{}),
	}

	r := evaluation.Evaluate(analyses, labels)
	if r.Units != 11 || r.PositiveUnits != 5 {
		t.Fatalf("unidades = %d, positivas = %d, want 11 y 5 (el ataque distribuido solo marca la unidad del tenant)", r.Units, r.PositiveUnits)
	}

	want := map[string]evaluation.Counts{
		evaluation.MethodRules:    {TP: 1, FP: 1, FN: 4, TN: 5},
		evaluation.MethodDecoys:   {TP: 2, FP: 0, FN: 3, TN: 6},
		evaluation.MethodBaseline: {TP: 3, FP: 1, FN: 2, TN: 5},
		evaluation.MethodForest:   {TP: 3, FP: 1, FN: 2, TN: 5},
		evaluation.MethodCombined: {TP: 5, FP: 2, FN: 0, TN: 4},
	}
	for m, c := range want {
		if got := methodResult(t, r, m).Overall; got != c {
			t.Errorf("%s: matriz = %+v, want %+v", m, got, c)
		}
	}

	rules := methodResult(t, r, evaluation.MethodRules).Overall
	if p := rules.Precision(); p.Value() != 0.5 {
		t.Errorf("precisión de reglas = %v, want 0,5", p.Value())
	}
	if rec := rules.Recall(); rec.Num != 1 || rec.Den != 5 {
		t.Errorf("exhaustividad de reglas = %+v, want 1/5", rec)
	}
	// F1 = 2·VP / (2·VP + FP + FN) = 2/7.
	if f1 := rules.F1(); f1.Num != 2 || f1.Den != 7 {
		t.Errorf("F1 de reglas = %+v, want 2/7", f1)
	}
	if fpr := rules.FPR(); fpr.Num != 1 || fpr.Den != 6 {
		t.Errorf("tasa de falsos positivos de reglas = %+v, want 1/6", fpr)
	}

	// Desglose por tipo de clave.
	if got := methodResult(t, r, evaluation.MethodForest).ByKey[detector.KeyTenant]; got.TP != 2 {
		t.Errorf("el bosque debe acertar 2 unidades de tenant (relleno y distribuido), tiene %+v", got)
	}
}

func TestEvaluate_DeteccionPorEscenarioEIncidente(t *testing.T) {
	// Un ataque de 3 ventanas (incidente 1): las reglas lo ven solo en la tercera.
	// Otro de 1 ventana (incidente 2) que nadie ve.
	labels := []simulate.Label{
		label(1, simulate.ScenarioBruteForce, 0, "T1", "9.9.9.9"),
		label(1, simulate.ScenarioBruteForce, 1, "T1", "9.9.9.9"),
		label(1, simulate.ScenarioBruteForce, 2, "T1", "9.9.9.9"),
		label(2, simulate.ScenarioBruteForce, 5, "T2", "6.6.6.6"),
	}
	var analyses []detector.Analysis
	for win := 0; win < 3; win++ {
		analyses = append(analyses,
			analysis(unit(win, detector.KeyTenant, "T1", detector.Features{}), opts{}),
			analysis(unit(win, detector.KeyIP, "9.9.9.9", detector.Features{}), opts{rules: win == 2}))
	}
	analyses = append(analyses,
		analysis(unit(5, detector.KeyTenant, "T2", detector.Features{}), opts{}),
		analysis(unit(5, detector.KeyIP, "6.6.6.6", detector.Features{}), opts{}))

	r := evaluation.Evaluate(analyses, labels)
	var s evaluation.ScenarioResult
	for _, sc := range r.Scenarios {
		if sc.Scenario == simulate.ScenarioBruteForce {
			s = sc
		}
	}
	if s.Windows != 4 || s.Incidents != 2 {
		t.Fatalf("ventanas = %d, incidentes = %d, want 4 y 2", s.Windows, s.Incidents)
	}
	if s.DetectedWindows[evaluation.MethodRules] != 1 || s.DetectedIncidents[evaluation.MethodRules] != 1 {
		t.Fatalf("reglas: ventanas %d, incidentes %d, want 1 y 1", s.DetectedWindows[evaluation.MethodRules], s.DetectedIncidents[evaluation.MethodRules])
	}
	if s.DetectedWindows[evaluation.MethodForest] != 0 || s.DetectedIncidents[evaluation.MethodCombined] != 1 {
		t.Fatalf("el bosque no vio nada y el combinado vio el incidente 1: %+v", s)
	}
}

func TestEvaluate_Senuelos(t *testing.T) {
	f := detector.Features{IntentosContraSenuelos: 1}
	analyses := []detector.Analysis{
		analysis(unit(0, detector.KeyIP, "8.8.8.8", f), opts{decoys: true}),                // solo señuelos
		analysis(unit(1, detector.KeyIP, "8.8.4.4", f), opts{decoys: true, forest: true}),  // señuelos y bosque
		analysis(unit(2, detector.KeyIP, "5.5.5.5", detector.Features{Fallos: 1}), opts{}), // sin señuelo: no cuenta
	}
	r := evaluation.Evaluate(analyses, nil)
	if r.Decoys.Units != 2 || r.Decoys.Detected[evaluation.MethodDecoys] != 2 || r.Decoys.Detected[evaluation.MethodForest] != 1 ||
		r.Decoys.Detected[evaluation.MethodRules] != 0 || r.Decoys.OnlyDecoys != 1 {
		t.Fatalf("señuelos = %+v", r.Decoys)
	}
}

func TestEvaluate_IgnoraEtiquetasFueraDeLoAnalizado(t *testing.T) {
	analyses := []detector.Analysis{analysis(unit(0, detector.KeyIP, "1.1.1.1", detector.Features{}), opts{})}
	labels := []simulate.Label{label(1, simulate.ScenarioStuffing, 99, "T1", "9.9.9.9")} // otra ventana
	r := evaluation.Evaluate(analyses, labels)
	if r.PositiveUnits != 0 || methodResult(t, r, evaluation.MethodRules).Overall.FN != 0 {
		t.Fatalf("una etiqueta fuera del rango analizado no debe contar como falso negativo: %+v", r)
	}
}

func TestReport_FormatosMarkdownYCSV(t *testing.T) {
	labels := []simulate.Label{label(1, simulate.ScenarioStuffing, 0, "T1", "9.9.9.9")}
	analyses := []detector.Analysis{
		analysis(unit(0, detector.KeyTenant, "T1", detector.Features{}), opts{rules: true}),
		analysis(unit(0, detector.KeyIP, "9.9.9.9", detector.Features{}), opts{rules: true}),
		analysis(unit(1, detector.KeyIP, "1.1.1.1", detector.Features{}), opts{}),
	}
	r := evaluation.Evaluate(analyses, labels)

	md := r.Markdown(evaluation.Header{Seed: 42, EvalFrom: w0, EvalTo: w0.AddDate(0, 0, 1), TrainingFrom: w0.AddDate(0, 0, -7), TrainingTo: w0,
		Rules: detector.DefaultRules(), IFThresholds: map[string]float64{detector.KeyTenant: 0.7123, detector.KeyIP: 0.6987}, ThresholdQuantile: 0.995,
		Trees: 100, SampleSize: 256, ModelSeed: 42, TrainingUnits: map[string]int{detector.KeyTenant: 10, detector.KeyIP: 20}})
	for _, want := range []string{
		"# Resultados de la evaluación", "| Método | VP | FP | FN | VN |", "| Reglas (umbrales) | 2 | 0 | 0 | 1 | 1,000 | 1,000 | 1,000 | 0,000 |",
		"## Detección por escenario (ventanas atacadas detectadas)", "Relleno de credenciales", "1/1 (100,0 %)", "## Detección de señuelos",
		"calibrado con el cuantil 0,995", "0,712 por tenant, 0,699 por IP", "t = 100 árboles", "## Isolation Forest: AUC-ROC y sensibilidad al umbral",
	} {
		if !strings.Contains(md, want) {
			t.Errorf("el Markdown no contiene %q:\n%s", want, md)
		}
	}
	// Sin alertas de ningún método (el bosque): precisión no definida, no 0.
	if !strings.Contains(md, "| Isolation Forest | 0 | 0 | 2 | 1 | n/d | 0,000 | 0,000 | 0,000 |") {
		t.Errorf("un método sin alertas debe mostrar precisión n/d:\n%s", md)
	}

	csv := r.MetricsCSV()
	if !strings.HasPrefix(csv, "metodo,clave,vp,fp,fn,vn,precision,exhaustividad,f1,tasa_falsos_positivos\n") || !strings.Contains(csv, "reglas,todas,2,0,0,1,1.0000,1.0000,1.0000,0.0000\n") {
		t.Errorf("CSV de métricas inesperado:\n%s", csv)
	}
	if !strings.Contains(csv, "isolation_forest,todas,0,0,2,1,,0.0000,0.0000,0.0000\n") {
		t.Errorf("la precisión indefinida debe ir vacía en el CSV:\n%s", csv)
	}
	if !strings.Contains(r.ScenariosCSV(), "relleno_credenciales,ventana,reglas,1,1,1.0000\n") {
		t.Errorf("CSV de escenarios inesperado:\n%s", r.ScenariosCSV())
	}
	if !strings.HasPrefix(r.DecoysCSV(), "metodo,unidades_con_senuelo,detectadas,tasa_deteccion\n") {
		t.Errorf("CSV de señuelos inesperado:\n%s", r.DecoysCSV())
	}
}

func scored(a detector.Analysis, score float64) detector.Analysis {
	a.Score = &score
	return a
}

// Las IPs participantes de un ataque distribuido no se cuentan: ni como
// falsos positivos (aunque el método las marque) ni como positivos.
func TestEvaluate_ExcluyeLasIPsDelAtaqueDistribuido(t *testing.T) {
	l := label(1, simulate.ScenarioDistributed, 0, "T1", "")
	l.Key.IPs = []string{"7.7.7.7", "7.7.7.8"}
	analyses := []detector.Analysis{
		analysis(unit(0, detector.KeyTenant, "T1", detector.Features{Fallos: 60}), opts{forest: true}),
		analysis(unit(0, detector.KeyIP, "7.7.7.7", detector.Features{Fallos: 1}), opts{forest: true}), // bot: el bosque la marca
		analysis(unit(0, detector.KeyIP, "7.7.7.8", detector.Features{Fallos: 1}), opts{}),             // bot
		analysis(unit(0, detector.KeyIP, "1.1.1.1", detector.Features{}), opts{forest: true}),          // normal: sí es FP
		analysis(unit(0, detector.KeyIP, "2.2.2.2", detector.Features{}), opts{}),
	}
	r := evaluation.Evaluate(analyses, []simulate.Label{l})
	if r.ExcludedUnits != 2 || r.Units != 3 || r.PositiveUnits != 1 {
		t.Fatalf("excluidas=%d evaluadas=%d positivas=%d, want 2, 3 y 1", r.ExcludedUnits, r.Units, r.PositiveUnits)
	}
	if got := methodResult(t, r, evaluation.MethodForest).Overall; got != (evaluation.Counts{TP: 1, FP: 1, FN: 0, TN: 1}) {
		t.Fatalf("matriz del bosque = %+v, want 1 VP, 1 FP (solo la IP normal), 0 FN, 1 VN", got)
	}
	if md := r.Markdown(evaluation.Header{IFThresholds: map[string]float64{}}); !strings.Contains(md, "Excluidas de la matriz: 2 unidades") {
		t.Fatalf("el Markdown debe avisar de las unidades excluidas:\n%s", md)
	}
}

func TestEvaluate_AUCYSensibilidadAlUmbral(t *testing.T) {
	labels := []simulate.Label{label(1, simulate.ScenarioBruteForce, 0, "T1", "9.9.9.9")}
	analyses := []detector.Analysis{
		scored(analysis(unit(0, detector.KeyIP, "9.9.9.9", detector.Features{}), opts{}), 0.90), // positiva
		scored(analysis(unit(0, detector.KeyIP, "1.1.1.1", detector.Features{}), opts{}), 0.50),
		scored(analysis(unit(0, detector.KeyIP, "2.2.2.2", detector.Features{}), opts{}), 0.62),
		scored(analysis(unit(0, detector.KeyIP, "3.3.3.3", detector.Features{}), opts{}), 0.90), // empata con la positiva
		scored(analysis(unit(0, detector.KeyTenant, "T1", detector.Features{}), opts{}), 0.80),  // positiva
		scored(analysis(unit(0, detector.KeyTenant, "T2", detector.Features{}), opts{}), 0.40),
	}
	r := evaluation.Evaluate(analyses, labels)

	// IP: 1 positiva (0,90) contra 3 negativas (0,50 · 0,62 · 0,90): gana 2, empata 1 → (2 + 0,5) / 3.
	if auc := r.AUC[detector.KeyIP]; auc.Num != 5 || auc.Den != 6 {
		t.Fatalf("AUC por IP = %+v, want 5/6", auc)
	}
	// Tenant: la positiva supera a la única negativa → AUC 1.
	if auc := r.AUC[detector.KeyTenant]; auc.Value() != 1 {
		t.Fatalf("AUC por tenant = %+v, want 1", auc)
	}

	byThreshold := map[float64]evaluation.Counts{}
	for _, s := range r.Sweep {
		byThreshold[s.Threshold] = s.Counts
	}
	// Con 0,60: marca 0,90 (pos), 0,62, 0,90 (neg) y 0,80 (pos) → 2 VP, 2 FP, 0 FN, 2 VN.
	if got := byThreshold[0.60]; got != (evaluation.Counts{TP: 2, FP: 2, FN: 0, TN: 2}) {
		t.Fatalf("umbral 0,60: %+v", got)
	}
	// Con 0,85: solo marca las dos de 0,90 → 1 VP, 1 FP, 1 FN (la de tenant, 0,80), 3 VN.
	if got := byThreshold[0.85]; got != (evaluation.Counts{TP: 1, FP: 1, FN: 1, TN: 3}) {
		t.Fatalf("umbral 0,85: %+v", got)
	}
	if !strings.Contains(r.SweepCSV(), "auc_ip,0.8333\n") {
		t.Fatalf("el CSV del umbral debe traer el AUC:\n%s", r.SweepCSV())
	}
}
