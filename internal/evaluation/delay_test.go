package evaluation_test

import (
	"strings"
	"testing"
	"time"

	"auth-2fa-api/internal/detector"
	"auth-2fa-api/internal/evaluation"
	"auth-2fa-api/internal/simulate"
)

// attackWindow arma la etiqueta y las dos unidades positivas (tenant e IP) de
// una ventana de un incidente. Cada incidente k usa su propio tenant e IP, así
// que los incidentes no se mezclan entre sí.
func attackWindow(incident int, scenario string, win int, flaggedTenant, flaggedIP opts) (simulate.Label, []detector.Analysis) {
	tenant := "T" + string(rune('0'+incident))
	ip := "9.9.9." + string(rune('0'+incident))
	l := label(incident, scenario, win, tenant, ip)
	return l, []detector.Analysis{
		analysis(unit(win, detector.KeyTenant, tenant, detector.Features{}), flaggedTenant),
		analysis(unit(win, detector.KeyIP, ip, detector.Features{}), flaggedIP),
	}
}

type incidentSpec struct {
	incident int
	scenario string
	first    int
	// flaggedFrom: índice (dentro del incidente) de la primera ventana en que
	// el método alerta; -1 = nunca.
	flaggedFrom int
	windows     int
}

func build(specs ...incidentSpec) ([]detector.Analysis, []simulate.Label) {
	var analyses []detector.Analysis
	var labels []simulate.Label
	for _, s := range specs {
		for i := 0; i < s.windows; i++ {
			o := opts{}
			if s.flaggedFrom >= 0 && i >= s.flaggedFrom {
				o = opts{rules: true}
			}
			l, as := attackWindow(s.incident, s.scenario, s.first+i, o, o)
			labels = append(labels, l)
			analyses = append(analyses, as...)
		}
	}
	return analyses, labels
}

func delayOf(t *testing.T, r *evaluation.Report, scenario, method string) evaluation.DelayResult {
	t.Helper()
	for _, d := range r.Delays {
		if d.Scenario == scenario && d.Method == method {
			return d
		}
	}
	t.Fatalf("falta el resultado de tiempo de %s / %s", scenario, method)
	return evaluation.DelayResult{}
}

func TestDelay_IncidenteDeUnaVentanaDetectadoEnLaPrimera(t *testing.T) {
	analyses, labels := build(incidentSpec{1, simulate.ScenarioDecoy, 5, 0, 1})
	r := evaluation.Evaluate(analyses, labels)

	d := delayOf(t, r, simulate.ScenarioDecoy, evaluation.MethodRules)
	s := d.Stats()
	if s.Total != 1 || s.Detected != 1 || s.Undetected != 0 || s.Mean != 0 || s.Median != 0 || s.Max != 0 {
		t.Fatalf("stats = %+v, want 1 incidente detectado con retraso 0", s)
	}
	// Peor caso: fin de su ventana (10 min) + intervalo (5 min) − inicio = 15.
	mean, median, max, ok := d.WorstCaseMinutes(5 * time.Minute)
	if !ok || mean != 15 || median != 15 || max != 15 {
		t.Fatalf("peor caso = %v/%v/%v (ok=%v), want 15/15/15", mean, median, max, ok)
	}
	// Con otro intervalo del detector, el peor caso cambia con él.
	if mean, _, _, _ := d.WorstCaseMinutes(10 * time.Minute); mean != 20 {
		t.Fatalf("peor caso con intervalo de 10 min = %v, want 20", mean)
	}
}

func TestDelay_IncidenteDeVariasVentanasDetectadoTarde(t *testing.T) {
	// 4 ventanas; el método alerta desde la tercera (índice 2): retraso 2.
	analyses, labels := build(incidentSpec{2, simulate.ScenarioStuffing, 10, 2, 4})
	r := evaluation.Evaluate(analyses, labels)

	d := delayOf(t, r, simulate.ScenarioStuffing, evaluation.MethodRules)
	if s := d.Stats(); s.Detected != 1 || s.Mean != 2 || s.Max != 2 {
		t.Fatalf("stats = %+v, want retraso 2", s)
	}
	// Fin de la ventana detectada = 3 ventanas desde el inicio del ataque (30 min) + 5.
	if mean, _, max, _ := d.WorstCaseMinutes(5 * time.Minute); mean != 35 || max != 35 {
		t.Fatalf("peor caso = %v/%v, want 35", mean, max)
	}
	// Un método que nunca alertó no tiene retraso, y el incidente queda como sin detectar.
	if s := delayOf(t, r, simulate.ScenarioStuffing, evaluation.MethodForest).Stats(); s.Detected != 0 || s.Undetected != 1 {
		t.Fatalf("el bosque no alertó: %+v", s)
	}
}

func TestDelay_SoloCuentaLaPrimeraVentanaEnQueAlerto(t *testing.T) {
	// Alerta en las ventanas 1, 2 y 3 del incidente: el retraso es el de la primera (1).
	analyses, labels := build(incidentSpec{3, simulate.ScenarioSpraying, 0, 1, 4})
	d := delayOf(t, evaluation.Evaluate(analyses, labels), simulate.ScenarioSpraying, evaluation.MethodRules)
	if s := d.Stats(); s.Mean != 1 || s.Max != 1 || len(d.Delays) != 1 {
		t.Fatalf("stats = %+v delays = %v, want un solo retraso de 1", s, d.Delays)
	}
}

func TestDelay_IncidenteNoDetectadoNoEntraEnElPromedio(t *testing.T) {
	analyses, labels := build(
		incidentSpec{1, simulate.ScenarioBruteForce, 0, 0, 1},   // retraso 0
		incidentSpec{2, simulate.ScenarioBruteForce, 10, 3, 5},  // retraso 3
		incidentSpec{3, simulate.ScenarioBruteForce, 20, -1, 2}, // nunca detectado
	)
	r := evaluation.Evaluate(analyses, labels)

	s := delayOf(t, r, simulate.ScenarioBruteForce, evaluation.MethodRules).Stats()
	if s.Total != 3 || s.Detected != 2 || s.Undetected != 1 {
		t.Fatalf("conteos = %+v, want 3 incidentes, 2 detectados, 1 sin detectar", s)
	}
	if s.Mean != 1.5 || s.Median != 1.5 || s.Max != 3 {
		t.Fatalf("promedio/mediana/máximo = %v/%v/%v, want 1,5/1,5/3 (sin contar el no detectado)", s.Mean, s.Median, s.Max)
	}
	// Los otros escenarios no se mezclan.
	if s := delayOf(t, r, simulate.ScenarioStuffing, evaluation.MethodRules).Stats(); s.Total != 0 {
		t.Fatalf("un escenario sin incidentes debe tener 0: %+v", s)
	}
	// "todos" suma los de cualquier escenario.
	if s := delayOf(t, r, evaluation.ScenarioAll, evaluation.MethodRules).Stats(); s.Total != 3 || s.Detected != 2 {
		t.Fatalf("todos = %+v", s)
	}
}

func TestDelay_MedianaPromedioYMaximo(t *testing.T) {
	d := evaluation.DelayResult{Total: 5, Delays: []int{0, 2, 5}}
	if s := d.Stats(); s.Median != 2 || s.Max != 5 || s.Undetected != 2 || s.Mean < 2.333 || s.Mean > 2.334 {
		t.Fatalf("impar: %+v", s)
	}
	if s := (evaluation.DelayResult{Total: 2, Delays: []int{3, 1}}).Stats(); s.Median != 2 || s.Mean != 2 {
		t.Fatalf("par (la mediana promedia las dos del medio): %+v", s)
	}
	if _, _, _, ok := (evaluation.DelayResult{Total: 2}).WorstCaseMinutes(5 * time.Minute); ok {
		t.Fatal("sin incidentes detectados no hay peor caso")
	}
}

// Una ventana cuenta como detectada si el método marcó cualquiera de sus
// unidades positivas: aquí solo la unidad por IP alerta.
func TestDelay_BastaConUnaDeLasUnidadesPositivas(t *testing.T) {
	l, as := attackWindow(4, simulate.ScenarioStuffing, 0, opts{}, opts{rules: true})
	r := evaluation.Evaluate(as, []simulate.Label{l})
	if s := delayOf(t, r, simulate.ScenarioStuffing, evaluation.MethodRules).Stats(); s.Detected != 1 || s.Mean != 0 {
		t.Fatalf("stats = %+v, want detectado con retraso 0", s)
	}
}

func TestDelay_MarkdownYCSV(t *testing.T) {
	analyses, labels := build(
		incidentSpec{1, simulate.ScenarioStuffing, 0, 2, 4},
		incidentSpec{2, simulate.ScenarioStuffing, 10, -1, 2},
	)
	r := evaluation.Evaluate(analyses, labels)

	md := r.Markdown(evaluation.Header{Interval: 5 * time.Minute, IFThresholds: map[string]float64{}})
	i := strings.Index(md, "## Tiempo de detección")
	if i < 0 || i < strings.Index(md, "## Detección de señuelos") {
		t.Fatalf("la sección de tiempos debe ir al final, después de las demás:\n%s", md)
	}
	for _, want := range []string{
		"intervalo de la tarea (5 min, DETECTOR_INTERVAL)",
		"| Relleno de credenciales | Reglas (umbrales) | 2 | 1 | 2,00 | 2,0 | 2 | 35,0 | 35,0 | 35,0 |",
		"| Relleno de credenciales | Isolation Forest | 2 | 2 | n/d | n/d | n/d | n/d | n/d | n/d |",
		"| Todos los escenarios | Reglas (umbrales) | 2 | 1 |",
	} {
		if !strings.Contains(md, want) {
			t.Errorf("el Markdown no contiene %q:\n%s", want, md[i:])
		}
	}

	csv := r.DelaysCSV(5 * time.Minute)
	if !strings.HasPrefix(csv, "escenario,metodo,incidentes,detectados,sin_detectar,retraso_promedio_ventanas,") {
		t.Fatalf("cabecera del CSV inesperada:\n%s", csv)
	}
	for _, want := range []string{
		"relleno_credenciales,reglas,2,1,1,2.0000,2.0,2,35.0000,35.0,35.0,5\n",
		"relleno_credenciales,isolation_forest,2,0,2,,,,,,,5\n",
		"todos,reglas,2,1,1,",
	} {
		if !strings.Contains(csv, want) {
			t.Errorf("el CSV no contiene %q:\n%s", want, csv)
		}
	}
	// 6 filas por método (5 escenarios y "todos") × 5 métodos = 30, más la cabecera.
	if n := strings.Count(csv, "\n"); n != 31 {
		t.Errorf("el CSV tiene %d líneas, want 31", n)
	}
}

func TestDelay_IgnoraEtiquetasFueraDeLoAnalizado(t *testing.T) {
	analyses, labels := build(incidentSpec{1, simulate.ScenarioStuffing, 0, 0, 1})
	labels = append(labels, label(9, simulate.ScenarioStuffing, 500, "T9", "9.9.9.9")) // otra ventana: sin tráfico analizado
	s := delayOf(t, evaluation.Evaluate(analyses, labels), simulate.ScenarioStuffing, evaluation.MethodRules).Stats()
	if s.Total != 1 {
		t.Fatalf("un incidente fuera de lo analizado no debe contar como sin detectar: %+v", s)
	}
}
