// Package evaluation compara lo que el detector concluyó (detector.Analysis)
// con las etiquetas reales de la simulación (simulate.Label) y arma las
// tablas del informe: matriz de confusión, precisión, exhaustividad y F1 por
// método, detección por escenario y detección de señuelos.
//
// Solo cmd/evaluate usa este paquete — es el único lugar donde las etiquetas
// reales y los resultados del detector se miran juntos. El detector nunca
// ve las etiquetas.
//
// La unidad evaluada es una "unidad": una ventana de 10 minutos para una
// clave (un tenant o una IP). Es positiva si alguna etiqueta apunta a ella:
// la unidad del tenant siempre, y la de la IP cuando la etiqueta trae IP (un
// ataque distribuido no la trae: cada IP suelta se ve normal, solo el tenant
// lo delata).
package evaluation

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"auth-2fa-api/internal/detector"
	"auth-2fa-api/internal/simulate"
)

// SweepThresholds son los umbrales de puntaje con que se muestra cómo cambia
// el Isolation Forest — para ver la sensibilidad, no para elegir uno mirando
// la evaluación (el umbral de verdad sale del entrenamiento).
var SweepThresholds = []float64{0.55, 0.60, 0.65, 0.70, 0.75, 0.80, 0.85}

// Métodos que se comparan, en el orden en que se reportan.
const (
	MethodRules    = "reglas"
	MethodDecoys   = "senuelos"
	MethodBaseline = "reglas_senuelos"
	MethodForest   = "isolation_forest"
	MethodCombined = "combinado"
)

// Methods fija el orden de columnas y filas.
var Methods = []string{MethodRules, MethodDecoys, MethodBaseline, MethodForest, MethodCombined}

// MethodTitle es el nombre legible de cada método.
var MethodTitle = map[string]string{
	MethodRules:    "Reglas (umbrales)",
	MethodDecoys:   "Señuelos (regla)",
	MethodBaseline: "Reglas + señuelos (línea base)",
	MethodForest:   "Isolation Forest",
	MethodCombined: "Combinado (línea base + Isolation Forest)",
}

// ScenarioTitle es el nombre legible de cada escenario de ataque.
var ScenarioTitle = map[string]string{
	simulate.ScenarioStuffing:    "Relleno de credenciales",
	simulate.ScenarioSpraying:    "Pulverizado de contraseñas",
	simulate.ScenarioBruteForce:  "Fuerza bruta a una cuenta",
	simulate.ScenarioDistributed: "Ataque distribuido",
	simulate.ScenarioDecoy:       "Toque a señuelos",
}

// flagged dice si el método marca la unidad como anómala.
func flagged(method string, a detector.Analysis) bool {
	rules := len(a.RuleMotives) > 0
	decoys := len(a.DecoyMotives) > 0
	switch method {
	case MethodRules:
		return rules
	case MethodDecoys:
		return decoys
	case MethodBaseline:
		return rules || decoys
	case MethodForest:
		return a.ForestAlert
	case MethodCombined:
		return rules || decoys || a.ForestAlert
	}
	return false
}

// Counts es una matriz de confusión.
type Counts struct{ TP, FP, FN, TN int }

// Ratio es un cociente que puede no estar definido (denominador 0).
type Ratio struct{ Num, Den int }

// Value devuelve el cociente, o 0 si no está definido.
func (r Ratio) Value() float64 {
	if r.Den == 0 {
		return 0
	}
	return float64(r.Num) / float64(r.Den)
}

// Precision = VP / (VP + FP).
func (c Counts) Precision() Ratio { return Ratio{c.TP, c.TP + c.FP} }

// Recall (exhaustividad) = VP / (VP + FN).
func (c Counts) Recall() Ratio { return Ratio{c.TP, c.TP + c.FN} }

// FPR (tasa de falsos positivos) = FP / (FP + VN).
func (c Counts) FPR() Ratio { return Ratio{c.FP, c.FP + c.TN} }

// F1 = 2·P·R / (P + R) = 2·VP / (2·VP + FP + FN). Indefinido sin positivos
// ni alertas.
func (c Counts) F1() Ratio { return Ratio{2 * c.TP, 2*c.TP + c.FP + c.FN} }

// MethodResult son los números de un método.
type MethodResult struct {
	Method  string
	Overall Counts
	ByKey   map[string]Counts // por tipo de clave: detector.KeyTenant / KeyIP
}

// ScenarioResult es la detección de un escenario de ataque.
type ScenarioResult struct {
	Scenario  string
	Windows   int
	Incidents int
	// DetectedWindows[método]: ventanas etiquetadas en las que el método
	// marcó la unidad atacada. DetectedIncidents[método]: incidentes en los
	// que lo hizo en al menos una de sus ventanas.
	DetectedWindows   map[string]int
	DetectedIncidents map[string]int
}

// DecoyResult es la detección de las ventanas con intentos contra señuelos.
type DecoyResult struct {
	// Units: unidades (ventana × clave) con al menos un intento contra un
	// señuelo.
	Units    int
	Detected map[string]int
	// OnlyDecoys: unidades que solo la regla de señuelos marcó — ni los
	// umbrales ni el bosque las vieron.
	OnlyDecoys int
}

// SweepRow es el Isolation Forest con un umbral de puntaje fijo.
type SweepRow struct {
	Threshold float64
	Counts    Counts
}

// Report es el resultado completo de una evaluación.
type Report struct {
	// Units: unidades evaluadas, ya sin las excluidas.
	Units         int
	PositiveUnits int
	// ExcludedUnits: unidades por IP de los participantes de un ataque
	// distribuido. Son tráfico de ataque que no se puede distinguir del normal
	// una IP a la vez, así que no se cuentan ni como positivas ni como
	// negativas (ver simulate.Key).
	ExcludedUnits int
	Methods       []MethodResult
	Scenarios     []ScenarioResult
	Decoys        DecoyResult
	// AUC: área bajo la curva ROC del puntaje del bosque, por tipo de clave
	// (no depende del umbral). Vacío si el modelo no cubre ese tipo de clave.
	AUC   map[string]Ratio
	Sweep []SweepRow
	// Delays: tiempo de detección por escenario y método (ver DelayResult).
	Delays []DelayResult
}

type unitID struct {
	window  int64
	keyType string
	key     string
}

func idOf(u detector.Unit) unitID {
	key := u.TenantID
	if u.KeyType == detector.KeyIP {
		key = u.IP
	}
	return unitID{u.WindowStart.Unix(), u.KeyType, key}
}

// positives devuelve las unidades positivas de una etiqueta.
func positives(l simulate.Label) []unitID {
	ids := []unitID{{l.WindowStart.Unix(), detector.KeyTenant, l.Key.TenantID}}
	if l.Key.IP != "" {
		ids = append(ids, unitID{l.WindowStart.Unix(), detector.KeyIP, l.Key.IP})
	}
	return ids
}

// Evaluate califica analyses contra labels. Las etiquetas fuera de las
// ventanas analizadas (otro rango de fechas) se ignoran.
func Evaluate(analyses []detector.Analysis, labels []simulate.Label) *Report {
	byID := make(map[unitID]detector.Analysis, len(analyses))
	for _, a := range analyses {
		byID[idOf(a.Unit)] = a
	}

	// Etiquetas que caen dentro de lo analizado.
	var inScope []simulate.Label
	positive := map[unitID]bool{}
	for _, l := range labels {
		if _, ok := byID[positives(l)[0]]; !ok {
			continue
		}
		inScope = append(inScope, l)
		for _, id := range positives(l) {
			positive[id] = true
		}
	}

	// Unidades de IPs participantes de un ataque distribuido: se excluyen.
	excluded := map[unitID]bool{}
	for _, l := range inScope {
		for _, ip := range l.Key.IPs {
			id := unitID{l.WindowStart.Unix(), detector.KeyIP, ip}
			if _, ok := byID[id]; ok && !positive[id] {
				excluded[id] = true
			}
		}
	}
	var evaluated []detector.Analysis
	for _, a := range analyses {
		if !excluded[idOf(a.Unit)] {
			evaluated = append(evaluated, a)
		}
	}

	rep := &Report{Units: len(evaluated), PositiveUnits: len(positive), ExcludedUnits: len(excluded), AUC: map[string]Ratio{}}

	for _, m := range Methods {
		res := MethodResult{Method: m, ByKey: map[string]Counts{}}
		for _, a := range evaluated {
			isPos := positive[idOf(a.Unit)]
			isFlag := flagged(m, a)
			bump := func(c *Counts) {
				switch {
				case isPos && isFlag:
					c.TP++
				case !isPos && isFlag:
					c.FP++
				case isPos && !isFlag:
					c.FN++
				default:
					c.TN++
				}
			}
			bump(&res.Overall)
			c := res.ByKey[a.Unit.KeyType]
			bump(&c)
			res.ByKey[a.Unit.KeyType] = c
		}
		rep.Methods = append(rep.Methods, res)
	}

	// Por escenario.
	for _, scenario := range simulate.Scenarios {
		sr := ScenarioResult{Scenario: scenario, DetectedWindows: map[string]int{}, DetectedIncidents: map[string]int{}}
		incidents := map[int]map[string]bool{}
		for _, l := range inScope {
			if l.Scenario != scenario {
				continue
			}
			sr.Windows++
			if incidents[l.Incident] == nil {
				incidents[l.Incident] = map[string]bool{}
			}
			for _, m := range Methods {
				hit := false
				for _, id := range positives(l) {
					if a, ok := byID[id]; ok && flagged(m, a) {
						hit = true
					}
				}
				if hit {
					sr.DetectedWindows[m]++
					incidents[l.Incident][m] = true
				}
			}
		}
		sr.Incidents = len(incidents)
		ids := make([]int, 0, len(incidents))
		for id := range incidents {
			ids = append(ids, id)
		}
		sort.Ints(ids)
		for _, id := range ids {
			for _, m := range Methods {
				if incidents[id][m] {
					sr.DetectedIncidents[m]++
				}
			}
		}
		rep.Scenarios = append(rep.Scenarios, sr)
	}

	// AUC por tipo de clave, y la sensibilidad al umbral.
	for _, key := range []string{detector.KeyTenant, detector.KeyIP} {
		var pos, neg []float64
		for _, a := range evaluated {
			if a.Unit.KeyType != key || a.Score == nil {
				continue
			}
			if positive[idOf(a.Unit)] {
				pos = append(pos, *a.Score)
			} else {
				neg = append(neg, *a.Score)
			}
		}
		if len(pos) > 0 && len(neg) > 0 {
			rep.AUC[key] = aucRatio(pos, neg)
		}
	}
	for _, thr := range SweepThresholds {
		row := SweepRow{Threshold: thr}
		for _, a := range evaluated {
			isPos := positive[idOf(a.Unit)]
			isFlag := a.Score != nil && *a.Score >= thr
			switch {
			case isPos && isFlag:
				row.Counts.TP++
			case !isPos && isFlag:
				row.Counts.FP++
			case isPos && !isFlag:
				row.Counts.FN++
			default:
				row.Counts.TN++
			}
		}
		rep.Sweep = append(rep.Sweep, row)
	}

	rep.Delays = computeDelays(byID, inScope)

	// Señuelos.
	rep.Decoys.Detected = map[string]int{}
	for _, a := range analyses {
		if a.Unit.Features.IntentosContraSenuelos < 1 {
			continue
		}
		rep.Decoys.Units++
		for _, m := range Methods {
			if flagged(m, a) {
				rep.Decoys.Detected[m]++
			}
		}
		if flagged(MethodDecoys, a) && !flagged(MethodRules, a) && !flagged(MethodForest, a) {
			rep.Decoys.OnlyDecoys++
		}
	}
	return rep
}

// aucRatio calcula el área bajo la curva ROC por el estadístico de
// Mann–Whitney: la probabilidad de que un positivo puntúe más que un negativo
// (los empates cuentan la mitad). Se devuelve como fracción exacta Num/Den,
// con Num en medios (por eso el doble) para no perder los empates.
func aucRatio(pos, neg []float64) Ratio {
	type point struct {
		score float64
		pos   bool
	}
	pts := make([]point, 0, len(pos)+len(neg))
	for _, s := range pos {
		pts = append(pts, point{s, true})
	}
	for _, s := range neg {
		pts = append(pts, point{s, false})
	}
	sort.Slice(pts, func(i, j int) bool { return pts[i].score < pts[j].score })

	// Suma de rangos de los positivos, con rango promedio en los empates —
	// en medios, es decir, duplicada, para quedarse en enteros.
	var rank2Sum int64
	for i := 0; i < len(pts); {
		j := i
		for j < len(pts) && pts[j].score == pts[i].score {
			j++
		}
		// Posiciones i+1..j: su rango promedio duplicado es (i+1)+j.
		for k := i; k < j; k++ {
			if pts[k].pos {
				rank2Sum += int64(i + 1 + j)
			}
		}
		i = j
	}
	nPos, nNeg := int64(len(pos)), int64(len(neg))
	// AUC = (sumaRangos − nPos(nPos+1)/2) / (nPos·nNeg), con sumaRangos = rank2Sum/2.
	num2 := rank2Sum - nPos*(nPos+1)
	return Ratio{Num: int(num2), Den: int(2 * nPos * nNeg)}
}

// --- formato ---

// comma formatea con coma decimal (texto del informe).
func comma(v float64, decimals int) string {
	return strings.Replace(strconv.FormatFloat(v, 'f', decimals, 64), ".", ",", 1)
}

func ratioText(r Ratio) string {
	if r.Den == 0 {
		return "n/d"
	}
	return comma(r.Value(), 3)
}

func ratioCSV(r Ratio) string {
	if r.Den == 0 {
		return ""
	}
	return strconv.FormatFloat(r.Value(), 'f', 4, 64)
}

func aucText(r Ratio) string {
	if r.Den == 0 {
		return "n/d"
	}
	return comma(r.Value(), 3)
}

func percentText(num, den int) string {
	if den == 0 {
		return "n/d"
	}
	return comma(100*float64(num)/float64(den), 1) + " %"
}

func countAndPercent(num, den int) string {
	return fmt.Sprintf("%d/%d (%s)", num, den, percentText(num, den))
}

// Header describe el experimento: parámetros que van arriba de las tablas.
type Header struct {
	// Interval es el intervalo de la tarea del detector (DETECTOR_INTERVAL):
	// solo se usa para pasar el tiempo de detección a minutos de peor caso.
	Interval time.Duration
	// Intensity: nivel de intensidad de los ataques; vacío (la simulación
	// original) no agrega ninguna línea.
	Intensity    string
	Seed         uint64
	EvalFrom     time.Time
	EvalTo       time.Time
	TrainingFrom time.Time
	TrainingTo   time.Time
	Rules        detector.Rules
	// IFThresholds: el umbral de puntaje que se aplicó a cada tipo de clave.
	// IFThresholdFixed dice si lo fijó DETECTOR_IF_THRESHOLD (true) o salió
	// calibrado del entrenamiento (false).
	IFThresholds     map[string]float64
	IFThresholdFixed bool
	// ThresholdQuantile es el cuantil con que se calibró (si no es fijo).
	ThresholdQuantile float64
	Trees             int
	SampleSize        int
	ModelSeed         uint64
	TrainingUnits     map[string]int
}

func (h Header) lines() []string {
	day := func(t time.Time) string { return t.UTC().Format("2006-01-02") }
	out := []string{
		fmt.Sprintf("Semilla de la simulación: %d.", h.Seed),
		fmt.Sprintf("Entrenamiento: %s a %s (sin ataques). Evaluación: %s a %s (con ataques).", day(h.TrainingFrom), day(h.TrainingTo), day(h.EvalFrom), day(h.EvalTo)),
		fmt.Sprintf("Reglas: ≥ %d fallos, ≥ %d cuentas distintas atacadas, ≥ %d IPs distintas con fallos o ≥ %d intentos contra cuentas inexistentes en 10 min; cualquier intento contra un señuelo.",
			h.Rules.Fallos, h.Rules.Cuentas, h.Rules.IPsConFallos, h.Rules.Inexistentes),
		fmt.Sprintf("Isolation Forest: t = %d árboles, ψ = %d, semilla %d. Ventanas de entrenamiento: %d por tenant, %d por IP.",
			h.Trees, h.SampleSize, h.ModelSeed, h.TrainingUnits[detector.KeyTenant], h.TrainingUnits[detector.KeyIP]),
	}
	if h.Intensity != "" {
		out = append(out[:1], append([]string{fmt.Sprintf("Intensidad de los ataques: %s.", h.Intensity)}, out[1:]...)...)
	}
	origin := fmt.Sprintf("calibrado con el cuantil %s de los puntajes del entrenamiento", comma(h.ThresholdQuantile, 3))
	if h.IFThresholdFixed {
		origin = "fijado con DETECTOR_IF_THRESHOLD"
	}
	out = append(out, fmt.Sprintf("Umbral de puntaje del bosque (%s): %s por tenant, %s por IP.",
		origin, comma(h.IFThresholds[detector.KeyTenant], 3), comma(h.IFThresholds[detector.KeyIP], 3)))
	return out
}

// Markdown arma las tablas del informe, listas para pegar.
func (r *Report) Markdown(h Header) string {
	var b strings.Builder
	b.WriteString("# Resultados de la evaluación\n\n")
	for _, l := range h.lines() {
		b.WriteString("- " + l + "\n")
	}
	fmt.Fprintf(&b, "- Unidades evaluadas (ventana de 10 min × tenant o IP): %d, de las cuales %d son positivas (ataque real).\n", r.Units, r.PositiveUnits)
	if r.ExcludedUnits > 0 {
		fmt.Fprintf(&b, "- Excluidas de la matriz: %d unidades por IP de participantes de ataques distribuidos (cada IP suelta se ve como tráfico normal; el ataque se evalúa en la unidad del tenant).\n", r.ExcludedUnits)
	}
	b.WriteString("\n")

	b.WriteString("## Matriz de confusión y métricas por método\n\n")
	b.WriteString("| Método | VP | FP | FN | VN | Precisión | Exhaustividad | F1 | Tasa de falsos positivos |\n")
	b.WriteString("|---|---:|---:|---:|---:|---:|---:|---:|---:|\n")
	for _, m := range r.Methods {
		c := m.Overall
		fmt.Fprintf(&b, "| %s | %d | %d | %d | %d | %s | %s | %s | %s |\n", MethodTitle[m.Method], c.TP, c.FP, c.FN, c.TN,
			ratioText(c.Precision()), ratioText(c.Recall()), ratioText(c.F1()), ratioText(c.FPR()))
	}

	b.WriteString("\n## Isolation Forest: AUC-ROC y sensibilidad al umbral\n\n")
	fmt.Fprintf(&b, "AUC-ROC (independiente del umbral): %s por tenant, %s por IP.\n\n", aucText(r.AUC[detector.KeyTenant]), aucText(r.AUC[detector.KeyIP]))
	b.WriteString("| Umbral de puntaje (igual para tenant e IP) | VP | FP | FN | VN | Precisión | Exhaustividad | F1 |\n|---:|---:|---:|---:|---:|---:|---:|---:|\n")
	for _, s := range r.Sweep {
		c := s.Counts
		fmt.Fprintf(&b, "| %s | %d | %d | %d | %d | %s | %s | %s |\n", comma(s.Threshold, 2), c.TP, c.FP, c.FN, c.TN,
			ratioText(c.Precision()), ratioText(c.Recall()), ratioText(c.F1()))
	}

	b.WriteString("\n## Métricas por tipo de clave\n\n")
	b.WriteString("| Método | Clave | VP | FP | FN | VN | Precisión | Exhaustividad | F1 |\n")
	b.WriteString("|---|---|---:|---:|---:|---:|---:|---:|---:|\n")
	for _, m := range r.Methods {
		for _, key := range []string{detector.KeyTenant, detector.KeyIP} {
			c := m.ByKey[key]
			fmt.Fprintf(&b, "| %s | %s | %d | %d | %d | %d | %s | %s | %s |\n", MethodTitle[m.Method], key, c.TP, c.FP, c.FN, c.TN,
				ratioText(c.Precision()), ratioText(c.Recall()), ratioText(c.F1()))
		}
	}

	for _, level := range []string{"ventanas", "incidentes"} {
		if level == "ventanas" {
			b.WriteString("\n## Detección por escenario (ventanas atacadas detectadas)\n\n")
		} else {
			b.WriteString("\n## Detección por escenario (incidentes detectados en al menos una de sus ventanas)\n\n")
		}
		b.WriteString("| Escenario | Total |")
		for _, m := range Methods {
			b.WriteString(" " + MethodTitle[m] + " |")
		}
		b.WriteString("\n|---|---:|" + strings.Repeat("---:|", len(Methods)) + "\n")
		for _, s := range r.Scenarios {
			total, detected := s.Windows, s.DetectedWindows
			if level == "incidentes" {
				total, detected = s.Incidents, s.DetectedIncidents
			}
			fmt.Fprintf(&b, "| %s | %d |", ScenarioTitle[s.Scenario], total)
			for _, m := range Methods {
				b.WriteString(" " + countAndPercent(detected[m], total) + " |")
			}
			b.WriteString("\n")
		}
	}

	b.WriteString("\n## Detección de señuelos\n\n")
	fmt.Fprintf(&b, "Unidades con al menos un intento contra un señuelo: %d.\n\n", r.Decoys.Units)
	b.WriteString("| Método | Unidades detectadas |\n|---|---:|\n")
	for _, m := range Methods {
		fmt.Fprintf(&b, "| %s | %s |\n", MethodTitle[m], countAndPercent(r.Decoys.Detected[m], r.Decoys.Units))
	}
	fmt.Fprintf(&b, "\nDe esas unidades, %s solo las marcó la regla de señuelos (ni los umbrales ni el bosque las vieron).\n", countAndPercent(r.Decoys.OnlyDecoys, r.Decoys.Units))
	b.WriteString(r.delaysMarkdown(h.Interval))
	return b.String()
}

// SweepCSV: el Isolation Forest con cada umbral fijo, más el AUC por clave.
func (r *Report) SweepCSV() string {
	var b strings.Builder
	b.WriteString("umbral,vp,fp,fn,vn,precision,exhaustividad,f1\n")
	for _, s := range r.Sweep {
		c := s.Counts
		fmt.Fprintf(&b, "%.2f,%d,%d,%d,%d,%s,%s,%s\n", s.Threshold, c.TP, c.FP, c.FN, c.TN, ratioCSV(c.Precision()), ratioCSV(c.Recall()), ratioCSV(c.F1()))
	}
	for _, key := range []string{detector.KeyTenant, detector.KeyIP} {
		fmt.Fprintf(&b, "auc_%s,%s\n", key, ratioCSV(r.AUC[key]))
	}
	return b.String()
}

// MetricsCSV: una fila por método y tipo de clave (más "todas").
func (r *Report) MetricsCSV() string {
	var b strings.Builder
	b.WriteString("metodo,clave,vp,fp,fn,vn,precision,exhaustividad,f1,tasa_falsos_positivos\n")
	for _, m := range r.Methods {
		rows := []struct {
			key string
			c   Counts
		}{{"todas", m.Overall}, {detector.KeyTenant, m.ByKey[detector.KeyTenant]}, {detector.KeyIP, m.ByKey[detector.KeyIP]}}
		for _, row := range rows {
			c := row.c
			fmt.Fprintf(&b, "%s,%s,%d,%d,%d,%d,%s,%s,%s,%s\n", m.Method, row.key, c.TP, c.FP, c.FN, c.TN,
				ratioCSV(c.Precision()), ratioCSV(c.Recall()), ratioCSV(c.F1()), ratioCSV(c.FPR()))
		}
	}
	return b.String()
}

// ScenariosCSV: una fila por escenario, nivel (ventana o incidente) y método.
func (r *Report) ScenariosCSV() string {
	var b strings.Builder
	b.WriteString("escenario,nivel,metodo,total,detectados,tasa_deteccion\n")
	for _, s := range r.Scenarios {
		for _, level := range []string{"ventana", "incidente"} {
			total, detected := s.Windows, s.DetectedWindows
			if level == "incidente" {
				total, detected = s.Incidents, s.DetectedIncidents
			}
			for _, m := range Methods {
				fmt.Fprintf(&b, "%s,%s,%s,%d,%d,%s\n", s.Scenario, level, m, total, detected[m], ratioCSV(Ratio{detected[m], total}))
			}
		}
	}
	return b.String()
}

// DecoysCSV: una fila por método.
func (r *Report) DecoysCSV() string {
	var b strings.Builder
	b.WriteString("metodo,unidades_con_senuelo,detectadas,tasa_deteccion\n")
	for _, m := range Methods {
		fmt.Fprintf(&b, "%s,%d,%d,%s\n", m, r.Decoys.Units, r.Decoys.Detected[m], ratioCSV(Ratio{r.Decoys.Detected[m], r.Decoys.Units}))
	}
	fmt.Fprintf(&b, "solo_senuelos,%d,%d,%s\n", r.Decoys.Units, r.Decoys.OnlyDecoys, ratioCSV(Ratio{r.Decoys.OnlyDecoys, r.Decoys.Units}))
	return b.String()
}
