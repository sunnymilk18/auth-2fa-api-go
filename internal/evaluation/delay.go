package evaluation

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"auth-2fa-api/internal/detector"
	"auth-2fa-api/internal/simulate"
)

// ScenarioAll agrupa todos los escenarios en las tablas del tiempo de detección.
const ScenarioAll = "todos"

// DelayResult es el tiempo de detección de los incidentes de un escenario para
// un método: cuántas ventanas pasaron entre la primera ventana atacada del
// incidente y la primera en que el método alertó (0 = detectado en la
// primera). Un incidente sin detectar no tiene retraso: solo cuenta en Total.
type DelayResult struct {
	Scenario string
	Method   string
	// Total: incidentes del escenario.
	Total int
	// Delays: retraso, en ventanas, de cada incidente detectado.
	Delays []int
}

// DelayStats resume un DelayResult.
type DelayStats struct {
	Total      int
	Detected   int
	Undetected int
	// Mean, Median y Max sobre los incidentes detectados; no están definidos
	// (se ignoran) si Detected es 0.
	Mean   float64
	Median float64
	Max    int
}

// Stats calcula el resumen: promedio, mediana y máximo del retraso, y cuántos
// incidentes quedaron sin detectar.
func (d DelayResult) Stats() DelayStats {
	s := DelayStats{Total: d.Total, Detected: len(d.Delays), Undetected: d.Total - len(d.Delays)}
	if len(d.Delays) == 0 {
		return s
	}
	sorted := append([]int(nil), d.Delays...)
	sort.Ints(sorted)
	sum := 0
	for _, v := range sorted {
		sum += v
	}
	s.Mean = float64(sum) / float64(len(sorted))
	s.Max = sorted[len(sorted)-1]
	if n := len(sorted); n%2 == 1 {
		s.Median = float64(sorted[n/2])
	} else {
		s.Median = float64(sorted[n/2-1]+sorted[n/2]) / 2
	}
	return s
}

// WorstCaseMinutes pasa el retraso a minutos reales con el detector actual. El
// peor caso de un incidente es el fin de la ventana en que se detectó más el
// intervalo de la tarea (DETECTOR_INTERVAL), menos el inicio de su primera
// ventana atacada: el detector solo mira ventanas ya completas, y la pasada que
// la recoge puede tardar hasta un intervalo más en correr. Devuelve promedio,
// mediana y máximo; ok es false si no hubo ningún incidente detectado.
func (d DelayResult) WorstCaseMinutes(interval time.Duration) (mean, median, max float64, ok bool) {
	s := d.Stats()
	if s.Detected == 0 {
		return 0, 0, 0, false
	}
	toMinutes := func(windows float64) float64 {
		return (windows+1)*detector.WindowSize.Minutes() + interval.Minutes()
	}
	return toMinutes(s.Mean), toMinutes(s.Median), toMinutes(float64(s.Max)), true
}

type incident struct {
	scenario string
	first    time.Time
	hit      map[string]time.Time // método -> primera ventana en que alertó
}

// computeDelays arma el tiempo de detección de cada escenario (y de todos
// juntos) para cada método. Una ventana atacada cuenta como detectada por un
// método si este marcó cualquiera de sus unidades positivas — el mismo
// criterio que la detección por escenario.
func computeDelays(byID map[unitID]detector.Analysis, inScope []simulate.Label) []DelayResult {
	incidents := map[int]*incident{}
	for _, l := range inScope {
		inc := incidents[l.Incident]
		if inc == nil {
			inc = &incident{scenario: l.Scenario, hit: map[string]time.Time{}}
			incidents[l.Incident] = inc
		}
		if inc.first.IsZero() || l.WindowStart.Before(inc.first) {
			inc.first = l.WindowStart
		}
		for _, m := range Methods {
			hit := false
			for _, id := range positives(l) {
				if a, ok := byID[id]; ok && flagged(m, a) {
					hit = true
				}
			}
			if cur, seen := inc.hit[m]; hit && (!seen || l.WindowStart.Before(cur)) {
				inc.hit[m] = l.WindowStart
			}
		}
	}
	ids := make([]int, 0, len(incidents))
	for id := range incidents {
		ids = append(ids, id)
	}
	sort.Ints(ids)

	scenarios := append(append([]string(nil), simulate.Scenarios...), ScenarioAll)
	var out []DelayResult
	for _, scenario := range scenarios {
		for _, m := range Methods {
			res := DelayResult{Scenario: scenario, Method: m}
			for _, id := range ids {
				inc := incidents[id]
				if scenario != ScenarioAll && inc.scenario != scenario {
					continue
				}
				res.Total++
				if t, ok := inc.hit[m]; ok {
					res.Delays = append(res.Delays, int(t.Sub(inc.first)/detector.WindowSize))
				}
			}
			out = append(out, res)
		}
	}
	return out
}

func scenarioLabel(s string) string {
	if s == ScenarioAll {
		return "Todos los escenarios"
	}
	return ScenarioTitle[s]
}

func floatText(v float64, decimals int) string { return comma(v, decimals) }

// delaysMarkdown es la sección "Tiempo de detección" de resultados.md. Va al
// final del informe, así lo anterior no cambia.
func (r *Report) delaysMarkdown(interval time.Duration) string {
	var b strings.Builder
	b.WriteString("\n## Tiempo de detección\n\n")
	b.WriteString("Retraso: ventanas de 10 min entre la primera ventana atacada del incidente y la primera en que el método alertó (0 = detectado en la primera). ")
	b.WriteString("Los incidentes sin detectar no entran en promedio, mediana ni máximo; se muestran aparte.\n\n")
	fmt.Fprintf(&b, "Peor caso en minutos con el detector actual: fin de la ventana detectada + intervalo de la tarea (%s min, DETECTOR_INTERVAL) − inicio de la primera ventana atacada.\n\n", floatText(interval.Minutes(), 0))
	b.WriteString("| Escenario | Método | Incidentes | Sin detectar | Retraso promedio (ventanas) | Retraso mediana | Retraso máximo | Peor caso promedio (min) | Peor caso mediana | Peor caso máximo |\n")
	b.WriteString("|---|---|---:|---:|---:|---:|---:|---:|---:|---:|\n")
	for _, d := range r.Delays {
		s := d.Stats()
		fmt.Fprintf(&b, "| %s | %s | %d | %d |", scenarioLabel(d.Scenario), MethodTitle[d.Method], s.Total, s.Undetected)
		if s.Detected == 0 {
			b.WriteString(" n/d | n/d | n/d | n/d | n/d | n/d |\n")
			continue
		}
		wm, wmed, wmax, _ := d.WorstCaseMinutes(interval)
		fmt.Fprintf(&b, " %s | %s | %d | %s | %s | %s |\n", floatText(s.Mean, 2), floatText(s.Median, 1), s.Max, floatText(wm, 1), floatText(wmed, 1), floatText(wmax, 1))
	}
	return b.String()
}

// DelaysCSV: una fila por escenario y método, con los mismos números que la
// tabla de resultados.md. Las estadísticas indefinidas (sin ningún incidente
// detectado) van vacías.
func (r *Report) DelaysCSV(interval time.Duration) string {
	var b strings.Builder
	b.WriteString("escenario,metodo,incidentes,detectados,sin_detectar,retraso_promedio_ventanas,retraso_mediana_ventanas,retraso_maximo_ventanas,peor_caso_promedio_min,peor_caso_mediana_min,peor_caso_maximo_min,intervalo_min\n")
	for _, d := range r.Delays {
		s := d.Stats()
		fmt.Fprintf(&b, "%s,%s,%d,%d,%d,", d.Scenario, d.Method, s.Total, s.Detected, s.Undetected)
		if s.Detected == 0 {
			fmt.Fprintf(&b, ",,,,,,%.0f\n", interval.Minutes())
			continue
		}
		wm, wmed, wmax, _ := d.WorstCaseMinutes(interval)
		fmt.Fprintf(&b, "%.4f,%.1f,%d,%.4f,%.1f,%.1f,%.0f\n", s.Mean, s.Median, s.Max, wm, wmed, wmax, interval.Minutes())
	}
	return b.String()
}
