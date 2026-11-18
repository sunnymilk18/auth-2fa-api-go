// Command evaluate corre las reglas y el Isolation Forest sobre las ventanas
// simuladas del período de evaluación y las compara con las etiquetas reales
// (ground_truth.json): matriz de confusión, precisión, exhaustividad y F1 por
// método, detección por escenario y detección de señuelos. Escribe CSV y
// tablas en Markdown, listas para pegar en el informe, y las imprime.
//
// Es el único lugar donde las etiquetas reales y el detector se miran juntos;
// el detector nunca las lee. No escribe alertas en la base: usa
// detector.Scan, que solo lee. Lee de la base de datos LOCAL (se niega a
// correr contra cualquier otra) y no carga el .env de la API.
//
// Mismos datos, mismo modelo y mismos parámetros dan exactamente los mismos
// archivos: no se escribe ninguna fecha de ejecución.
//
//	go run ./cmd/evaluate -meta experimento/meta.json -etiquetas experimento/ground_truth.json -modelo experimento/modelo.json -prefijo-tenant sim- -salida experimento
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"

	"auth-2fa-api/internal/detector"
	"auth-2fa-api/internal/evaluation"
	"auth-2fa-api/internal/experiment"
	"auth-2fa-api/internal/simulate"
)

func main() {
	log.SetFlags(0)
	if err := run(); err != nil {
		log.Fatalf("error: %v", err)
	}
}

func run() error {
	cfg, err := detector.LoadConfig()
	if err != nil {
		return err
	}
	metaPath := flag.String("meta", "", "meta.json de la simulación: de ahí salen las fechas si no se dan")
	truthPath := flag.String("etiquetas", "experimento/ground_truth.json", "etiquetas reales (ground_truth.json)")
	modelPath := flag.String("modelo", cfg.ModelPath, "modelo entrenado con cmd/train")
	fromFlag := flag.String("desde", "", "inicio del período de evaluación (AAAA-MM-DD o RFC 3339)")
	toFlag := flag.String("hasta", "", "fin (exclusivo) del período de evaluación")
	prefix := flag.String("prefijo-tenant", "", "usar solo tenants cuyo nombre empieza así (para el experimento: sim-)")
	out := flag.String("salida", "experimento", "carpeta de los resultados (CSV y Markdown)")
	flag.Parse()

	var meta simulate.Meta
	if *metaPath != "" {
		m, err := simulate.LoadMeta(*metaPath)
		if err != nil {
			return err
		}
		meta = *m
	}
	from, to := meta.EvalFrom, meta.EvalTo
	if *fromFlag != "" {
		if from, err = experiment.ParseTime(*fromFlag); err != nil {
			return err
		}
	}
	if *toFlag != "" {
		if to, err = experiment.ParseTime(*toFlag); err != nil {
			return err
		}
	}
	if from.IsZero() || to.IsZero() || !from.Before(to) {
		return fmt.Errorf("falta el período de evaluación: indica -meta, o -desde y -hasta (con desde anterior a hasta)")
	}

	truth, err := simulate.LoadTruth(*truthPath)
	if err != nil {
		return fmt.Errorf("leyendo las etiquetas reales: %w", err)
	}
	model, err := detector.LoadModel(*modelPath)
	if err != nil {
		return fmt.Errorf("leyendo el modelo %s (¿corriste cmd/train?): %w", *modelPath, err)
	}

	ctx := context.Background()
	pool, err := experiment.Connect(ctx)
	if err != nil {
		return err
	}
	defer pool.Close()

	d := detector.New(pool, cfg.Rules, model, cfg.IFThreshold, nil)
	d.TenantNamePrefix = *prefix
	analyses, err := d.Scan(ctx, from, to)
	if err != nil {
		return err
	}
	if len(analyses) == 0 {
		return fmt.Errorf("no hay ventanas con tráfico entre %s y %s: ¿corriste cmd/simulate?", from.Format("2006-01-02"), to.Format("2006-01-02"))
	}

	report := evaluation.Evaluate(analyses, truth.Labels)
	header := evaluation.Header{
		Seed: truth.Seed, EvalFrom: from, EvalTo: to, TrainingFrom: meta.TrainingFrom, TrainingTo: meta.TrainingTo,
		Rules: cfg.Rules, Trees: model.Trees, SampleSize: model.SampleSize, ModelSeed: model.Seed,
		IFThresholds: map[string]float64{}, IFThresholdFixed: cfg.IFThreshold > 0, TrainingUnits: map[string]int{},
	}
	for key, km := range model.Keys {
		header.TrainingUnits[key] = km.TrainingUnits
		header.IFThresholds[key] = d.IFThreshold(key)
		header.ThresholdQuantile = km.ThresholdQuantile
	}

	if err := os.MkdirAll(*out, 0o755); err != nil {
		return err
	}
	markdown := report.Markdown(header)
	files := []struct{ name, content string }{
		{"resultados.md", markdown},
		{"resultados_metricas.csv", report.MetricsCSV()},
		{"resultados_escenarios.csv", report.ScenariosCSV()},
		{"resultados_senuelos.csv", report.DecoysCSV()},
		{"resultados_umbral.csv", report.SweepCSV()},
	}
	for _, f := range files {
		if err := os.WriteFile(filepath.Join(*out, f.name), []byte(f.content), 0o644); err != nil {
			return err
		}
	}

	fmt.Print(markdown)
	fmt.Printf("\nArchivos escritos en %s: resultados.md, resultados_metricas.csv, resultados_escenarios.csv, resultados_senuelos.csv, resultados_umbral.csv\n", *out)
	return nil
}
