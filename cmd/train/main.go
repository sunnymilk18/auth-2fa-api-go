// Command train entrena el Isolation Forest del detector de accesos anómalos
// con tráfico normal y escribe el modelo en un archivo JSON (árboles +
// estadísticas de normalidad por característica). Es OFFLINE: la API solo
// carga ese archivo al arrancar (ver DETECTOR_MODEL_PATH).
//
// Lee de la base de datos LOCAL (se niega a correr contra cualquier otra,
// y no carga el .env de la API: ver internal/experiment). Los parámetros del
// bosque salen de DETECTOR_IF_TREES, DETECTOR_IF_SUBSAMPLE y DETECTOR_IF_SEED
// (por defecto t=100, ψ=256, semilla 42) y se pueden pisar con las banderas.
//
//	go run ./cmd/train -meta experimento/meta.json -prefijo-tenant sim- -salida experimento/modelo.json
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"

	"auth-2fa-api/internal/detector"
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
	metaPath := flag.String("meta", "", "meta.json de la simulación: de ahí salen las fechas de entrenamiento si no se dan")
	fromFlag := flag.String("desde", "", "inicio del tráfico normal de entrenamiento (AAAA-MM-DD o RFC 3339)")
	toFlag := flag.String("hasta", "", "fin (exclusivo) del tráfico normal de entrenamiento")
	out := flag.String("salida", cfg.ModelPath, "archivo del modelo")
	prefix := flag.String("prefijo-tenant", "", "usar solo tenants cuyo nombre empieza así (para el experimento: sim-)")
	trees := flag.Int("arboles", cfg.Train.Trees, "cantidad de árboles (t)")
	sample := flag.Int("submuestra", cfg.Train.SampleSize, "tamaño de la submuestra por árbol (ψ)")
	seed := flag.Uint64("semilla", cfg.Train.Seed, "semilla del bosque")
	quantile := flag.Float64("cuantil", cfg.Train.ThresholdQuantile, "cuantil de los puntajes de entrenamiento con que se calibra el umbral de alerta")
	flag.Parse()

	var from, to time.Time
	if *metaPath != "" {
		meta, err := simulate.LoadMeta(*metaPath)
		if err != nil {
			return err
		}
		from, to = meta.TrainingFrom, meta.TrainingTo
	}
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
		return fmt.Errorf("falta el rango de entrenamiento: indica -meta, o -desde y -hasta (con desde anterior a hasta)")
	}

	ctx := context.Background()
	pool, err := experiment.Connect(ctx)
	if err != nil {
		return err
	}
	defer pool.Close()

	events, err := detector.LoadEvents(ctx, pool, from, to, *prefix)
	if err != nil {
		return err
	}
	units := detector.Aggregate(events)

	model, err := detector.TrainModel(units, detector.TrainParams{Trees: *trees, SampleSize: *sample, Seed: *seed, ThresholdQuantile: *quantile})
	if err != nil {
		return err
	}
	if dir := filepath.Dir(*out); dir != "." {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return err
		}
	}
	if err := model.Save(*out); err != nil {
		return err
	}

	// Aviso útil: el bosque aprende que lo visto es "normal". Si en el rango
	// de entrenamiento hay ventanas que ya disparan las reglas, probablemente
	// hay ataques mezclados.
	noisy := 0
	for _, u := range units {
		if len(cfg.Rules.Evaluate(u.Features)) > 0 || len(detector.DecoyMotives(u.Features)) > 0 {
			noisy++
		}
	}

	fmt.Printf("Modelo escrito en %s\n", *out)
	fmt.Printf("  rango de entrenamiento: %s a %s, %d eventos, %d ventanas\n", from.Format("2006-01-02"), to.Format("2006-01-02"), len(events), len(units))
	fmt.Printf("  árboles: %d, submuestra: %d, semilla: %d\n", model.Trees, model.SampleSize, model.Seed)
	for _, key := range []string{detector.KeyTenant, detector.KeyIP} {
		if km := model.Keys[key]; km != nil {
			fmt.Printf("  bosque por %s: %d ventanas de entrenamiento, umbral calibrado %.4f (cuantil %.3f)\n", key, km.TrainingUnits, km.Threshold, km.ThresholdQuantile)
		} else {
			fmt.Printf("  bosque por %s: omitido (menos de %d ventanas)\n", key, detector.MinTrainingUnits)
		}
	}
	if noisy > 0 {
		fmt.Printf("  AVISO: %d ventanas de entrenamiento disparan las reglas; el entrenamiento debería ser solo tráfico normal\n", noisy)
	}
	return nil
}
