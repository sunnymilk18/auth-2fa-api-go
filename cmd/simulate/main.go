// Command simulate genera datos SIMULADOS de autenticación en la base de
// datos LOCAL, con semilla fija, para el experimento del detector de accesos
// anómalos: tráfico normal (con ruido) y cinco escenarios de ataque. Además
// escribe las etiquetas reales de cada ventana atacada en ground_truth.json —
// un archivo que el detector jamás lee; solo cmd/evaluate.
//
// Se niega a correr si el servidor de la base no es local, o si falta la
// confirmación explícita SIMULATE_CONFIRM_LOCAL=yes. No carga el .env de la
// API: ver internal/experiment.
//
//	SIMULATE_CONFIRM_LOCAL=yes go run ./cmd/simulate -semilla 42 -salida experimento
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"path/filepath"

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
	seed := flag.Uint64("semilla", 42, "semilla de la simulación (misma semilla, mismos datos)")
	out := flag.String("salida", "experimento", "carpeta donde se escriben ground_truth.json y meta.json")
	clean := flag.Bool("limpiar", false, "solo borrar la simulación anterior de la base, sin generar otra")
	flag.Parse()

	if err := experiment.RequireConfirmation(); err != nil {
		return err
	}
	ctx := context.Background()
	pool, err := experiment.Connect(ctx)
	if err != nil {
		return err
	}
	defer pool.Close()

	if *clean {
		if err := simulate.Wipe(ctx, pool); err != nil {
			return err
		}
		fmt.Println("Simulación anterior borrada de la base local.")
		return nil
	}

	res := simulate.Generate(simulate.DefaultConfig(*seed))
	if err := simulate.Write(ctx, pool, res); err != nil {
		return err
	}
	truth, meta := filepath.Join(*out, "ground_truth.json"), filepath.Join(*out, "meta.json")
	if err := simulate.WriteTruth(truth, res); err != nil {
		return err
	}
	if err := simulate.WriteMeta(meta, res); err != nil {
		return err
	}

	users := 0
	for _, t := range res.Tenants {
		users += len(t.Users) + len(t.Decoys)
	}
	perScenario := map[string]int{}
	incidents := map[int]bool{}
	for _, l := range res.Labels {
		if !incidents[l.Incident] {
			incidents[l.Incident] = true
			perScenario[l.Scenario]++
		}
	}
	fmt.Printf("Simulación escrita en la base local (semilla %d).\n", *seed)
	fmt.Printf("  tenants: %d, cuentas: %d (incluye señuelos), eventos: %d\n", len(res.Tenants), users, len(res.Rows))
	fmt.Printf("  entrenamiento: %s a %s (solo tráfico normal)\n", res.Meta.TrainingFrom.Format("2006-01-02"), res.Meta.TrainingTo.Format("2006-01-02"))
	fmt.Printf("  evaluación:    %s a %s (con ataques)\n", res.Meta.EvalFrom.Format("2006-01-02"), res.Meta.EvalTo.Format("2006-01-02"))
	for _, s := range simulate.Scenarios {
		fmt.Printf("  incidentes de %s: %d\n", s, perScenario[s])
	}
	fmt.Printf("  etiquetas reales: %s\n  rangos:           %s\n", truth, meta)
	return nil
}
