// Command seedalerts deja alertas reales en la base de datos LOCAL para probar
// la pantalla del panel con la simulación ya cargada (cmd/simulate): corre el
// detector con detector.Run sobre el período de evaluación, con el modelo
// entrenado (cmd/train), y cierra algunas alertas por las rutas de la API —
// unas como descartadas y otras como resueltas —, dejando el resto abiertas.
// Nunca inserta alertas a mano.
//
// Es repetible: correrlo otra vez no duplica ni cierra más alertas. Las
// alertas de los tenants sim-* se borran con `cmd/simulate -limpiar`.
//
// Mismas protecciones que cmd/simulate: se niega a correr si la base no es
// local y exige SIMULATE_CONFIRM_LOCAL=yes. No carga el .env de la API.
//
//	SIMULATE_CONFIRM_LOCAL=yes go run ./cmd/seedalerts -meta experimento/meta.json -modelo experimento/modelo.json
package main

import (
	"context"
	"flag"
	"fmt"
	"log"

	"auth-2fa-api/internal/alertseed"
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
	metaPath := flag.String("meta", "experimento/meta.json", "meta.json de la simulación: de ahí sale el período de evaluación")
	modelPath := flag.String("modelo", "experimento/modelo.json", "modelo entrenado con cmd/train")
	prefix := flag.String("prefijo-tenant", simulate.TenantPrefix, "usar solo tenants cuyo nombre empieza así")
	perSource := flag.Int("por-fuente", 2, "cuántas alertas por fuente se dejan descartadas y cuántas resueltas")
	flag.Parse()

	if err := experiment.RequireConfirmation(); err != nil {
		return err
	}
	meta, err := simulate.LoadMeta(*metaPath)
	if err != nil {
		return fmt.Errorf("leyendo %s (¿corriste cmd/simulate?): %w", *metaPath, err)
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

	router, err := alertseed.NewRouter(pool)
	if err != nil {
		return err
	}
	defer router.Close()

	d := detector.New(pool, cfg.Rules, model, cfg.IFThreshold, nil)
	d.TenantNamePrefix = *prefix

	sum, err := alertseed.Seed(ctx, pool, alertseed.Options{
		Detector: d, Router: router, From: meta.EvalFrom, To: meta.EvalTo,
		TenantNamePrefix: *prefix, PerSource: *perSource,
	})
	if err != nil {
		return err
	}

	fmt.Printf("Período: %s a %s. Alertas nuevas del detector: %d. Cerradas por las rutas de la API: %d.\n",
		meta.EvalFrom.Format("2006-01-02"), meta.EvalTo.Format("2006-01-02"), sum.Created, sum.Closed)
	fmt.Printf("%-18s %8s %11s %9s\n", "fuente", "abierta", "descartada", "resuelta")
	for _, s := range alertseed.Sources {
		c := sum.Counts[s]
		fmt.Printf("%-18s %8d %11d %9d\n", s, c[detector.StateAbierta], c[detector.StateDescartada], c[detector.StateResuelta])
	}
	return nil
}
