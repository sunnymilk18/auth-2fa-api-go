package main

import (
	"bytes"
	"log/slog"
	"math/rand/v2"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"auth-2fa-api/internal/detector"
)

func testModelFile(t *testing.T) string {
	t.Helper()
	rng := rand.New(rand.NewPCG(1, 2))
	var units []detector.Unit
	for i := 0; i < 200; i++ {
		units = append(units, detector.Unit{
			WindowStart: time.Date(2026, 10, 5, 0, 0, 0, 0, time.UTC).Add(time.Duration(i) * detector.WindowSize),
			KeyType:     detector.KeyIP, IP: "198.18.0.1",
			Features: detector.Features{Fallos: rng.IntN(4), Correctos: rng.IntN(10)},
		})
	}
	model, err := detector.TrainModel(units, detector.TrainParams{Trees: 5, SampleSize: 32, Seed: 1})
	if err != nil {
		t.Fatalf("TrainModel: %v", err)
	}
	path := filepath.Join(t.TempDir(), "iforest.json")
	if err := model.Save(path); err != nil {
		t.Fatalf("Save: %v", err)
	}
	return path
}

// Sin modelo (archivo ausente) o con un modelo dañado, la API no se cae: el
// detector arranca solo con reglas y señuelos.
func TestLoadDetectorModel_SinModeloNoRompe(t *testing.T) {
	var logs bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logs, nil))

	if m := loadDetectorModel(filepath.Join(t.TempDir(), "no-existe.json"), logger); m != nil {
		t.Fatal("un archivo ausente debe dar nil (solo reglas)")
	}
	if !strings.Contains(logs.String(), "sin modelo, solo reglas") || strings.Contains(logs.String(), "level=ERROR") {
		t.Fatalf("un archivo ausente es normal: se informa, no es un error:\n%s", logs.String())
	}

	logs.Reset()
	broken := filepath.Join(t.TempDir(), "roto.json")
	if err := os.WriteFile(broken, []byte("esto no es un modelo"), 0o644); err != nil {
		t.Fatal(err)
	}
	if m := loadDetectorModel(broken, logger); m != nil {
		t.Fatal("un archivo dañado debe dar nil (solo reglas), no un modelo a medias")
	}
	if !strings.Contains(logs.String(), "level=ERROR") {
		t.Fatalf("un archivo dañado sí debe quedar como error en el log:\n%s", logs.String())
	}
}

func TestLoadDetectorModel_CargaUnModeloValido(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil))
	m := loadDetectorModel(testModelFile(t), logger)
	if m == nil {
		t.Fatal("un modelo válido debe cargarse")
	}
	if _, ok := m.Score(detector.KeyIP, detector.Features{Fallos: 50}); !ok {
		t.Fatal("el modelo cargado debe poder puntuar")
	}
}
