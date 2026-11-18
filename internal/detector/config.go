package detector

import (
	"fmt"
	"os"
	"strconv"
	"time"
)

// Config reúne los ajustes del detector, todos por variables de entorno. Vive
// aquí y no en internal/config porque cmd/train, cmd/evaluate y cmd/simulate
// también lo necesitan y no deben cargar el .env de la API (ver
// internal/experiment).
type Config struct {
	// Enabled (DETECTOR_ENABLED, apagado por defecto): arranca la tarea en
	// segundo plano dentro de la API.
	Enabled bool
	// Interval (DETECTOR_INTERVAL, 5m): cada cuánto corre la tarea.
	Interval time.Duration
	// Lookback (DETECTOR_LOOKBACK, 1h): cuánto hacia atrás revisa en cada
	// pasada. Debe cubrir al menos dos ventanas para no perder la que se
	// completó justo entre dos pasadas.
	Lookback time.Duration
	// ModelPath (DETECTOR_MODEL_PATH): archivo del modelo. Si no existe, la
	// API sigue solo con reglas.
	ModelPath string
	// IFThreshold (DETECTOR_IF_THRESHOLD): puntaje desde el cual el bosque
	// alerta. Sin definir (0), cada bosque usa el umbral calibrado con el
	// tráfico de entrenamiento y guardado en el modelo (ver
	// KeyModel.Threshold); definido, vale para todos.
	IFThreshold float64
	// Train (DETECTOR_IF_TREES, DETECTOR_IF_SUBSAMPLE, DETECTOR_IF_SEED,
	// DETECTOR_IF_QUANTILE): parámetros del bosque y del cuantil con que se
	// calibra su umbral; solo los usa cmd/train.
	Train TrainParams
	// Rules (DETECTOR_RULE_*): umbrales de la línea base.
	Rules Rules
}

// DefaultModelPath es dónde cmd/train escribe y la API busca el modelo si no
// se indica otra cosa.
const DefaultModelPath = "models/iforest.json"

// LoadConfig lee los ajustes del entorno aplicando los valores por defecto.
// Lee solo el entorno del proceso: no carga ningún archivo .env.
func LoadConfig() (Config, error) {
	def := DefaultRules()
	cfg := Config{
		ModelPath: envString("DETECTOR_MODEL_PATH", DefaultModelPath),
		Train:     DefaultTrainParams(),
	}
	var err error
	if cfg.Enabled, err = envBool("DETECTOR_ENABLED", false); err != nil {
		return cfg, err
	}
	if cfg.Interval, err = envDuration("DETECTOR_INTERVAL", 5*time.Minute); err != nil {
		return cfg, err
	}
	if cfg.Lookback, err = envDuration("DETECTOR_LOOKBACK", time.Hour); err != nil {
		return cfg, err
	}
	if cfg.IFThreshold, err = envFloat("DETECTOR_IF_THRESHOLD", 0); err != nil {
		return cfg, err
	}
	if cfg.Train.ThresholdQuantile, err = envFloat("DETECTOR_IF_QUANTILE", DefaultThresholdQuantile); err != nil {
		return cfg, err
	}
	if cfg.Train.Trees, err = envInt("DETECTOR_IF_TREES", DefaultTrees); err != nil {
		return cfg, err
	}
	if cfg.Train.SampleSize, err = envInt("DETECTOR_IF_SUBSAMPLE", DefaultSampleSize); err != nil {
		return cfg, err
	}
	seed, err := envInt("DETECTOR_IF_SEED", DefaultSeed)
	if err != nil {
		return cfg, err
	}
	cfg.Train.Seed = uint64(seed)
	if cfg.Rules.Fallos, err = envInt("DETECTOR_RULE_FALLOS", def.Fallos); err != nil {
		return cfg, err
	}
	if cfg.Rules.Cuentas, err = envInt("DETECTOR_RULE_CUENTAS", def.Cuentas); err != nil {
		return cfg, err
	}
	if cfg.Rules.IPsConFallos, err = envInt("DETECTOR_RULE_IPS", def.IPsConFallos); err != nil {
		return cfg, err
	}
	if cfg.Rules.Inexistentes, err = envInt("DETECTOR_RULE_INEXISTENTES", def.Inexistentes); err != nil {
		return cfg, err
	}

	if cfg.Interval < time.Second {
		return cfg, fmt.Errorf("DETECTOR_INTERVAL debe ser de al menos 1s")
	}
	if cfg.Lookback < 2*WindowSize {
		return cfg, fmt.Errorf("DETECTOR_LOOKBACK debe cubrir al menos dos ventanas (%s)", 2*WindowSize)
	}
	if cfg.IFThreshold != 0 && (cfg.IFThreshold < 0 || cfg.IFThreshold >= 1) {
		return cfg, fmt.Errorf("DETECTOR_IF_THRESHOLD debe estar entre 0 y 1 (sin incluirlos)")
	}
	if cfg.Train.ThresholdQuantile <= 0 || cfg.Train.ThresholdQuantile >= 1 {
		return cfg, fmt.Errorf("DETECTOR_IF_QUANTILE debe estar entre 0 y 1 (sin incluirlos)")
	}
	if cfg.Train.Trees < 1 || cfg.Train.SampleSize < 2 || seed < 0 {
		return cfg, fmt.Errorf("DETECTOR_IF_TREES >= 1, DETECTOR_IF_SUBSAMPLE >= 2 y DETECTOR_IF_SEED >= 0")
	}
	return cfg, nil
}

func envString(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func envInt(key string, fallback int) (int, error) {
	v := os.Getenv(key)
	if v == "" {
		return fallback, nil
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return 0, fmt.Errorf("%s debe ser un entero: %w", key, err)
	}
	return n, nil
}

func envFloat(key string, fallback float64) (float64, error) {
	v := os.Getenv(key)
	if v == "" {
		return fallback, nil
	}
	f, err := strconv.ParseFloat(v, 64)
	if err != nil {
		return 0, fmt.Errorf("%s debe ser un número: %w", key, err)
	}
	return f, nil
}

func envBool(key string, fallback bool) (bool, error) {
	v := os.Getenv(key)
	if v == "" {
		return fallback, nil
	}
	b, err := strconv.ParseBool(v)
	if err != nil {
		return false, fmt.Errorf("%s debe ser verdadero o falso: %w", key, err)
	}
	return b, nil
}

func envDuration(key string, fallback time.Duration) (time.Duration, error) {
	v := os.Getenv(key)
	if v == "" {
		return fallback, nil
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		return 0, fmt.Errorf("%s debe ser una duración (por ejemplo 5m): %w", key, err)
	}
	return d, nil
}
