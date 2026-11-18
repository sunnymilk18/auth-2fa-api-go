package detector

import (
	"encoding/json"
	"fmt"
	"math"
	"math/rand/v2"
	"os"
	"slices"
	"sort"
	"strconv"
	"strings"
)

// ModelVersion cambia si el formato del archivo cambia de forma incompatible.
const ModelVersion = 1

// MinTrainingUnits es la cantidad mínima de ventanas de entrenamiento para
// armar un bosque de un tipo de clave. Con menos, el bosque no representa
// nada y ese tipo de clave queda solo con reglas.
const MinTrainingUnits = 50

// Parámetros por defecto del bosque (los del artículo original) y del
// cuantil con que se calibra el umbral.
const (
	DefaultTrees             = 100
	DefaultSampleSize        = 256
	DefaultSeed              = 42
	DefaultThresholdQuantile = 0.995
)

// Umbral de desviación robusta (z) desde el cual una característica se
// considera fuera de lo normal al explicar una alerta, y cuántos motivos
// como máximo se muestran.
const (
	explainMinZ = 3.0
	explainTopN = 3
)

// TrainParams son los parámetros de entrenamiento.
type TrainParams struct {
	Trees      int
	SampleSize int
	Seed       uint64
	// ThresholdQuantile: con qué cuantil de los puntajes del propio
	// entrenamiento se calibra el umbral de alerta de cada bosque (0,995: se
	// espera alertar a lo más ~0,5 % del tráfico normal). Ver KeyModel.Threshold.
	ThresholdQuantile float64
}

// DefaultTrainParams devuelve t=100, ψ=256, la semilla fija y el cuantil
// 0,995 por defecto.
func DefaultTrainParams() TrainParams {
	return TrainParams{Trees: DefaultTrees, SampleSize: DefaultSampleSize, Seed: DefaultSeed, ThresholdQuantile: DefaultThresholdQuantile}
}

// FeatureStats resume una característica en el tráfico normal de
// entrenamiento. Sirve para explicar una alerta, no para puntuar.
type FeatureStats struct {
	Median float64 `json:"median"`
	// MAD es la desviación absoluta mediana: más robusta que la desviación
	// estándar frente a las pocas ventanas raras que siempre hay.
	MAD  float64 `json:"mad"`
	Mean float64 `json:"mean"`
	Std  float64 `json:"std"`
}

// KeyModel es el modelo de un tipo de clave (tenant o IP). Se entrenan por
// separado porque una ventana por tenant junta a muchas personas y una por
// IP a pocas: lo normal en una no lo es en la otra.
type KeyModel struct {
	TrainingUnits int `json:"training_units"`
	// Threshold es el umbral de alerta calibrado con el tráfico normal de
	// entrenamiento: el primer valor de puntaje por encima del cuantil
	// ThresholdQuantile de los puntajes de esas mismas ventanas. Un valor
	// fijo (como 0,6) no sirve de referencia con conteos tan repetidos —
	// en el propio entrenamiento, una parte del tráfico normal ya lo pasa —
	// así que cada bosque lleva el suyo. DETECTOR_IF_THRESHOLD, si se define,
	// lo reemplaza.
	Threshold         float64        `json:"threshold"`
	ThresholdQuantile float64        `json:"threshold_quantile"`
	Forest            *Forest        `json:"forest"`
	Stats             []FeatureStats `json:"stats"`
}

// Model es lo que cmd/train escribe y la API carga al arrancar. No guarda la
// fecha de entrenamiento a propósito: mismos datos y misma semilla dan un
// archivo idéntico byte a byte.
type Model struct {
	Version    int                  `json:"version"`
	Window     string               `json:"window"`
	Features   []string             `json:"features"`
	Trees      int                  `json:"trees"`
	SampleSize int                  `json:"sample_size"`
	Seed       uint64               `json:"seed"`
	Keys       map[string]*KeyModel `json:"keys"`
}

// TrainModel entrena un bosque por tipo de clave con las unidades dadas, que
// deben ser tráfico normal. Un tipo de clave con menos de MinTrainingUnits
// ventanas se omite; si no queda ninguno, devuelve error.
func TrainModel(units []Unit, p TrainParams) (*Model, error) {
	if p.Trees == 0 {
		p.Trees = DefaultTrees
	}
	if p.SampleSize == 0 {
		p.SampleSize = DefaultSampleSize
	}
	if p.ThresholdQuantile == 0 {
		p.ThresholdQuantile = DefaultThresholdQuantile
	}
	if p.ThresholdQuantile <= 0 || p.ThresholdQuantile >= 1 {
		return nil, fmt.Errorf("el cuantil del umbral debe estar entre 0 y 1 (sin incluirlos), no %v", p.ThresholdQuantile)
	}

	sorted := slices.Clone(units)
	SortUnits(sorted)

	m := &Model{
		Version:    ModelVersion,
		Window:     WindowSize.String(),
		Features:   slices.Clone(FeatureNames),
		Trees:      p.Trees,
		SampleSize: p.SampleSize,
		Seed:       p.Seed,
		Keys:       map[string]*KeyModel{},
	}

	for i, keyType := range []string{KeyTenant, KeyIP} {
		var data [][]float64
		for _, u := range sorted {
			if u.KeyType == keyType {
				data = append(data, u.Features.Vector())
			}
		}
		if len(data) < MinTrainingUnits {
			continue
		}
		// Una secuencia aleatoria propia por tipo de clave, derivada de la
		// misma semilla: agregar o quitar un tipo no cambia el otro bosque.
		rng := rand.New(rand.NewPCG(p.Seed, uint64(i)+1))
		forest, err := trainForest(data, p.Trees, p.SampleSize, rng)
		if err != nil {
			return nil, fmt.Errorf("entrenando el bosque de %s: %w", keyType, err)
		}
		m.Keys[keyType] = &KeyModel{
			TrainingUnits: len(data), Forest: forest, Stats: computeStats(data),
			Threshold: calibrateThreshold(forest, data, p.ThresholdQuantile), ThresholdQuantile: p.ThresholdQuantile,
		}
	}
	if len(m.Keys) == 0 {
		return nil, fmt.Errorf("no hay suficientes ventanas de entrenamiento (mínimo %d por tipo de clave)", MinTrainingUnits)
	}
	return m, nil
}

// calibrateThreshold puntúa los datos de entrenamiento y devuelve el primer
// valor por encima de su cuantil q. "Por encima" (no "igual"): con conteos
// repetidos, muchas ventanas idénticas comparten exactamente el mismo
// puntaje, y un umbral igual a ese valor las alertaría a todas de golpe.
func calibrateThreshold(f *Forest, data [][]float64, q float64) float64 {
	scores := make([]float64, len(data))
	for i, x := range data {
		scores[i] = f.Score(x)
	}
	sort.Float64s(scores)
	idx := int(math.Ceil(q*float64(len(scores)))) - 1
	if idx < 0 {
		idx = 0
	}
	if idx >= len(scores) {
		idx = len(scores) - 1
	}
	return math.Nextafter(scores[idx], 2)
}

func computeStats(data [][]float64) []FeatureStats {
	stats := make([]FeatureStats, len(FeatureNames))
	col := make([]float64, len(data))
	for d := range stats {
		var sum float64
		for i, row := range data {
			col[i] = row[d]
			sum += row[d]
		}
		mean := sum / float64(len(col))
		var sq float64
		for _, v := range col {
			sq += (v - mean) * (v - mean)
		}
		median := medianOf(col)
		dev := make([]float64, len(col))
		for i, v := range col {
			dev[i] = math.Abs(v - median)
		}
		stats[d] = FeatureStats{Median: median, MAD: medianOf(dev), Mean: mean, Std: math.Sqrt(sq / float64(len(col)))}
	}
	return stats
}

func medianOf(values []float64) float64 {
	c := slices.Clone(values)
	sort.Float64s(c)
	n := len(c)
	if n == 0 {
		return 0
	}
	if n%2 == 1 {
		return c[n/2]
	}
	return (c[n/2-1] + c[n/2]) / 2
}

// Save escribe el modelo como JSON.
func (m *Model) Save(path string) error {
	b, err := json.Marshal(m)
	if err != nil {
		return fmt.Errorf("serializando el modelo: %w", err)
	}
	if err := os.WriteFile(path, b, 0o644); err != nil {
		return fmt.Errorf("escribiendo el modelo: %w", err)
	}
	return nil
}

// LoadModel lee y valida un modelo. Un archivo dañado da error en vez de un
// pánico más adelante, al puntuar.
func LoadModel(path string) (*Model, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var m Model
	if err := json.Unmarshal(b, &m); err != nil {
		return nil, fmt.Errorf("el modelo no es un JSON válido: %w", err)
	}
	if m.Version != ModelVersion {
		return nil, fmt.Errorf("versión de modelo %d no soportada (se esperaba %d)", m.Version, ModelVersion)
	}
	if !slices.Equal(m.Features, FeatureNames) {
		return nil, fmt.Errorf("el modelo se entrenó con otras características: %v", m.Features)
	}
	if len(m.Keys) == 0 {
		return nil, fmt.Errorf("el modelo no trae ningún bosque")
	}
	for keyType, km := range m.Keys {
		if keyType != KeyTenant && keyType != KeyIP {
			return nil, fmt.Errorf("tipo de clave desconocido en el modelo: %q", keyType)
		}
		if km == nil || km.Forest == nil {
			return nil, fmt.Errorf("el bosque de %s está vacío", keyType)
		}
		if len(km.Stats) != len(FeatureNames) {
			return nil, fmt.Errorf("las estadísticas de %s no cubren las %d características", keyType, len(FeatureNames))
		}
		if err := km.Forest.validate(len(FeatureNames)); err != nil {
			return nil, fmt.Errorf("bosque de %s: %w", keyType, err)
		}
	}
	return &m, nil
}

// Threshold devuelve el umbral calibrado del bosque de keyType, o
// DefaultIFThreshold si el modelo no lo tiene.
func (m *Model) Threshold(keyType string) float64 {
	if m != nil {
		if km := m.Keys[keyType]; km != nil && km.Threshold > 0 {
			return km.Threshold
		}
	}
	return DefaultIFThreshold
}

// Score puntúa f con el bosque de keyType. ok es false si el modelo no tiene
// bosque para ese tipo de clave (o el modelo es nil): esa ventana queda solo
// con reglas.
func (m *Model) Score(keyType string, f Features) (score float64, ok bool) {
	if m == nil {
		return 0, false
	}
	km := m.Keys[keyType]
	if km == nil {
		return 0, false
	}
	return km.Forest.Score(f.Vector()), true
}

// Explain lista, en español, las características que más se alejan de lo
// normal en el entrenamiento — nunca vacía. Usa la desviación robusta
// z = (x − mediana) / (1,4826·MAD); cuando MAD es 0 (lo habitual en conteos
// con muchos ceros) cae a la desviación estándar, y si esa también es 0, a 1.
// Solo cuenta lo que está por encima de lo normal: un valor bajo no es un
// ataque. "Lo normal" es la mediana del entrenamiento.
func (m *Model) Explain(keyType string, f Features) []string {
	var km *KeyModel
	if m != nil {
		km = m.Keys[keyType]
	}
	if km == nil {
		return []string{"puntaje de aislamiento alto, sin referencia de tráfico normal para explicarlo"}
	}

	values := f.Vector()
	type dev struct {
		idx int
		z   float64
	}
	var all []dev
	for i, v := range values {
		st := km.Stats[i]
		if v <= st.Median {
			continue
		}
		scale := 1.4826 * st.MAD
		if scale < 1e-9 {
			scale = st.Std
		}
		if scale < 1e-9 {
			scale = 1
		}
		all = append(all, dev{i, (v - st.Median) / scale})
	}
	sort.SliceStable(all, func(a, b int) bool { return all[a].z > all[b].z })

	var chosen []dev
	for _, d := range all {
		if d.z >= explainMinZ && len(chosen) < explainTopN {
			chosen = append(chosen, d)
		}
	}
	if len(chosen) == 0 && len(all) > 0 {
		chosen = all[:1]
	}
	if len(chosen) == 0 {
		return []string{"puntaje de aislamiento alto, sin una característica claramente fuera de lo normal"}
	}

	motives := make([]string, 0, len(chosen))
	for _, d := range chosen {
		motives = append(motives, deviationText(d.idx, int(values[d.idx]), km.Stats[d.idx].Median))
	}
	return motives
}

type featureText struct{ one, many string }

var deviationTexts = map[string]featureText{
	FeatureFallos:            {"fallo", "fallos"},
	FeatureCorrectos:         {"inicio de sesión correcto", "inicios de sesión correctos"},
	FeatureIPsConFallos:      {"IP distinta con fallos", "IPs distintas con fallos"},
	FeatureCuentasAtacadas:   {"cuenta distinta atacada", "cuentas distintas atacadas"},
	FeatureCuentaInexistente: {"intento contra una cuenta inexistente", "intentos contra cuentas inexistentes"},
	FeatureSenuelos:          {"intento contra una cuenta señuelo", "intentos contra cuentas señuelo"},
}

// deviationText arma, por ejemplo, "42 fallos en 10 min (lo normal es 3)".
func deviationText(idx, value int, median float64) string {
	t := deviationTexts[FeatureNames[idx]]
	return fmt.Sprintf("%s en %s (lo normal es %s)", countText(value, t.one, t.many), windowLabel, formatNumber(median))
}

// formatNumber muestra enteros sin decimales y el resto con una coma decimal.
func formatNumber(v float64) string {
	if v == math.Trunc(v) {
		return strconv.Itoa(int(v))
	}
	return strings.Replace(strconv.FormatFloat(v, 'f', 1, 64), ".", ",", 1)
}
