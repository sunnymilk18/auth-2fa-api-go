package detector

import (
	"fmt"
	"math"
	"math/rand/v2"
)

// Isolation Forest (Liu, Ting y Zhou, 2008), implementado con la biblioteca
// estándar. Idea: los puntos raros se aíslan con pocos cortes aleatorios, así
// que su largo de camino promedio en los árboles es corto.
//
//	s(x, ψ) = 2^(-E(h(x)) / c(ψ))
//
// con E(h(x)) el largo de camino promedio de x en el bosque (en las hojas se
// suma c(tamaño de la hoja) por los puntos que el árbol no llegó a separar) y
// c(n) el largo de camino promedio de una búsqueda fallida en un árbol
// binario de búsqueda con n puntos. s cerca de 1 es anómalo; cerca de 0,5 o
// menos, normal.

// eulerGamma es la constante de Euler–Mascheroni, para la aproximación de la
// serie armónica H(i) ≈ ln(i) + γ.
const eulerGamma = 0.5772156649015329

// avgPathLength es c(n).
func avgPathLength(n int) float64 {
	switch {
	case n <= 1:
		return 0
	case n == 2:
		return 1
	default:
		fn := float64(n)
		return 2*(math.Log(fn-1)+eulerGamma) - 2*(fn-1)/fn
	}
}

// node es un nodo de árbol en forma plana. Una hoja tiene Feature < 0 y Size
// con la cantidad de puntos de entrenamiento que quedaron en ella. Los hijos
// siempre tienen un índice mayor que su padre (así se construyen), lo que
// permite validar un modelo cargado sin riesgo de ciclos.
type node struct {
	Feature int     `json:"f"`
	Split   float64 `json:"s,omitempty"`
	Left    int     `json:"l,omitempty"`
	Right   int     `json:"r,omitempty"`
	Size    int     `json:"n,omitempty"`
}

// Tree es un árbol de aislamiento.
type Tree struct {
	Nodes []node `json:"nodes"`
}

// Forest es un conjunto de árboles de aislamiento entrenados con submuestras
// de tamaño SampleSize (ψ).
type Forest struct {
	SampleSize int    `json:"sample_size"`
	Trees      []Tree `json:"trees"`
}

// trainForest entrena trees árboles, cada uno con una submuestra sin
// reposición de tamaño min(psi, len(data)), con altura máxima ceil(log2(ψ)).
// Con la misma semilla y los mismos datos entrega siempre el mismo bosque.
func trainForest(data [][]float64, trees, psi int, rng *rand.Rand) (*Forest, error) {
	if len(data) < 2 {
		return nil, fmt.Errorf("se necesitan al menos 2 puntos para entrenar, hay %d", len(data))
	}
	if trees < 1 || psi < 2 {
		return nil, fmt.Errorf("parámetros inválidos: árboles=%d, submuestra=%d", trees, psi)
	}
	if psi > len(data) {
		psi = len(data)
	}
	heightLimit := int(math.Ceil(math.Log2(float64(psi))))

	f := &Forest{SampleSize: psi, Trees: make([]Tree, trees)}
	for t := range f.Trees {
		idx := rng.Perm(len(data))[:psi]
		sample := make([][]float64, psi)
		for i, j := range idx {
			sample[i] = data[j]
		}
		b := &treeBuilder{rng: rng, heightLimit: heightLimit}
		b.build(sample, 0)
		f.Trees[t] = Tree{Nodes: b.nodes}
	}
	return f, nil
}

type treeBuilder struct {
	rng         *rand.Rand
	heightLimit int
	nodes       []node
}

// build agrega a b.nodes el subárbol de rows y devuelve el índice de su raíz.
func (b *treeBuilder) build(rows [][]float64, depth int) int {
	self := len(b.nodes)
	b.nodes = append(b.nodes, node{Feature: -1, Size: len(rows)})
	if depth >= b.heightLimit || len(rows) <= 1 {
		return self
	}

	// Solo se puede cortar por una característica que no sea constante en
	// este nodo. Si todas lo son, los puntos son idénticos: queda hoja.
	dims := len(rows[0])
	mins := make([]float64, dims)
	maxs := make([]float64, dims)
	copy(mins, rows[0])
	copy(maxs, rows[0])
	for _, r := range rows[1:] {
		for d, v := range r {
			if v < mins[d] {
				mins[d] = v
			}
			if v > maxs[d] {
				maxs[d] = v
			}
		}
	}
	var candidates []int
	for d := 0; d < dims; d++ {
		if maxs[d] > mins[d] {
			candidates = append(candidates, d)
		}
	}
	if len(candidates) == 0 {
		return self
	}

	feature := candidates[b.rng.IntN(len(candidates))]
	split := mins[feature] + b.rng.Float64()*(maxs[feature]-mins[feature])
	var left, right [][]float64
	for _, r := range rows {
		if r[feature] < split {
			left = append(left, r)
		} else {
			right = append(right, r)
		}
	}
	if len(left) == 0 || len(right) == 0 {
		// Solo si el sorteo cayó justo en el mínimo: se corta por el punto
		// medio, que siempre separa (el máximo es estrictamente mayor).
		split = (mins[feature] + maxs[feature]) / 2
		left, right = left[:0], right[:0]
		for _, r := range rows {
			if r[feature] < split {
				left = append(left, r)
			} else {
				right = append(right, r)
			}
		}
	}

	b.nodes[self].Feature = feature
	b.nodes[self].Split = split
	b.nodes[self].Size = 0
	l := b.build(left, depth+1)
	r := b.build(right, depth+1)
	b.nodes[self].Left = l
	b.nodes[self].Right = r
	return self
}

// pathLength es h(x) en un árbol: profundidad de la hoja donde cae x más
// c(tamaño de la hoja).
func (t *Tree) pathLength(x []float64) float64 {
	i, depth := 0, 0
	for {
		n := t.Nodes[i]
		if n.Feature < 0 {
			return float64(depth) + avgPathLength(n.Size)
		}
		if x[n.Feature] < n.Split {
			i = n.Left
		} else {
			i = n.Right
		}
		depth++
	}
}

// Score es s = 2^(-E(h(x))/c(ψ)), entre 0 y 1.
func (f *Forest) Score(x []float64) float64 {
	c := avgPathLength(f.SampleSize)
	if c == 0 || len(f.Trees) == 0 {
		return 0.5
	}
	var sum float64
	for i := range f.Trees {
		sum += f.Trees[i].pathLength(x)
	}
	return math.Pow(2, -(sum/float64(len(f.Trees)))/c)
}

// validate comprueba que un bosque cargado desde un archivo no pueda hacer
// entrar en pánico a Score: índices en rango, hijos siempre después del
// padre (sin ciclos) y características dentro del vector.
func (f *Forest) validate(dims int) error {
	if f.SampleSize < 2 || len(f.Trees) == 0 {
		return fmt.Errorf("bosque vacío o con submuestra inválida")
	}
	for ti, t := range f.Trees {
		if len(t.Nodes) == 0 {
			return fmt.Errorf("árbol %d sin nodos", ti)
		}
		for i, n := range t.Nodes {
			if n.Feature < 0 {
				continue
			}
			if n.Feature >= dims {
				return fmt.Errorf("árbol %d, nodo %d: característica %d fuera de rango", ti, i, n.Feature)
			}
			if n.Left <= i || n.Right <= i || n.Left >= len(t.Nodes) || n.Right >= len(t.Nodes) {
				return fmt.Errorf("árbol %d, nodo %d: hijos fuera de rango", ti, i)
			}
		}
	}
	return nil
}
