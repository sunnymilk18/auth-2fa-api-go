#!/usr/bin/env sh
# Corre el experimento completo del detector de accesos anómalos:
# simulate -> train -> evaluate, contra la base de datos LOCAL.
#
#   sh scripts/experimento.sh            # semilla 42, salida en ./experimento
#   sh scripts/experimento.sh 7 salida7  # semilla y carpeta de salida
#
# Con la misma semilla, los tres pasos dan exactamente los mismos archivos.
# Se niega a correr si la base no es local (ver internal/experiment). La
# confirmación SIMULATE_CONFIRM_LOCAL=yes solo vale para estos comandos.
set -eu

cd "$(dirname "$0")/.."
SEMILLA="${1:-42}"
SALIDA="${2:-experimento}"

export SIMULATE_CONFIRM_LOCAL=yes

echo "== 1/3 Simular datos =="
go run ./cmd/simulate -semilla "$SEMILLA" -salida "$SALIDA"

echo
echo "== 2/3 Entrenar el Isolation Forest =="
go run ./cmd/train -meta "$SALIDA/meta.json" -prefijo-tenant sim- -salida "$SALIDA/modelo.json"

echo
echo "== 3/3 Evaluar =="
go run ./cmd/evaluate -meta "$SALIDA/meta.json" -etiquetas "$SALIDA/ground_truth.json" -modelo "$SALIDA/modelo.json" -prefijo-tenant sim- -salida "$SALIDA"
