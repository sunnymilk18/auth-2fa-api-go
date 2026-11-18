<#
.SYNOPSIS
  Corre el experimento completo del detector de accesos anómalos:
  simulate -> train -> evaluate, contra la base de datos LOCAL.

.DESCRIPTION
  Desde la raíz del proyecto:

    pwsh scripts/experimento.ps1
    pwsh scripts/experimento.ps1 -Semilla 7 -Salida experimento-7
    pwsh scripts/experimento.ps1 -Intensidad lento -Salida experimento_lento

  Con la misma semilla, los tres pasos dan exactamente los mismos archivos.
  Escribe en la carpeta de salida: ground_truth.json (etiquetas reales),
  meta.json (rangos de fechas), modelo.json (Isolation Forest entrenado) y los
  resultados (resultados.md y cuatro CSV).

  Se niega a correr si la base no es local (ver internal/experiment). La
  confirmación explícita SIMULATE_CONFIRM_LOCAL=yes solo se define mientras
  corre este script.
#>
param(
    [UInt64]$Semilla = 42,
    [string]$Salida = "experimento",
    [ValidateSet("actual", "lento")][string]$Intensidad = "actual"
)

$ErrorActionPreference = "Stop"
Set-Location (Split-Path -Parent $PSScriptRoot)

function Invoke-Paso([string]$Titulo, [string[]]$Argumentos) {
    Write-Host ""
    Write-Host "== $Titulo ==" -ForegroundColor Cyan
    & go run @Argumentos
    if ($LASTEXITCODE -ne 0) { throw "El paso '$Titulo' falló (código $LASTEXITCODE)." }
}

$env:SIMULATE_CONFIRM_LOCAL = "yes"
try {
    Invoke-Paso "1/3 Simular datos" @("./cmd/simulate", "-semilla", "$Semilla", "-intensidad", $Intensidad, "-salida", $Salida)
    Invoke-Paso "2/3 Entrenar el Isolation Forest" @("./cmd/train", "-meta", "$Salida/meta.json", "-prefijo-tenant", "sim-", "-salida", "$Salida/modelo.json")
    Invoke-Paso "3/3 Evaluar" @("./cmd/evaluate", "-meta", "$Salida/meta.json", "-etiquetas", "$Salida/ground_truth.json", "-modelo", "$Salida/modelo.json", "-prefijo-tenant", "sim-", "-salida", $Salida)
}
finally {
    Remove-Item Env:SIMULATE_CONFIRM_LOCAL -ErrorAction SilentlyContinue
}
