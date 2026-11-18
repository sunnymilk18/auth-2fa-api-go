#!/usr/bin/env python3
"""Arma experimento_resumen/resumen.md: las métricas del experimento del
detector agregadas por semilla y por intensidad (promedio y rango).

Lee los archivos que escribe cmd/evaluate en cada carpeta de resultados:
resultados.md, resultados_metricas.csv, resultados_escenarios.csv,
resultados_umbral.csv y resultados_tiempos.csv. No toca la base de datos ni
corre nada: primero hay que haber corrido el experimento por semilla e
intensidad (ver MANUAL.md, secciones 3.5 y 3.7).

Convención de carpetas, desde la raíz del proyecto:

  intensidad actual:  experimento (semilla 42) y experimento_s<semilla>
  intensidad lento:   experimento_lento_s<semilla>

Uso (desde cualquier carpeta):

  python scripts/resumen_experimento.py
  python scripts/resumen_experimento.py --semillas 42 7 123 2026 --intensidades actual lento
"""
import argparse
import csv
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

METHODS = ["reglas", "senuelos", "reglas_senuelos", "isolation_forest", "combinado"]
TITLE = {"reglas": "Reglas", "senuelos": "Señuelos", "reglas_senuelos": "Línea base",
         "isolation_forest": "Isolation Forest", "combinado": "Combinado"}
SCEN = ["relleno_credenciales", "pulverizado_contrasenas", "fuerza_bruta_cuenta", "ataque_distribuido", "toque_senuelos"]
STITLE = {"relleno_credenciales": "Relleno de credenciales", "pulverizado_contrasenas": "Pulverizado",
          "fuerza_bruta_cuenta": "Fuerza bruta", "ataque_distribuido": "Distribuido",
          "toque_senuelos": "Señuelos", "todos": "Todos"}


def carpeta(intensidad, semilla):
    if intensidad == "actual":
        return "experimento" if semilla == 42 else f"experimento_s{semilla}"
    return f"experimento_{intensidad}_s{semilla}"


def leer_csv(ruta):
    with open(os.path.join(ROOT, ruta), encoding="utf-8", newline="") as f:
        return list(csv.reader(f))


def numero(v):
    return None if v == "" else float(v)


def fmt(v, d=3):
    return "n/d" if v is None else f"{v:.{d}f}".replace(".", ",")


def estadisticas(vals, d=3):
    """Promedio y rango entre semillas; ignora las semillas sin dato."""
    vals = [v for v in vals if v is not None]
    if not vals:
        return "n/d"
    return f"{fmt(sum(vals) / len(vals), d)} [{fmt(min(vals), d)}–{fmt(max(vals), d)}]"


def tiene_tiempos(intensidad, semillas):
    return all(os.path.exists(os.path.join(ROOT, carpeta(intensidad, s), "resultados_tiempos.csv")) for s in semillas)


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--semillas", type=int, nargs="+", default=[42, 7, 123, 2026])
    ap.add_argument("--intensidades", nargs="+", default=["actual", "lento"])
    args = ap.parse_args()
    semillas = args.semillas

    out = []

    def p(linea=""):
        out.append(linea)

    for nivel in args.intensidades:
        p(f"## Intensidad: {nivel}")
        p()
        metricas, info = {}, {}
        for s in semillas:
            d = carpeta(nivel, s)
            for fila in leer_csv(f"{d}/resultados_metricas.csv")[1:]:
                if fila[1] == "todas":
                    metricas[(s, fila[0])] = (numero(fila[6]), numero(fila[7]), numero(fila[8]), fila[2:6])
            with open(os.path.join(ROOT, d, "resultados.md"), encoding="utf-8") as f:
                md = f.read()
            m = re.search(r"Unidades evaluadas.*?: (\d+), de las cuales (\d+) son positivas", md)
            e = re.search(r"Excluidas de la matriz: (\d+)", md)
            info[s] = (m.group(1), m.group(2), e.group(1) if e else "0")
        p("Unidades evaluadas / positivas / excluidas por semilla: " + "; ".join(f"{s}: {info[s][0]} / {info[s][1]} / {info[s][2]}" for s in semillas))
        p()

        for nombre, col in [("F1", 2), ("Precisión", 0), ("Exhaustividad", 1)]:
            p(f"**{nombre} por método y semilla**")
            p()
            p("| Método | " + " | ".join(f"s{s}" for s in semillas) + " | Promedio [rango] |")
            p("|---|" + "---:|" * (len(semillas) + 1))
            for m in METHODS:
                vals = [metricas[(s, m)][col] for s in semillas]
                p(f"| {TITLE[m]} | " + " | ".join(fmt(v) for v in vals) + f" | {estadisticas(vals)} |")
            p()

        p("**Matriz (VP / FP / FN / VN) por método y semilla**")
        p()
        p("| Método | " + " | ".join(f"s{s}" for s in semillas) + " |")
        p("|---|" + "---:|" * len(semillas))
        for m in METHODS:
            p(f"| {TITLE[m]} | " + " | ".join(" / ".join(metricas[(s, m)][3]) for s in semillas) + " |")
        p()

        auc = {}
        for s in semillas:
            for fila in leer_csv(f"{carpeta(nivel, s)}/resultados_umbral.csv"):
                if fila[0].startswith("auc_"):
                    auc[(s, fila[0])] = numero(fila[1])
        p("**AUC-ROC del bosque**")
        p()
        p("| Clave | " + " | ".join(f"s{s}" for s in semillas) + " | Promedio [rango] |")
        p("|---|" + "---:|" * (len(semillas) + 1))
        for k, t in [("auc_tenant", "tenant"), ("auc_ip", "ip")]:
            vals = [auc.get((s, k)) for s in semillas]
            p(f"| {t} | " + " | ".join(fmt(v) for v in vals) + f" | {estadisticas(vals)} |")
        p()

        det = {}
        for s in semillas:
            for fila in leer_csv(f"{carpeta(nivel, s)}/resultados_escenarios.csv")[1:]:
                det[(s, fila[1], fila[0], fila[2])] = (int(fila[4]), int(fila[3]))
        for tipo, rotulo in [("incidente", "incidentes"), ("ventana", "ventanas")]:
            p(f"**Detección por escenario ({rotulo}): tasa promedio [rango entre semillas]**")
            p()
            p("| Escenario | Total por semilla | " + " | ".join(TITLE[m] for m in METHODS) + " |")
            p("|---|---|" + "---:|" * len(METHODS))
            for sc in SCEN:
                totales = [det[(s, tipo, sc, "reglas")][1] for s in semillas]
                celdas = []
                for m in METHODS:
                    tasas = [det[(s, tipo, sc, m)][0] / det[(s, tipo, sc, m)][1] if det[(s, tipo, sc, m)][1] else None for s in semillas]
                    celdas.append(estadisticas(tasas))
                p(f"| {STITLE[sc]} | {'/'.join(str(t) for t in totales)} | " + " | ".join(celdas) + " |")
            p()

        # --- tiempo de detección
        if not tiene_tiempos(nivel, semillas):
            p("_Tiempo de detección: faltan los resultados_tiempos.csv de alguna semilla; vuelve a correr cmd/evaluate._")
            p()
            continue
        tiempos = {}  # (semilla, escenario, método) -> fila
        for s in semillas:
            for fila in leer_csv(f"{carpeta(nivel, s)}/resultados_tiempos.csv")[1:]:
                tiempos[(s, fila[0], fila[1])] = fila
        intervalo = leer_csv(f"{carpeta(nivel, semillas[0])}/resultados_tiempos.csv")[1][11]
        p(f"**Tiempo de detección** (intervalo de la tarea: {intervalo} min). Retraso en ventanas de 10 min entre la primera ventana atacada y la primera en que el método alertó; "
          "el peor caso en minutos es el fin de la ventana detectada + el intervalo − el inicio del ataque. "
          "Promedio [rango entre semillas] de cada estadística por semilla; las semillas en que el método no detectó nada no entran. "
          "Solo se muestran los métodos que detectaron algo.")
        p()
        p("| Escenario | Método | Incidentes (suma) | Sin detectar (suma) | Retraso promedio (ventanas) | Retraso mediana | Retraso máximo (máx. entre semillas) | Peor caso promedio (min) | Peor caso máximo (máx. entre semillas) |")
        p("|---|---|---:|---:|---:|---:|---:|---:|---:|")
        for sc in SCEN + ["todos"]:
            for m in METHODS:
                filas = [tiempos[(s, sc, m)] for s in semillas]
                if sum(int(f[3]) for f in filas) == 0:
                    continue
                total = sum(int(f[2]) for f in filas)
                sin = sum(int(f[4]) for f in filas)
                prom = [numero(f[5]) for f in filas]
                med = [numero(f[6]) for f in filas]
                maxi = [numero(f[7]) for f in filas if f[7] != ""]
                peor = [numero(f[8]) for f in filas]
                peor_max = [numero(f[10]) for f in filas if f[10] != ""]
                p(f"| {STITLE[sc]} | {TITLE[m]} | {total} | {sin} | {estadisticas(prom, 2)} | {estadisticas(med, 1)} | "
                  f"{fmt(max(maxi), 0)} | {estadisticas(peor, 1)} | {fmt(max(peor_max), 1)} |")
        p()

    texto = "\n".join(out)
    destino = os.path.join(ROOT, "experimento_resumen")
    os.makedirs(destino, exist_ok=True)
    with open(os.path.join(destino, "resumen.md"), "w", encoding="utf-8", newline="\n") as f:
        f.write(texto)
    sys.stdout.reconfigure(encoding="utf-8")
    print(texto)


if __name__ == "__main__":
    main()
