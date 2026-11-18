package detector

import (
	"fmt"
	"strconv"
)

// Rules son los umbrales fijos de la línea base. Una ventana dispara la regla
// cuando alguna característica los alcanza o supera (>=). Configurables por
// variables de entorno, ver LoadConfig.
type Rules struct {
	Fallos       int
	Cuentas      int
	IPsConFallos int
	Inexistentes int
}

// DefaultRules son valores razonables para una plataforma de tamaño modesto:
// en 10 minutos, 20 fallos o 10 cuentas distintas atacadas ya no se parece a
// olvidar la contraseña. No están calibrados contra ningún conjunto de datos.
func DefaultRules() Rules {
	return Rules{Fallos: 20, Cuentas: 10, IPsConFallos: 10, Inexistentes: 10}
}

// Evaluate devuelve un motivo legible por cada umbral alcanzado — vacío si la
// ventana no dispara ninguna regla. Un umbral en 0 o menos desactiva esa regla.
func (r Rules) Evaluate(f Features) []string {
	var motives []string
	if r.Fallos > 0 && f.Fallos >= r.Fallos {
		motives = append(motives, fmt.Sprintf("%s en %s (umbral de la regla: %d)", countText(f.Fallos, "fallo", "fallos"), windowLabel, r.Fallos))
	}
	if r.Cuentas > 0 && f.CuentasDistintasAtacadas >= r.Cuentas {
		motives = append(motives, fmt.Sprintf("%s en %s (umbral de la regla: %d)", countText(f.CuentasDistintasAtacadas, "cuenta distinta atacada", "cuentas distintas atacadas"), windowLabel, r.Cuentas))
	}
	if r.IPsConFallos > 0 && f.IPsDistintasConFallos >= r.IPsConFallos {
		motives = append(motives, fmt.Sprintf("%s en %s (umbral de la regla: %d)", countText(f.IPsDistintasConFallos, "IP distinta con fallos", "IPs distintas con fallos"), windowLabel, r.IPsConFallos))
	}
	if r.Inexistentes > 0 && f.IntentosCuentaInexistente >= r.Inexistentes {
		motives = append(motives, fmt.Sprintf("%s en %s (umbral de la regla: %d)", countText(f.IntentosCuentaInexistente, "intento contra una cuenta inexistente", "intentos contra cuentas inexistentes"), windowLabel, r.Inexistentes))
	}
	return motives
}

// DecoyMotives es la regla de los señuelos: cualquier intento contra una
// cuenta señuelo genera alerta, sin umbral.
func DecoyMotives(f Features) []string {
	if f.IntentosContraSenuelos < 1 {
		return nil
	}
	return []string{fmt.Sprintf("%s en %s", countText(f.IntentosContraSenuelos, "intento contra una cuenta señuelo", "intentos contra cuentas señuelo"), windowLabel)}
}

// windowLabel es cómo se nombra la ventana en los textos.
var windowLabel = strconv.Itoa(int(WindowSize.Minutes())) + " min"

// countText arma "1 fallo" / "42 fallos".
func countText(n int, singular, plural string) string {
	if n == 1 {
		return "1 " + singular
	}
	return strconv.Itoa(n) + " " + plural
}
