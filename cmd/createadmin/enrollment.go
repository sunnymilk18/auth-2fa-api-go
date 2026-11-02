package main

import (
	"fmt"
	"io"
	"net/url"
	"os"
	"strings"

	"github.com/boombuler/barcode/qr"
)

// quietZone es el margen blanco, en módulos, alrededor del código QR. La
// especificación pide 4; un margen menor suele funcionar, pero algunas
// cámaras fallan sin él.
const quietZone = 4

// printEnrollment muestra cómo registrar la cuenta en una app autenticadora:
// el código QR (solo si la salida es una terminal) y la clave en texto,
// en grupos de 4 caracteres para poder copiarla o teclearla sin errores.
// Es la única vez que se muestran: la clave no se guarda en claro.
func printEnrollment(w io.Writer, otpauthURL string) error {
	secret, err := secretFromURL(otpauthURL)
	if err != nil {
		return err
	}

	fmt.Fprintln(w, "Registro en la app autenticadora (se muestra una sola vez):")
	fmt.Fprintln(w)

	if isTerminal(os.Stdout) {
		compact, err := compactURL(otpauthURL)
		if err != nil {
			return err
		}
		if err := renderQR(w, compact); err != nil {
			return fmt.Errorf("dibujando el código QR: %w", err)
		}
		fmt.Fprintln(w)
		fmt.Fprintln(w, "Escanea el código QR con la app, o ingresa esta clave manualmente")
	} else {
		fmt.Fprintln(w, "Ingresa esta clave manualmente en la app")
	}
	fmt.Fprintln(w, "(tipo de clave: basada en tiempo; los espacios son opcionales):")
	fmt.Fprintln(w)
	fmt.Fprintf(w, "  %s\n", groupSecret(secret))
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Dirección completa, por si la app la acepta pegada:")
	fmt.Fprintf(w, "  %s\n", otpauthURL)
	return nil
}

// secretFromURL extrae el parámetro secret de una dirección otpauth://.
func secretFromURL(otpauthURL string) (string, error) {
	u, err := url.Parse(otpauthURL)
	if err != nil {
		return "", fmt.Errorf("leyendo la dirección otpauth: %w", err)
	}
	secret := u.Query().Get("secret")
	if secret == "" {
		return "", fmt.Errorf("la dirección otpauth no trae el parámetro secret")
	}
	return secret, nil
}

// compactURL deja en la dirección otpauth solo la cuenta, el emisor y la
// clave, y quita algorithm, digits y period. Esos tres traen los valores por
// defecto que asumen las apps autenticadoras (SHA1, 6 dígitos, 30 segundos),
// y sacarlos achica el QR para que quepa en una terminal de pocas líneas.
func compactURL(otpauthURL string) (string, error) {
	u, err := url.Parse(otpauthURL)
	if err != nil {
		return "", fmt.Errorf("leyendo la dirección otpauth: %w", err)
	}
	q := url.Values{}
	q.Set("secret", u.Query().Get("secret"))
	if issuer := u.Query().Get("issuer"); issuer != "" {
		q.Set("issuer", issuer)
	}
	u.RawQuery = q.Encode()
	return u.String(), nil
}

// groupSecret separa la clave en bloques de 4 caracteres ("ABCD EFGH ...").
// Las apps autenticadoras ignoran los espacios; a una persona le sirven para
// no perder el lugar al copiar o teclear.
func groupSecret(secret string) string {
	var b strings.Builder
	for i, r := range secret {
		if i > 0 && i%4 == 0 {
			b.WriteByte(' ')
		}
		b.WriteRune(r)
	}
	return b.String()
}

// isTerminal indica si f es una terminal interactiva. Con la salida
// redirigida a un archivo o a otro comando, los códigos de color del QR
// quedarían como texto basura.
func isTerminal(f *os.File) bool {
	info, err := f.Stat()
	if err != nil {
		return false
	}
	return info.Mode()&os.ModeCharDevice != 0
}

// renderQR dibuja content como código QR en la terminal usando medios
// bloques (▀), dos filas de módulos por línea de texto. Fija explícitamente
// negro sobre blanco con colores ANSI en vez de depender del tema de la
// terminal: un QR con los colores invertidos no lo leen todas las cámaras.
func renderQR(w io.Writer, content string) error {
	// Nivel L (corrección de errores baja): un QR en pantalla no se ensucia
	// ni se daña como uno impreso, y así el código sale más chico.
	code, err := qr.Encode(content, qr.L, qr.Auto)
	if err != nil {
		return err
	}
	bounds := code.Bounds()
	size := bounds.Dx()

	// dark dice si el módulo (x, y) es oscuro; fuera del código es margen blanco.
	dark := func(x, y int) bool {
		if x < 0 || y < 0 || x >= size || y >= size {
			return false
		}
		r, _, _, _ := code.At(bounds.Min.X+x, bounds.Min.Y+y).RGBA()
		return r < 0x8000
	}
	// fg y bg devuelven el código ANSI de primer plano (30 negro, 97 blanco)
	// o de fondo (40 negro, 107 blanco) según el módulo sea oscuro o no.
	fg := func(isDark bool) int {
		if isDark {
			return 30
		}
		return 97
	}
	bg := func(isDark bool) int {
		if isDark {
			return 40
		}
		return 107
	}

	for y := -quietZone; y < size+quietZone; y += 2 {
		var line strings.Builder
		for x := -quietZone; x < size+quietZone; x++ {
			// ▀ pinta la mitad de arriba con el color de primer plano y la
			// de abajo con el de fondo.
			fmt.Fprintf(&line, "\x1b[%d;%dm▀", fg(dark(x, y)), bg(dark(x, y+1)))
		}
		line.WriteString("\x1b[0m")
		fmt.Fprintf(w, "  %s\n", line.String())
	}
	return nil
}
