package user

import "testing"

func TestNormalizeRUT(t *testing.T) {
	cases := map[string]string{
		"12.345.678-5":   "123456785",
		"12345678-5":     "123456785",
		"123456785":      "123456785",
		"  12.345.678-5": "123456785",
		"12.345.678-k":   "12345678K",
		"12.345.678-K":   "12345678K",
	}
	for in, want := range cases {
		if got := NormalizeRUT(in); got != want {
			t.Errorf("NormalizeRUT(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestValidateRUT(t *testing.T) {
	// "123456785" is a commonly-cited real-shaped example (check digit
	// verified by hand against the módulo 11 algorithm); NewRUT(...)
	// generates the other so this doesn't depend on hand-computing a second
	// check digit correctly.
	valid := []string{"123456785", NewRUT("7654321")}
	for _, rut := range valid {
		if !ValidateRUT(rut) {
			t.Errorf("ValidateRUT(%q) = false, want true", rut)
		}
	}

	invalid := []string{
		"123456780", // wrong check digit (should be 5)
		"1234567",   // no check digit, body-only
		"1234A6785", // non-digit in the body
		"",
		"5",
	}
	for _, rut := range invalid {
		if ValidateRUT(rut) {
			t.Errorf("ValidateRUT(%q) = true, want false", rut)
		}
	}
}

func TestNewRUT_RoundTripsThroughValidateRUT(t *testing.T) {
	for _, body := range []string{"123456", "12345678", "1234567"} {
		rut := NewRUT(body)
		if !ValidateRUT(rut) {
			t.Errorf("NewRUT(%q) = %q, but ValidateRUT rejects it", body, rut)
		}
	}
}
