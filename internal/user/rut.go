package user

import "strings"

// NormalizeRUT strips everything but digits and the trailing check
// character (dots, dashes, spaces — however someone typed it: "12.345.678-5",
// "12345678-5", "123456785" all collapse to the same "123456785"), and
// uppercases a 'k' check digit. This is the only form ever stored or looked
// up — registration and login both call it, so "12.345.678-5" at register
// time and "123456785" at login time resolve to the same row.
func NormalizeRUT(raw string) string {
	var b strings.Builder
	for _, r := range raw {
		switch {
		case r >= '0' && r <= '9':
			b.WriteRune(r)
		case r == 'k' || r == 'K':
			b.WriteRune('K')
		}
	}
	return b.String()
}

// ValidateRUT checks a normalized RUT (see NormalizeRUT) against Chile's
// módulo 11 check digit — catches typos (transposed digits, a wrong check
// character) the way a plain "is this shaped like a RUT" regex wouldn't.
// Body length 6-8 digits covers the real range of issued RUTs; anything
// outside that, or a check digit that doesn't match, is rejected.
func ValidateRUT(normalized string) bool {
	if len(normalized) < 7 || len(normalized) > 9 {
		return false
	}
	body := normalized[:len(normalized)-1]
	check := normalized[len(normalized)-1]
	if len(body) < 6 || len(body) > 8 {
		return false
	}
	for _, r := range body {
		if r < '0' || r > '9' {
			return false
		}
	}
	return checkDigit(body) == check
}

// NewRUT builds a normalized, checksum-valid RUT from a body (6-8 digits) —
// exported mainly so tests can generate a fresh valid RUT per case without
// duplicating the checksum algorithm themselves.
func NewRUT(body string) string {
	return body + string(checkDigit(body))
}

// checkDigit computes Chile's módulo 11 check digit for a RUT body (the
// digits before the dash). Weights cycle 2,3,4,5,6,7 from the rightmost
// digit; a result of 11 maps to '0', a result of 10 maps to 'K'.
func checkDigit(body string) byte {
	weights := [6]int{2, 3, 4, 5, 6, 7}
	sum := 0
	for i := 0; i < len(body); i++ {
		d := int(body[len(body)-1-i] - '0')
		sum += d * weights[i%6]
	}
	switch rem := 11 - (sum % 11); rem {
	case 11:
		return '0'
	case 10:
		return 'K'
	default:
		return byte('0' + rem)
	}
}
