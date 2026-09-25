package user

import "testing"

func TestLooksLikeRUT(t *testing.T) {
	rutShaped := []string{
		"12.345.678-5",
		"12345678-5",
		"123456785",
		"12345678-K",
	}
	for _, s := range rutShaped {
		if !looksLikeRUT(s) {
			t.Errorf("looksLikeRUT(%q) = false, want true", s)
		}
	}

	notRUTShaped := []string{
		"user@example.com",
		"a@b.co",
		"juan.perez",
		"juan.perez2",
		"",
		"short",
	}
	for _, s := range notRUTShaped {
		if looksLikeRUT(s) {
			t.Errorf("looksLikeRUT(%q) = true, want false", s)
		}
	}
}

func TestValidateUsername(t *testing.T) {
	valid := []string{
		"juan.perez",                       // 10 chars, has letters
		"juanperez",                        // pure letters, no digits at all — the letter rule doesn't also require a digit
		"user1234",                         // exactly 8, mixed
		"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", // exactly 32
	}
	for _, u := range valid {
		if !ValidateUsername(u) {
			t.Errorf("ValidateUsername(%q) = false, want true", u)
		}
	}

	invalid := []string{
		"short",                             // < 8 chars
		"12345678",                          // 8 digits, purely numeric — the case this rule exists to rule out
		"123456785",                         // 9 digits, purely numeric (RUT-shaped even)
		"",                                  // empty
		"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", // 33 chars, over the max
		"micorreo@example.com",              // has "@" — would always match the email column instead
		"1234.5678",                         // digits + a dot — looksLikeRUT strips the dot and still sees a RUT shape
		"12.345.678-5",                      // fully RUT-formatted, even though it "has non-digit characters"
		"123456789012",                      // 12 digits, no letters — NOT rut-shaped (too long for a rut), but still purely numeric, which the letter requirement rules out on its own
	}
	for _, u := range invalid {
		if ValidateUsername(u) {
			t.Errorf("ValidateUsername(%q) = true, want false", u)
		}
	}
}
