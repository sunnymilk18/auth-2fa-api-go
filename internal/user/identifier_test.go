package user

import "testing"

func TestClassifyIdentifier(t *testing.T) {
	cases := map[string]identifierKind{
		"user@example.com": identifierEmail,
		"a@b.co":           identifierEmail,
		"12.345.678-5":     identifierRUT,
		"12345678-5":       identifierRUT,
		"123456785":        identifierRUT,
		"12345678-K":       identifierRUT,
		"juan.perez":       identifierUsername,
		"juan.perez2":      identifierUsername,
		"":                 identifierUsername,
		"short":            identifierUsername,
	}
	for in, want := range cases {
		if got := classifyIdentifier(in); got != want {
			t.Errorf("classifyIdentifier(%q) = %v, want %v", in, got, want)
		}
	}
}

func TestValidateUsername(t *testing.T) {
	valid := []string{
		"juan.perez",                       // 10 chars, has letters
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
		"micorreo@example.com",              // has "@" — classifyIdentifier would always route this to email lookup
		"1234.5678",                         // digits + a dot — looksLikeRUT strips the dot and still sees a RUT shape
		"12.345.678-5",                      // fully RUT-formatted, even though it "has non-digit characters"
	}
	for _, u := range invalid {
		if ValidateUsername(u) {
			t.Errorf("ValidateUsername(%q) = true, want false", u)
		}
	}
}
