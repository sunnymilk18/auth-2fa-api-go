package user

import "strings"

// looksLikeRUT reports whether identifier, once RUT-typical separators
// (dots, dashes, spaces) are stripped, is entirely digits with at most a
// trailing check character (digit or K) — "12.345.678-5", "12345678-5" and
// "123456785" all match. Deliberately stricter than NormalizeRUT (which
// just extracts digits from anywhere in the string): any OTHER character —
// a letter, for instance — rules a RUT shape out entirely, rather than
// silently being dropped. This check is on shape only, not the checksum —
// see ValidateUsername's callers: a RUT-shaped string with a wrong check
// digit simply won't match any row, exactly like a wrong password would.
//
// Used by ValidateUsername to keep registration from ever accepting a
// username that could collide, across columns, with someone else's rut —
// findByIdentifier's single OR-query lookup (email = ? OR username = ? OR
// rut = ?) depends on that being impossible to stay unambiguous.
func looksLikeRUT(identifier string) bool {
	var digits strings.Builder
	for _, r := range identifier {
		switch {
		case r == '.' || r == '-' || r == ' ':
			continue
		case r >= '0' && r <= '9':
			digits.WriteRune(r)
		case r == 'k' || r == 'K':
			digits.WriteRune('K')
		default:
			return false
		}
	}

	s := digits.String()
	if len(s) < 7 || len(s) > 9 {
		return false
	}
	body, check := s[:len(s)-1], s[len(s)-1]
	for _, r := range body {
		if r < '0' || r > '9' {
			return false
		}
	}
	return (check >= '0' && check <= '9') || check == 'K'
}

// NormalizeUsername trims and lowercases — the only form ever stored or
// looked up, same reasoning as normalizeEmail.
func NormalizeUsername(username string) string {
	return strings.ToLower(strings.TrimSpace(username))
}

// ValidateUsername enforces 8-32 characters (checked after
// NormalizeUsername, so surrounding whitespace doesn't count either way),
// no "@", nothing looksLikeRUT would accept, and at least one letter. The
// first three rules keep findByIdentifier's single OR-query lookup
// (email = ? OR username = ? OR rut = ?) unambiguous: without them, one
// person's username could collide with a stranger's real email or rut, and
// the query could resolve to the wrong account entirely. Delegating to
// looksLikeRUT directly (rather than reimplementing "looks numeric" here)
// is deliberate too — an earlier version of this function only rejected
// *purely numeric* usernames, which missed digits-plus-separators like
// "1234.5678": no letters, so it passed, but looksLikeRUT still strips the
// dot and sees a bare 8-digit RUT shape underneath. Calling it directly
// means the two can't drift apart again.
//
// The letter requirement is different in kind from the other three — it's
// not needed to keep the OR-query unambiguous (looksLikeRUT already rules
// out every string that could pass for a rut), it's just a quality bar: a
// username that's nothing but digits reads like a phone number or an
// account number, not a name someone chose. Deliberately not requiring a
// digit too — a plain name like "juanperez" is a perfectly good username,
// and there's no ambiguity risk being closed by forcing one in.
func ValidateUsername(username string) bool {
	if len(username) < 8 || len(username) > maxUsernameLen {
		return false
	}
	if strings.Contains(username, "@") {
		return false
	}
	if looksLikeRUT(username) {
		return false
	}
	if !hasLetter(username) {
		return false
	}
	return true
}

func hasLetter(s string) bool {
	for _, r := range s {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') {
			return true
		}
	}
	return false
}
