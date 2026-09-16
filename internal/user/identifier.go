package user

import "strings"

type identifierKind int

const (
	identifierUsername identifierKind = iota
	identifierEmail
	identifierRUT
)

// classifyIdentifier decides how a login identifier should be looked up.
func classifyIdentifier(identifier string) identifierKind {
	if strings.Contains(identifier, "@") {
		return identifierEmail
	}
	if looksLikeRUT(identifier) {
		return identifierRUT
	}
	return identifierUsername
}

// looksLikeRUT reports whether identifier, once RUT-typical separators
// (dots, dashes, spaces) are stripped, is entirely digits with at most a
// trailing check character (digit or K) — "12.345.678-5", "12345678-5" and
// "123456785" all match. Deliberately stricter than NormalizeRUT (which
// just extracts digits from anywhere in the string): any OTHER character —
// a letter, for instance — rules a RUT shape out entirely, rather than
// silently being dropped. Without that, a username that merely contains a
// run of 7-9 digits somewhere in it (not unusual — e.g. one built from a
// random hex suffix) would get misclassified as a RUT and fail to find its
// account. This check is on shape only, not the checksum — see
// classifyIdentifier's callers: a RUT-shaped string with a wrong check
// digit simply won't match any row, exactly like a wrong password would.
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
// no "@", and — critically — nothing classifyIdentifier's own RUT-shape
// check (looksLikeRUT) would accept. That's deliberately delegated to
// looksLikeRUT itself rather than reimplemented here (an earlier version
// of this function only rejected *purely numeric* usernames, which missed
// digits-plus-separators like "1234.5678": no letters, so it passed this
// check, but looksLikeRUT still strips the dot and sees a bare 8-digit
// RUT shape underneath — exactly the ambiguity this function exists to
// rule out). Calling looksLikeRUT directly means the two can't drift apart
// again: whatever classifyIdentifier would call a RUT, this rejects as a
// username, by construction. Same reasoning for "@" and email.
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
	return true
}
