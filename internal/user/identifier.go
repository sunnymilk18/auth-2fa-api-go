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
// at least one non-digit character, and no "@". Neither rule is arbitrary —
// both keep classifyIdentifier's shape detection unambiguous, since it
// checks "@" first and RUT-shape second: a purely numeric 7-9 digit
// username would be indistinguishable from a RUT (see looksLikeRUT's doc
// comment), and a username containing "@" would always be misrouted to an
// email lookup instead, no matter what it actually is — either way, that
// username becomes silently unreachable at login for the person who chose
// it, which is exactly what this function exists to rule out up front.
func ValidateUsername(username string) bool {
	if len(username) < 8 || len(username) > 32 {
		return false
	}
	if strings.Contains(username, "@") {
		return false
	}
	for _, r := range username {
		if r < '0' || r > '9' {
			return true
		}
	}
	return false
}
