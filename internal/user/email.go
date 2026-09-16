package user

import "strings"

// ValidateEmail is a lightweight shape check — not full RFC 5322, just
// enough to catch the case that actually matters here: a value with no "@"
// at all still passed Register before this existed (only emptiness was
// checked), got stored as-is, and became permanently unreachable as a
// login identifier — classifyIdentifier only ever tries the email lookup
// when the identifier contains "@", so a malformed stored email could
// never match itself back. This never rejects anything genuinely on the
// stricter end of "looks like an email"; it only catches the shapes that
// would break that round-trip.
func ValidateEmail(email string) bool {
	if strings.Count(email, "@") != 1 {
		return false
	}
	at := strings.IndexByte(email, '@')
	local, domain := email[:at], email[at+1:]
	if local == "" || domain == "" {
		return false
	}
	if !strings.Contains(domain, ".") {
		return false
	}
	if strings.ContainsAny(email, " \t\n") {
		return false
	}
	return true
}
