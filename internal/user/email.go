package user

import "strings"

// ValidateEmail is a lightweight shape check — not full RFC 5322, just
// enough to catch the case that actually matters here: a value with no "@"
// at all still passed Register before this existed (only emptiness was
// checked), and got stored as-is. Login itself would still find that row
// today (findByIdentifier tries all three columns unconditionally, not
// just the one a "@" would suggest), but the account would never actually
// receive a verification code or an OTP — Register's whole point of
// emailing one requires something that at least looks like a deliverable
// address. This never rejects anything genuinely on the stricter end of
// "looks like an email"; it only catches shapes that couldn't possibly
// receive mail.
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
