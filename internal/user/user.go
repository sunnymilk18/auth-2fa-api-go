package user

import "time"

// User represents a persisted account. Password is only ever stored/handled
// as a bcrypt hash — never in plain text. Email, Username and RUT are each
// unique per APIClientID, not globally — the same value in any of the
// three can be a different account under a different consuming system.
// Login accepts any of the three (see identifier.go) precisely because all
// three carry that same per-tenant uniqueness.
type User struct {
	ID            string
	APIClientID   string
	Email         string
	Username      string
	RUT           string
	PasswordHash  string
	IsActive      bool
	EmailVerified bool
	CreatedAt     time.Time
	UpdatedAt     time.Time
}
