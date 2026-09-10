package user

import "time"

// User represents a persisted account. Password is only ever stored/handled
// as a bcrypt hash — never in plain text. Email is unique per APIClientID,
// not globally — the same email can be a different account under a
// different consuming system.
type User struct {
	ID            string
	APIClientID   string
	Email         string
	PasswordHash  string
	IsActive      bool
	EmailVerified bool
	CreatedAt     time.Time
	UpdatedAt     time.Time
}
