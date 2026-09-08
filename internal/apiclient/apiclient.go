package apiclient

import "time"

// APIClient identifies a system authorized to call this API (a "tenant").
// Each APIClient has its own isolated set of users.
type APIClient struct {
	ID         string
	Name       string
	APIKeyHash string
	Active     bool
	CreatedAt  time.Time
	UpdatedAt  time.Time
}
