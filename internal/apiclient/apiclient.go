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

	// SystemAdminKeyHash is nil until an operator provisions a scoped
	// admin credential for this client (see Service.RotateSystemAdminKey)
	// — most clients never get one. Distinct from APIKeyHash: that one
	// authenticates the tenant's regular users at /auth/*, this one
	// authenticates the tenant's own operators at /system-admin/*, scoped
	// to only ever act on this client's own users.
	SystemAdminKeyHash     *string
	SystemAdminKeyLastUsed *time.Time
}
