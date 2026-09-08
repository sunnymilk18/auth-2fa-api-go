package mailer

import "context"

// Mailer is the abstraction the rest of the app depends on. Swapping the
// email provider later (SendGrid, SES, Mailgun, ...) only means writing a
// new implementation of this interface — nothing else changes.
type Mailer interface {
	Send(ctx context.Context, to, subject, body string) error
}
