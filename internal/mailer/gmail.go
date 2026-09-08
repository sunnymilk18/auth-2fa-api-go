package mailer

import (
	"context"
	"fmt"
	"net/smtp"
)

// GmailMailer sends mail through Gmail's SMTP server using an App Password.
// Intended for development/testing only — see README for production notes.
type GmailMailer struct {
	host     string
	port     int
	username string
	password string
	from     string
}

func NewGmailMailer(host string, port int, username, password, from string) *GmailMailer {
	return &GmailMailer{
		host:     host,
		port:     port,
		username: username,
		password: password,
		from:     from,
	}
}

func (m *GmailMailer) Send(ctx context.Context, to, subject, body string) error {
	addr := fmt.Sprintf("%s:%d", m.host, m.port)
	auth := smtp.PlainAuth("", m.username, m.password, m.host)

	msg := []byte(
		"From: " + m.from + "\r\n" +
			"To: " + to + "\r\n" +
			"Subject: " + subject + "\r\n" +
			"MIME-Version: 1.0\r\n" +
			"Content-Type: text/plain; charset=\"UTF-8\"\r\n" +
			"\r\n" +
			body + "\r\n",
	)

	errCh := make(chan error, 1)
	go func() {
		errCh <- smtp.SendMail(addr, auth, m.from, []string{to}, msg)
	}()

	select {
	case <-ctx.Done():
		return ctx.Err()
	case err := <-errCh:
		if err != nil {
			return fmt.Errorf("sending email via gmail smtp: %w", err)
		}
		return nil
	}
}
