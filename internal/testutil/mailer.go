package testutil

import (
	"context"
	"regexp"
	"sync"
)

// SentEmail is one message captured by FakeMailer.
type SentEmail struct {
	To      string
	Subject string
	Body    string
}

// FakeMailer implements mailer.Mailer by recording every send instead of
// talking to a real SMTP server — lets tests assert on what would have been
// emailed (e.g. pull the OTP code out of the body) without any network I/O.
type FakeMailer struct {
	mu   sync.Mutex
	sent []SentEmail
}

func NewFakeMailer() *FakeMailer {
	return &FakeMailer{}
}

func (m *FakeMailer) Send(_ context.Context, to, subject, body string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.sent = append(m.sent, SentEmail{To: to, Subject: subject, Body: body})
	return nil
}

// Sent returns every email captured so far, in order.
func (m *FakeMailer) Sent() []SentEmail {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]SentEmail, len(m.sent))
	copy(out, m.sent)
	return out
}

// Last returns the most recently sent email, or false if none was sent.
func (m *FakeMailer) Last() (SentEmail, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.sent) == 0 {
		return SentEmail{}, false
	}
	return m.sent[len(m.sent)-1], true
}

var otpCodePattern = regexp.MustCompile(`\d{4,10}`)

// ExtractOTPCode pulls the numeric code out of an OTP email body, so tests
// can complete the login flow without ever seeing the code returned
// directly by the API (it never is — that's the point of 2FA).
func ExtractOTPCode(body string) string {
	return otpCodePattern.FindString(body)
}

// ExtractResetCode pulls the numeric password-reset code out of its email
// body — same shape and same regex as ExtractOTPCode, since password reset
// now uses a short numeric code too, not an opaque token.
func ExtractResetCode(body string) string {
	return otpCodePattern.FindString(body)
}

// ExtractVerificationCode pulls the numeric email-verification code out of
// its email body — same shape and same regex as ExtractOTPCode/ExtractResetCode.
func ExtractVerificationCode(body string) string {
	return otpCodePattern.FindString(body)
}
