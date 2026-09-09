package mailer

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

// ResendMailer sends mail through Resend's (https://resend.com) HTTPS API.
// Unlike GmailMailer (raw SMTP), this is just an HTTPS POST — several PaaS
// providers block or filter outbound SMTP ports by default to prevent
// spam, which makes SMTP-based mailers unreliable once deployed there
// (this project hit exactly that on Render: the OTP email would hang the
// whole request indefinitely). An HTTP API has no such problem.
type ResendMailer struct {
	apiKey string
	from   string
	client *http.Client
}

func NewResendMailer(apiKey, from string) *ResendMailer {
	return &ResendMailer{apiKey: apiKey, from: from, client: &http.Client{Timeout: 10 * time.Second}}
}

type resendSendRequest struct {
	From    string   `json:"from"`
	To      []string `json:"to"`
	Subject string   `json:"subject"`
	Text    string   `json:"text"`
}

func (m *ResendMailer) Send(ctx context.Context, to, subject, body string) error {
	payload, err := json.Marshal(resendSendRequest{From: m.from, To: []string{to}, Subject: subject, Text: body})
	if err != nil {
		return fmt.Errorf("marshaling resend request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://api.resend.com/emails", bytes.NewReader(payload))
	if err != nil {
		return fmt.Errorf("building resend request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+m.apiKey)
	req.Header.Set("Content-Type", "application/json")

	res, err := m.client.Do(req)
	if err != nil {
		return fmt.Errorf("sending via resend: %w", err)
	}
	defer res.Body.Close()

	if res.StatusCode >= 300 {
		var errBody struct {
			Message string `json:"message"`
		}
		_ = json.NewDecoder(res.Body).Decode(&errBody)
		if errBody.Message != "" {
			return fmt.Errorf("resend error (%d): %s", res.StatusCode, errBody.Message)
		}
		return fmt.Errorf("resend error: status %d", res.StatusCode)
	}
	return nil
}
