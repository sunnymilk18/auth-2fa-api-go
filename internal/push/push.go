// Package push sends login-approval notifications via Firebase Cloud
// Messaging (Android only for now — see README's design notes). This is
// the one piece of the mechanism that actually leaves the server: creating
// the pending request and checking its answer are ordinary Redis-backed
// logic in the auth package, same shape as the existing OTP/TOTP login
// sessions.
package push

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	firebase "firebase.google.com/go/v4"
	"firebase.google.com/go/v4/messaging"
	"google.golang.org/api/option"
)

// Client wraps the Firebase Admin SDK's messaging client. Construct once at
// startup (see cmd/api/main.go's setupPush) and reuse — it's safe for
// concurrent use, same as an *http.Client.
type Client struct {
	fcm *messaging.Client
}

// NewClient authenticates against Firebase using a service account key's
// raw JSON contents (see README's "Configurar Firebase Cloud Messaging"
// section for how to generate one) and returns a ready-to-use Client.
// Takes the JSON directly, not a file path — see cmd/api/main.go's
// setupPush for why: this project supports both a file
// (FIREBASE_CREDENTIALS_PATH, for a host with a persistent filesystem) and
// a base64 env var (FIREBASE_CREDENTIALS_JSON_BASE64, for one without —
// same reasoning as JWT_PRIVATE_KEY_PEM_BASE64), and resolving that choice
// is main.go's job, not this package's.
//
// The project ID is read from the credentials and passed explicitly via
// firebase.Config — passing nil there (the more obvious-looking call)
// works in some environments only by accident: the Admin SDK's Messaging
// client doesn't parse the credentials for the project ID itself, it falls
// back to the GOOGLE_CLOUD_PROJECT/GCLOUD_PROJECT env vars, which happened
// to be set on one developer's machine (from an unrelated gcloud install)
// but not on a clean deploy target, where it failed with "project ID is
// required to access Firebase Cloud Messaging client" despite perfectly
// valid credentials. Reading it ourselves removes that hidden environment
// dependency entirely.
func NewClient(ctx context.Context, credentialsJSON []byte) (*Client, error) {
	var creds struct {
		ProjectID string `json:"project_id"`
	}
	if err := json.Unmarshal(credentialsJSON, &creds); err != nil {
		return nil, fmt.Errorf("parsing firebase credentials: %w", err)
	}
	if creds.ProjectID == "" {
		return nil, fmt.Errorf("firebase credentials have no project_id")
	}

	app, err := firebase.NewApp(ctx, &firebase.Config{ProjectID: creds.ProjectID}, option.WithCredentialsJSON(credentialsJSON))
	if err != nil {
		return nil, fmt.Errorf("initializing firebase app: %w", err)
	}
	fcm, err := app.Messaging(ctx)
	if err != nil {
		return nil, fmt.Errorf("getting messaging client: %w", err)
	}
	return &Client{fcm: fcm}, nil
}

// SendLoginApproval notifies deviceToken that requestID is waiting for a
// decision, carrying the three numbers (one correct, two decoys, already
// shuffled by the caller — see auth.Service.StartPushLogin) for the app to
// show as tap targets, plus expiresAt so the app can show a countdown
// instead of the request just going stale with no warning. The
// notification text alone is enough for a user to know something needs
// their attention even before opening the app; the data payload is what
// the app itself reads to render the actual approve screen with the right
// requestID, numbers and deadline.
//
// expiresAt is sent as an absolute Unix timestamp, not a "seconds
// remaining" duration — FCM delivery isn't instant, and a relative value
// would already be wrong by however long the message sat in transit before
// the app received it.
func (c *Client) SendLoginApproval(ctx context.Context, deviceToken, requestID string, numbers [3]int, expiresAt time.Time) error {
	strs := make([]string, len(numbers))
	for i, n := range numbers {
		strs[i] = fmt.Sprintf("%02d", n)
	}

	message := &messaging.Message{
		Token: deviceToken,
		Notification: &messaging.Notification{
			Title: "Aprobar inicio de sesión",
			Body:  "Alguien está intentando entrar a tu cuenta desde otro dispositivo.",
		},
		Data: map[string]string{
			"type":       "push_login_approval",
			"request_id": requestID,
			"numbers":    strings.Join(strs, ","),
			"expires_at": strconv.FormatInt(expiresAt.Unix(), 10),
		},
		Android: &messaging.AndroidConfig{
			// High priority wakes the device out of Doze/battery-saver
			// states — a login approval that arrives minutes late is
			// useless, the whole point is it beats a 60-second expiry.
			Priority: "high",
		},
	}

	if _, err := c.fcm.Send(ctx, message); err != nil {
		return fmt.Errorf("sending push login approval: %w", err)
	}
	return nil
}
