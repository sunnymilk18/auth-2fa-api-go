// Command createadmin bootstraps the very first admin account for the
// operator panel (internal/adminauth) — the panel itself needs an
// already-authenticated admin to create another one (see
// httpserver.adminAuthHandlers.CreateAccount), so the first account always
// has to come from here, connecting straight to Postgres the same way
// cmd/createclient does for api_clients.
package main

import (
	"context"
	"encoding/base64"
	"flag"
	"fmt"
	"log"
	"os"

	"auth-2fa-api/internal/adminauth"
	"auth-2fa-api/internal/auth"
	"auth-2fa-api/internal/config"
	"auth-2fa-api/internal/db"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(1)
	}

	var err error
	switch os.Args[1] {
	case "create":
		err = runCreate(os.Args[2:])
	default:
		usage()
		os.Exit(1)
	}
	if err != nil {
		log.Fatalf("fatal: %v", err)
	}
}

func usage() {
	fmt.Println(`Usage:
  createadmin create -email <email> -password <password> [-role admin|superadmin]
      Provision a new admin account, printing its TOTP enrollment QR URL once.
      -role defaults to superadmin — the very first account has to be one
      (only a superadmin can create further accounts from the panel), and
      this CLI is also the "break glass" path for an emergency account, so
      defaulting to the more capable role is the safer assumption here.`)
}

func runCreate(args []string) error {
	fs := flag.NewFlagSet("create", flag.ExitOnError)
	email := fs.String("email", "", "the new admin's email")
	password := fs.String("password", "", "the new admin's password (at least 8 characters)")
	role := fs.String("role", string(adminauth.RoleSuperAdmin), `"admin" or "superadmin"`)
	_ = fs.Parse(args)
	if *email == "" || len(*password) < 8 {
		return fmt.Errorf("-email is required and -password must be at least 8 characters")
	}
	if !adminauth.Role(*role).Valid() {
		return fmt.Errorf(`-role must be "admin" or "superadmin", got %q`, *role)
	}

	cfg, err := config.Load()
	if err != nil {
		return err
	}
	if cfg.TOTPEncryptionKeyBase64 == "" {
		return fmt.Errorf("TOTP_ENCRYPTION_KEY must be configured — admin accounts require TOTP, it's not optional here")
	}
	key, err := base64.StdEncoding.DecodeString(cfg.TOTPEncryptionKeyBase64)
	if err != nil {
		return fmt.Errorf("decoding TOTP_ENCRYPTION_KEY: %w", err)
	}
	totpManager, err := auth.NewTOTPManager(cfg.TOTPIssuer, key)
	if err != nil {
		return err
	}

	ctx := context.Background()
	pool, err := db.NewPostgres(ctx, cfg.PostgresDSN)
	if err != nil {
		return err
	}
	defer pool.Close()

	svc := adminauth.NewService(
		adminauth.NewAccountRepository(pool),
		adminauth.NewSessionRepository(pool),
		nil, // no TOTP rotation store needed for account creation
		totpManager,
		nil, // no login-attempt limiter needed for account creation
		0,
	)

	account, otpauthURL, err := svc.CreateAccount(ctx, *email, *password, adminauth.Role(*role))
	if err != nil {
		return err
	}

	fmt.Println("Admin account created:")
	fmt.Printf("  id:    %s\n", account.ID)
	fmt.Printf("  email: %s\n", account.Email)
	fmt.Printf("  role:  %s\n", account.Role)
	fmt.Println()
	fmt.Println("TOTP enrollment (shown once — scan this into an authenticator app now):")
	fmt.Printf("  %s\n", otpauthURL)
	return nil
}
