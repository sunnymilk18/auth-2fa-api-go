// Command createclient provisions a new API client (tenant) and prints its
// plaintext API key exactly once — only its hash is ever stored, so if you
// lose the printed key you must create a new client.
package main

import (
	"context"
	"flag"
	"fmt"
	"log"

	"auth-2fa-api/internal/apiclient"
	"auth-2fa-api/internal/config"
	"auth-2fa-api/internal/db"
)

func main() {
	name := flag.String("name", "", "descriptive name for the consuming system (e.g. auth-2fa-app-flutter)")
	flag.Parse()

	if *name == "" {
		log.Fatal("fatal: -name is required")
	}

	if err := run(*name); err != nil {
		log.Fatalf("fatal: %v", err)
	}
}

func run(name string) error {
	cfg, err := config.Load()
	if err != nil {
		return err
	}

	ctx := context.Background()
	pool, err := db.NewPostgres(ctx, cfg.PostgresDSN)
	if err != nil {
		return err
	}
	defer pool.Close()

	repo := apiclient.NewRepository(pool)
	svc := apiclient.NewService(repo)

	client, key, err := svc.Create(ctx, name)
	if err != nil {
		return err
	}

	fmt.Println("API client created:")
	fmt.Printf("  id:   %s\n", client.ID)
	fmt.Printf("  name: %s\n", client.Name)
	fmt.Println()
	fmt.Println("API key (shown once — copy it now, it cannot be retrieved later):")
	fmt.Printf("  %s\n", key)
	fmt.Println()
	fmt.Println("The consuming system must send this in every /auth/* request as:")
	fmt.Println("  X-API-Key: <key>")

	return nil
}
