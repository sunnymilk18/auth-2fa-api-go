// Command createclient manages api clients (tenants): create, list,
// activate/deactivate, and rotate a key. Each api_client identifies one
// consuming system — see README's "Multi-tenant" section.
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"strings"

	"auth-2fa-api/internal/apiclient"
	"auth-2fa-api/internal/config"
	"auth-2fa-api/internal/db"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(1)
	}

	sub, args := os.Args[1], os.Args[2:]
	// Backward compatible: `createclient -name X` with no subcommand still
	// means "create", exactly like before this tool grew subcommands.
	if strings.HasPrefix(sub, "-") {
		sub, args = "create", os.Args[1:]
	}

	var err error
	switch sub {
	case "create":
		err = runCreate(args)
	case "list":
		err = runList(args)
	case "deactivate":
		err = runSetActive(args, false)
	case "activate":
		err = runSetActive(args, true)
	case "rotate":
		err = runRotate(args)
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
  createclient create -name <name>    Provision a new api client, printing its key once
  createclient list                   List all api clients (id, active, created, name)
  createclient deactivate -id <id>    Deactivate an api client — its key stops working immediately
  createclient activate -id <id>      Reactivate a previously-deactivated api client
  createclient rotate -id <id>        Issue a new key for an existing client, invalidating the old one`)
}

// newService connects to SQL Server and returns a ready-to-use Service plus
// a cleanup func the caller must defer.
func newService() (*apiclient.Service, func(), error) {
	cfg, err := config.Load()
	if err != nil {
		return nil, nil, err
	}

	sqlDB, err := db.NewMSSQL(context.Background(), cfg.MSSQLDSN)
	if err != nil {
		return nil, nil, err
	}

	closeFn := func() { sqlDB.Close() }
	return apiclient.NewService(apiclient.NewRepository(sqlDB)), closeFn, nil
}

func runCreate(args []string) error {
	fs := flag.NewFlagSet("create", flag.ExitOnError)
	name := fs.String("name", "", "descriptive name for the consuming system (e.g. auth-2fa-app-flutter)")
	_ = fs.Parse(args)
	if *name == "" {
		return fmt.Errorf("-name is required")
	}

	svc, closeFn, err := newService()
	if err != nil {
		return err
	}
	defer closeFn()

	client, key, err := svc.Create(context.Background(), *name)
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

func runList(args []string) error {
	fs := flag.NewFlagSet("list", flag.ExitOnError)
	_ = fs.Parse(args)

	svc, closeFn, err := newService()
	if err != nil {
		return err
	}
	defer closeFn()

	clients, err := svc.List(context.Background())
	if err != nil {
		return err
	}
	if len(clients) == 0 {
		fmt.Println("no api clients found")
		return nil
	}

	fmt.Printf("%-36s  %-6s  %-19s  %s\n", "ID", "ACTIVE", "CREATED", "NAME")
	for _, c := range clients {
		fmt.Printf("%-36s  %-6t  %-19s  %s\n", c.ID, c.Active, c.CreatedAt.Format("2006-01-02 15:04:05"), c.Name)
	}
	return nil
}

func runSetActive(args []string, active bool) error {
	verb := "deactivate"
	if active {
		verb = "activate"
	}
	fs := flag.NewFlagSet(verb, flag.ExitOnError)
	id := fs.String("id", "", "api client id (see `createclient list`)")
	_ = fs.Parse(args)
	if *id == "" {
		return fmt.Errorf("-id is required")
	}

	svc, closeFn, err := newService()
	if err != nil {
		return err
	}
	defer closeFn()

	var opErr error
	if active {
		opErr = svc.Activate(context.Background(), *id)
	} else {
		opErr = svc.Deactivate(context.Background(), *id)
	}
	if opErr != nil {
		return opErr
	}

	effect := "stops working"
	if active {
		effect = "works again"
	}
	fmt.Printf("api client %s %sd — its key %s immediately.\n", *id, verb, effect)
	return nil
}

func runRotate(args []string) error {
	fs := flag.NewFlagSet("rotate", flag.ExitOnError)
	id := fs.String("id", "", "api client id (see `createclient list`)")
	_ = fs.Parse(args)
	if *id == "" {
		return fmt.Errorf("-id is required")
	}

	svc, closeFn, err := newService()
	if err != nil {
		return err
	}
	defer closeFn()

	newKey, err := svc.Rotate(context.Background(), *id)
	if err != nil {
		return err
	}

	fmt.Println("API key rotated — the old key stops working immediately.")
	fmt.Println()
	fmt.Println("New API key (shown once — copy it now, it cannot be retrieved later):")
	fmt.Printf("  %s\n", newKey)
	return nil
}
