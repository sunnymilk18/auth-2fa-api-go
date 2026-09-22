package db

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	mssql "github.com/microsoft/go-mssqldb"
	"github.com/microsoft/go-mssqldb/msdsn"
)

// NewMSSQL opens a SQL Server connection pool and verifies connectivity,
// retrying with backoff for up to 30s — smooths over SQL Server still
// starting up instead of failing the whole service on one unlucky first
// ping. dsn uses the driver's URL form, e.g.
// sqlserver://user:password@host:port?database=dbname.
func NewMSSQL(ctx context.Context, dsn string) (*sql.DB, error) {
	params, err := msdsn.Parse(dsn)
	if err != nil {
		return nil, fmt.Errorf("parsing mssql dsn: %w", err)
	}
	// The plain "sqlserver" driver name (registered by the blank import
	// elsewhere) leaves "?" placeholders untranslated — every repository in
	// this project writes queries with "?" (matching every other driver
	// this project has used, pgx included), so open via a connector with
	// ProcessQueryText explicitly enabled instead, which rewrites "?" to
	// "@pN" the same way the deprecated "mssql" driver name always did.
	connector := mssql.NewConnectorWithProcessQueryText(params)
	db := sql.OpenDB(connector)

	err = retryConnect(ctx, "mssql", 30*time.Second, func(ctx context.Context) error {
		pingCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
		defer cancel()
		return db.PingContext(pingCtx)
	})
	if err != nil {
		db.Close()
		return nil, fmt.Errorf("pinging mssql: %w", err)
	}

	return db, nil
}
