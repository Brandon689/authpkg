package auth

import (
 "context"
 "database/sql"
 "fmt"
)

// dbHandle abstracts *sql.DB for testability and context-aware calls.
type dbHandle interface {
 Close() error
 Exec(query string, args ...any) (sql.Result, error)
 ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
 QueryRow(query string, args ...any) *sql.Row
 QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
 Begin() (*sql.Tx, error)
 BeginTx(ctx context.Context, opts *sql.TxOptions) (*sql.Tx, error)
}

// sqliteDB is the concrete DB handle in production (embeds *sql.DB).
type sqliteDB struct{ *sql.DB }

func (s *sqliteDB) Begin() (*sql.Tx, error)                  { return s.DB.Begin() }
func (s *sqliteDB) BeginTx(ctx context.Context, opts *sql.TxOptions) (*sql.Tx, error) {
 return s.DB.BeginTx(ctx, opts)
}

// New constructs the API and initializes the database.
func newAPI(cfg Config) (*API, error) {
 applyDefaults(&cfg)

 db, err := sql.Open("sqlite3", cfg.DBPath+"?_foreign_keys=on&_busy_timeout=5000")
 if err != nil {
  return nil, fmt.Errorf("open sqlite: %w", err)
 }
 if _, err := db.Exec(`PRAGMA journal_mode=WAL; PRAGMA foreign_keys=ON; PRAGMA synchronous=NORMAL;`); err != nil {
  _ = db.Close()
  return nil, fmt.Errorf("set pragmas: %w", err)
 }

 api := &API{db: &sqliteDB{DB: db}, cfg: cfg}
 if err := api.migrate(); err != nil {
  _ = db.Close()
  return nil, fmt.Errorf("migrate: %w", err)
 }
 return api, nil
}

func (a *API) closeInternal() error {
 if a.db == nil {
  return nil
 }
 return a.db.Close()
}