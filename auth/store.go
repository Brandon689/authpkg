package auth

import (
  "context"
  "database/sql"
  "fmt"
  "time"
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

func (s *sqliteDB) Begin() (*sql.Tx, error) { return s.DB.Begin() }
func (s *sqliteDB) BeginTx(ctx context.Context, opts *sql.TxOptions) (*sql.Tx, error) {
 return s.DB.BeginTx(ctx, opts)
}

// New constructs the API and initializes the database.
func newAPI(cfg Config) (*API, error) {
 applyDefaults(&cfg)
 if err := validateBcryptCost(cfg.BcryptCost); err != nil {
  return nil, err
 }

 db, err := sql.Open("sqlite3", cfg.DBPath+"?_foreign_keys=on&_busy_timeout=5000")
 if err != nil {
  return nil, fmt.Errorf("open sqlite: %w", err)
 }
 // Recommended SQLite pragmas and pool tuning.
 if _, err := db.Exec(`PRAGMA journal_mode=WAL; PRAGMA foreign_keys=ON; PRAGMA synchronous=NORMAL;`); err != nil {
  _ = db.Close()
  return nil, fmt.Errorf("set pragmas: %w", err)
 }
 db.SetMaxOpenConns(cfg.MaxOpenConns)
 db.SetMaxIdleConns(cfg.MaxIdleConns)

 api := &API{db: &sqliteDB{DB: db}, cfg: cfg, stopCh: make(chan struct{})}
 if err := api.migrate(); err != nil {
  _ = db.Close()
  return nil, fmt.Errorf("migrate: %w", err)
 }

 // Background session janitor.
 if cfg.PruneInterval > 0 {
  startJanitor(api, cfg.PruneInterval)
 }

 return api, nil
}

func (a *API) closeInternal() error {
  if a.db == nil {
    return nil
  }
  if a.stopCh != nil {
    close(a.stopCh)
    a.stopCh = nil
  }
  a.wg.Wait()
  return a.db.Close()
}

func startJanitor(a *API, interval time.Duration) {
  ticker := time.NewTicker(interval)
  a.wg.Add(1)
  go func() {
    defer a.wg.Done()
    defer ticker.Stop()
    for {
      select {
      case <-ticker.C:
        if err := a.pruneExpiredSessionsInternal(context.Background()); err != nil {
          a.logf("janitor prune error: %v", err)
        }
      case <-a.stopCh:
        return
      }
    }
  }()
}