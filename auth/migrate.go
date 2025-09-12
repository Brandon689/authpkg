package auth

import "fmt"

func (a *API) migrate() error {
 stmts := []string{
  `CREATE TABLE IF NOT EXISTS users (
   id INTEGER PRIMARY KEY AUTOINCREMENT,
   email TEXT NOT NULL UNIQUE,
   password_hash BLOB NOT NULL,
   created_at INTEGER NOT NULL
  );`,
  `CREATE TABLE IF NOT EXISTS sessions (
   id INTEGER PRIMARY KEY AUTOINCREMENT,
   token TEXT NOT NULL UNIQUE,
   user_id INTEGER NOT NULL,
   expires_at INTEGER NOT NULL,
   created_at INTEGER NOT NULL,
   FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
  );`,
  `CREATE INDEX IF NOT EXISTS idx_sessions_expires_at ON sessions(expires_at);`,
 }
 for _, s := range stmts {
  if _, err := a.db.Exec(s); err != nil {
   return fmt.Errorf("migrate step: %w", err)
  }
 }
 return nil
}