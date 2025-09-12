package auth

import (
 "context"
 "database/sql"
 "errors"
 "fmt"
 "net/http"
 "time"

 "golang.org/x/crypto/bcrypt"
)

func (a *API) registerInternal(ctx context.Context, email, password string) (User, error) {
 email = normalizeEmail(email)
 if !validEmailBasic(email) {
  return User{}, fmt.Errorf("invalid email")
 }
 if len(password) < 8 {
  return User{}, fmt.Errorf("password too short (min 8)")
 }

 hash, err := bcrypt.GenerateFromPassword([]byte(password), a.cfg.BcryptCost)
 if err != nil {
  return User{}, fmt.Errorf("hash password: %w", err)
 }

 now := a.now().Unix()
 tx, err := a.db.Begin()
 if err != nil {
  return User{}, fmt.Errorf("begin: %w", err)
 }
 defer rollbackIfNeeded(tx)

 var exists int
 if err := tx.QueryRow(`SELECT 1 FROM users WHERE email = ?`, email).Scan(&exists); err != nil && err != sql.ErrNoRows {
  return User{}, fmt.Errorf("check email: %w", err)
 }
 if exists == 1 {
  return User{}, fmt.Errorf("email already registered")
 }

 res, err := tx.Exec(`
  INSERT INTO users (email, password_hash, created_at)
  VALUES (?, ?, ?)
 `, email, hash, now)
 if err != nil {
  return User{}, fmt.Errorf("insert user: %w", err)
 }

 id, err := res.LastInsertId()
 if err != nil {
  return User{}, fmt.Errorf("last insert id: %w", err)
 }
 if err := tx.Commit(); err != nil {
  return User{}, fmt.Errorf("commit: %w", err)
 }

 return User{ID: id, Email: email, CreatedAt: time.Unix(now, 0)}, nil
}

func (a *API) loginInternal(w http.ResponseWriter, r *http.Request, email, password string) (User, error) {
 ctx := r.Context()
 email = normalizeEmail(email)

 var (
  id        int64
  dbEmail   string
  hash      []byte
  createdAt int64
 )
 err := a.db.QueryRowContext(ctx, `
  SELECT id, email, password_hash, created_at
  FROM users
  WHERE email = ?
 `, email).Scan(&id, &dbEmail, &hash, &createdAt)
 if err != nil {
  if errors.Is(err, sql.ErrNoRows) {
   return User{}, fmt.Errorf("invalid credentials")
  }
  return User{}, fmt.Errorf("query user: %w", err)
 }

 if err := bcrypt.CompareHashAndPassword(hash, []byte(password)); err != nil {
  return User{}, fmt.Errorf("invalid credentials")
 }

 user := User{ID: id, Email: dbEmail, CreatedAt: time.Unix(createdAt, 0)}
 if err := a.createSessionAndSetCookie(w, ctx, user.ID); err != nil {
  return User{}, fmt.Errorf("create session: %w", err)
 }
 return user, nil
}

func (a *API) logoutInternal(w http.ResponseWriter, r *http.Request) error {
 token, err := a.readSessionCookie(r)
 if err != nil || token == "" {
  a.clearCookie(w)
  return nil
 }
 if _, err := a.db.ExecContext(r.Context(), `DELETE FROM sessions WHERE token = ?`, token); err != nil {
  a.clearCookie(w)
  return fmt.Errorf("delete session: %w", err)
 }
 a.clearCookie(w)
 return nil
}

func (a *API) currentUserInternal(w http.ResponseWriter, r *http.Request) (User, bool, error) {
 ctx := r.Context()
 token, err := a.readSessionCookie(r)
 if err != nil || token == "" {
  return User{}, false, nil
 }

 var (
  userID    int64
  email     string
  uc        int64
  expiresAt int64
 )
 err = a.db.QueryRowContext(ctx, `
  SELECT u.id, u.email, u.created_at, s.expires_at
  FROM sessions s
  JOIN users u ON u.id = s.user_id
  WHERE s.token = ?
 `, token).Scan(&userID, &email, &uc, &expiresAt)
 if err != nil {
  if errors.Is(err, sql.ErrNoRows) {
   a.clearCookie(w)
   return User{}, false, nil
  }
  return User{}, false, fmt.Errorf("query session: %w", err)
 }

 now := a.now().Unix()
 if now >= expiresAt {
  _, _ = a.db.ExecContext(ctx, `DELETE FROM sessions WHERE token = ?`, token)
  a.clearCookie(w)
  return User{}, false, nil
 }

 // Refresh if within last 20% of TTL.
 ttl := int64(a.cfg.SessionTTL.Seconds())
 if ttl > 0 {
  remaining := expiresAt - now
  if remaining*5 <= ttl {
   newExp := now + ttl
   if _, err := a.db.ExecContext(ctx, `UPDATE sessions SET expires_at = ? WHERE token = ?`, newExp, token); err == nil {
    a.setCookie(w, token, time.Unix(newExp, 0))
   }
  }
 }

 return User{ID: userID, Email: email, CreatedAt: time.Unix(uc, 0)}, true, nil
}

func (a *API) setBcryptCostInternal(cost int) error {
 if err := validateBcryptCost(cost); err != nil {
  return err
 }
 a.cfg.BcryptCost = cost
 return nil
}