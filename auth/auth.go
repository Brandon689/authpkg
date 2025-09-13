package auth

import (
  "context"
  "database/sql"
  "errors"
  "fmt"
  "net/http"
  "strings"
  "time"
  "golang.org/x/crypto/bcrypt"
)

const failedLoginDelay = 250 * time.Millisecond

func (a *API) registerInternal(ctx context.Context, email, password string) (User, error) {
 email = normalizeEmail(email)
 if !validEmailBasic(email) {
  return User{}, fmt.Errorf("invalid email")
 }

 if err := validatePasswordPolicy(password, a.cfg.MinPasswordLength, a.cfg.RequireStrongPasswords); err != nil {
  return User{}, err
 }

 cost := a.cfg.BcryptCost
 hash, err := bcrypt.GenerateFromPassword([]byte(password), cost)
 if err != nil {
  return User{}, fmt.Errorf("hash password: %w", err)
 }

 now := a.now().Unix()
 tx, err := a.db.BeginTx(ctx, nil)
 if err != nil {
  return User{}, fmt.Errorf("begin: %w", err)
 }
 defer rollbackIfNeeded(tx)

 res, err := tx.ExecContext(ctx, `
  INSERT INTO users (email, password_hash, created_at)
  VALUES (?, ?, ?)
 `, email, hash, now)
 if err != nil {
  // Be driver-agnostic: detect unique violations by message.
  msg := strings.ToLower(err.Error())
  if strings.Contains(msg, "unique") && strings.Contains(msg, "users") && strings.Contains(msg, "email") {
   return User{}, fmt.Errorf("email already registered")
  }
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
      time.Sleep(failedLoginDelay)
      return User{}, fmt.Errorf("invalid credentials")
    }
    return User{}, fmt.Errorf("query user: %w", err)
  }
  if err := bcrypt.CompareHashAndPassword(hash, []byte(password)); err != nil {
    time.Sleep(failedLoginDelay)
    return User{}, fmt.Errorf("invalid credentials")
  }

  // Opportunistic bcrypt upgrade
  if currentCost, err := bcrypt.Cost(hash); err == nil && currentCost < a.cfg.BcryptCost {
    if err := validateBcryptCost(a.cfg.BcryptCost); err == nil {
      if newHash, err := bcrypt.GenerateFromPassword([]byte(password), a.cfg.BcryptCost); err == nil {
        if _, err := a.db.ExecContext(ctx, `UPDATE users SET password_hash = ? WHERE id = ?`, newHash, id); err != nil {
          a.logf("bcrypt upgrade failed for user %d: %v", id, err)
        }
      } else {
        a.logf("bcrypt rehash error: %v", err)
      }
    }
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

func (a *API) pruneExpiredSessionsInternal(ctx context.Context) error {
 _, err := a.db.ExecContext(ctx, `DELETE FROM sessions WHERE expires_at <= ?`, a.now().Unix())
 return err
}

func (a *API) revokeAllSessionsInternal(ctx context.Context, userID int64) error {
 _, err := a.db.ExecContext(ctx, `DELETE FROM sessions WHERE user_id = ?`, userID)
 return err
}

func (a *API) changePasswordInternal(ctx context.Context, userID int64, newPassword string) error {
 if err := validatePasswordPolicy(newPassword, a.cfg.MinPasswordLength, a.cfg.RequireStrongPasswords); err != nil {
  return err
 }
 hash, err := bcrypt.GenerateFromPassword([]byte(newPassword), a.cfg.BcryptCost)
 if err != nil {
  return fmt.Errorf("hash password: %w", err)
 }
 tx, err := a.db.BeginTx(ctx, nil)
 if err != nil {
  return fmt.Errorf("begin: %w", err)
 }
 defer rollbackIfNeeded(tx)
 if _, err := tx.ExecContext(ctx, `UPDATE users SET password_hash = ? WHERE id = ?`, hash, userID); err != nil {
  return fmt.Errorf("update user: %w", err)
 }
 if _, err := tx.ExecContext(ctx, `DELETE FROM sessions WHERE user_id = ?`, userID); err != nil {
  return fmt.Errorf("revoke sessions: %w", err)
 }
 if err := tx.Commit(); err != nil {
  return fmt.Errorf("commit: %w", err)
 }
 return nil
}