package auth

import (
 "context"
 "crypto/rand"
 "database/sql"
 "encoding/base64"
 "errors"
 "net/http"
 "time"
)

func (a *API) createSessionAndSetCookie(w http.ResponseWriter, ctx context.Context, userID int64) error {
 token, err := newSessionToken()
 if err != nil {
  return err
 }
 now := a.now()
 expiresAt := now.Add(a.cfg.SessionTTL).Unix()

 if _, err := a.db.ExecContext(ctx, `
  INSERT INTO sessions (token, user_id, expires_at, created_at)
  VALUES (?, ?, ?, ?)
 `, token, userID, expiresAt, now.Unix()); err != nil {
  return err
 }

 a.setCookie(w, token, time.Unix(expiresAt, 0))
 return nil
}

func (a *API) readSessionCookie(r *http.Request) (string, error) {
 c, err := r.Cookie(a.cfg.SessionName)
 if err != nil {
  if errors.Is(err, http.ErrNoCookie) {
   return "", nil
  }
  return "", err
 }
 return c.Value, nil
}

// setCookie computes MaxAge using the package's time source to keep tests deterministic.
func (a *API) setCookie(w http.ResponseWriter, token string, expires time.Time) {
 // Compute delta relative to a.now(), not time.Now(), so tests with fixed Now pass.
 delta := int(expires.Sub(a.now()).Seconds())
 if delta <= 0 {
  // Fallback to configured TTL seconds if clock skew or rounding produced non-positive.
  delta = int(a.cfg.SessionTTL.Seconds())
  if delta <= 0 {
   delta = 1
  }
 }
 c := &http.Cookie{
  Name:     a.cfg.SessionName,
  Value:    token,
  Path:     "/",
  Domain:   a.cfg.CookieDomain,
  Expires:  expires,
  MaxAge:   delta,
  HttpOnly: a.cfg.CookieHTTPOnly,
  Secure:   a.cfg.CookieSecure,
  SameSite: a.cfg.CookieSameSite,
 }
 http.SetCookie(w, c)
}

// clearCookie uses MaxAge=0 plus an Expires in the past to ensure deletion across clients.
func (a *API) clearCookie(w http.ResponseWriter) {
 c := &http.Cookie{
  Name:     a.cfg.SessionName,
  Value:    "",
  Path:     "/",
  Domain:   a.cfg.CookieDomain,
  Expires:  time.Unix(0, 0),
  MaxAge:   0,
  HttpOnly: a.cfg.CookieHTTPOnly,
  Secure:   a.cfg.CookieSecure,
  SameSite: a.cfg.CookieSameSite,
 }
 http.SetCookie(w, c)
}

func newSessionToken() (string, error) {
 var b [32]byte
 if _, err := rand.Read(b[:]); err != nil {
  return "", err
 }
 return base64.RawURLEncoding.EncodeToString(b[:]), nil
}

// rollbackIfNeeded rolls back tx if it's still active.
func rollbackIfNeeded(tx *sql.Tx) {
 _ = tx.Rollback()
}