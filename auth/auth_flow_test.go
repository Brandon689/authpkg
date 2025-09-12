package auth

import (
 "context"
 "net/http"
 "net/http/httptest"
 "strings"
 "testing"
 "time"
)

func TestRegisterLoginCurrentLogout(t *testing.T) {
 api, cleanup := newTestAPI(t)
 defer cleanup()

 ctx := context.Background()

 // Register
 u, err := api.Register(ctx, "User@Example.com", "password123")
 if err != nil {
  t.Fatalf("Register: %v", err)
 }
 if u.Email != "user@example.com" {
  t.Fatalf("email normalization failed: got %q", u.Email)
 }

 // Duplicate
 if _, err := api.Register(ctx, "user@example.com", "password123"); err == nil {
  t.Fatalf("expected duplicate email error")
 }

 // Wrong password
 w := httptest.NewRecorder()
 r := httptest.NewRequest(http.MethodPost, "/login", nil)
 if _, err := api.Login(w, r, "user@example.com", "bad"); err == nil {
  t.Fatalf("expected invalid credentials")
 }

 // Login
 c := mustLogin(t, api, "user@example.com", "password123")
 if !c.HttpOnly || c.Secure != false {
  t.Fatalf("cookie flags unexpected: httpOnly=%v secure=%v", c.HttpOnly, c.Secure)
 }
 if c.Name != api.cfg.SessionName || c.Value == "" {
  t.Fatalf("cookie name/value invalid")
 }

 // CurrentUser (valid)
 w2 := httptest.NewRecorder()
 r2 := newReqWithCookie(http.MethodGet, "/me", c)
 usr, ok, err := api.CurrentUser(w2, r2)
 if err != nil || !ok {
  t.Fatalf("CurrentUser expected ok=true, err=nil; got ok=%v err=%v", ok, err)
 }
 if usr.Email != "user@example.com" {
  t.Fatalf("CurrentUser email mismatch")
 }

 // Logout
 w3 := httptest.NewRecorder()
 r3 := newReqWithCookie(http.MethodPost, "/logout", c)
 if err := api.Logout(w3, r3); err != nil {
  t.Fatalf("Logout: %v", err)
 }
 // After logout, session invalid
 w4 := httptest.NewRecorder()
 r4 := newReqWithCookie(http.MethodGet, "/me", c)
 _, ok, err = api.CurrentUser(w4, r4)
 if err != nil || ok {
  t.Fatalf("CurrentUser after logout: ok=%v err=%v", ok, err)
 }
}

func TestInvalidEmailAndPassword(t *testing.T) {
 api, cleanup := newTestAPI(t)
 defer cleanup()

 ctx := context.Background()

 if _, err := api.Register(ctx, "not-an-email", "password123"); err == nil {
  t.Fatalf("expected invalid email error")
 }
 if _, err := api.Register(ctx, "a@b.com", "short"); err == nil {
  t.Fatalf("expected short password error")
 }
}

func TestSessionExpiry(t *testing.T) {
 base := time.Unix(1_700_000_000, 0)
 api, cleanup := newTestAPI(t, func(c *Config) {
  c.SessionTTL = time.Hour
  c.Now = func() time.Time { return base }
 })
 defer cleanup()

 ctx := context.Background()
 if _, err := api.Register(ctx, "u@example.com", "password123"); err != nil {
  t.Fatalf("register: %v", err)
 }
 c := mustLogin(t, api, "u@example.com", "password123")

 // Advance time beyond expiry
 api.cfg.Now = func() time.Time { return base.Add(2 * time.Hour) }

 w := httptest.NewRecorder()
 r := newReqWithCookie(http.MethodGet, "/me", c)
 _, ok, err := api.CurrentUser(w, r)
 if err != nil {
  t.Fatalf("CurrentUser err: %v", err)
 }
 if ok {
  t.Fatalf("expected session expired")
 }
 // Verify a clearing Set-Cookie was issued
 setCookie := strings.Join(w.Result().Header.Values("Set-Cookie"), ";")
 if !(strings.Contains(setCookie, "Max-Age=0") || strings.Contains(setCookie, "Expires=")) {
  t.Fatalf("expected cookie clearing header, got: %q", setCookie)
 }
}

func TestSessionRefresh(t *testing.T) {
 base := time.Unix(1_700_000_000, 0)
 api, cleanup := newTestAPI(t, func(c *Config) {
  c.SessionTTL = 100 * time.Second
  c.Now = func() time.Time { return base }
 })
 defer cleanup()

 ctx := context.Background()
 if _, err := api.Register(ctx, "u2@example.com", "password123"); err != nil {
  t.Fatalf("register: %v", err)
 }
 c := mustLogin(t, api, "u2@example.com", "password123")

 // Move time near expiry (remaining <= 20% => refresh)
 api.cfg.Now = func() time.Time { return base.Add(81 * time.Second) } // remaining=19s, 19*5 <= 100

 w := httptest.NewRecorder()
 r := newReqWithCookie(http.MethodGet, "/me", c)
 u, ok, err := api.CurrentUser(w, r)
 if err != nil || !ok || u.Email != "u2@example.com" {
  t.Fatalf("CurrentUser: ok=%v err=%v user=%v", ok, err, u)
 }
 // Should set a refreshed cookie (new Expires later than original)
 found := false
 for _, sc := range w.Result().Cookies() {
  if sc.Name == api.cfg.SessionName {
   found = true
   // Expires should be base+81+100
   want := base.Add(181 * time.Second)
   if !sc.Expires.Equal(want) {
    t.Fatalf("expected refreshed expire %v, got %v", want, sc.Expires)
   }
  }
 }
 if !found {
  t.Fatalf("expected refreshed Set-Cookie")
 }
}

func TestMultipleSessionsAndLogoutSingle(t *testing.T) {
 api, cleanup := newTestAPI(t)
 defer cleanup()

 ctx := context.Background()
 if _, err := api.Register(ctx, "m@example.com", "password123"); err != nil {
  t.Fatalf("register: %v", err)
 }
 c1 := mustLogin(t, api, "m@example.com", "password123")
 c2 := mustLogin(t, api, "m@example.com", "password123")

 // Logout using cookie 1
 w := httptest.NewRecorder()
 r := newReqWithCookie(http.MethodPost, "/logout", c1)
 if err := api.Logout(w, r); err != nil {
  t.Fatalf("logout: %v", err)
 }

 // c1 should no longer work
 w1 := httptest.NewRecorder()
 r1 := newReqWithCookie(http.MethodGet, "/me", c1)
 if _, ok, _ := api.CurrentUser(w1, r1); ok {
  t.Fatalf("c1 should be invalid after logout")
 }

 // c2 should still work
 w2 := httptest.NewRecorder()
 r2 := newReqWithCookie(http.MethodGet, "/me", c2)
 if _, ok, _ := api.CurrentUser(w2, r2); !ok {
  t.Fatalf("c2 should still be valid")
 }
}