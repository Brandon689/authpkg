package auth

import (
 "net/http"
 "net/http/httptest"
 "testing"
 "time"
)

func TestCookieFlagsOnLoginAndClear(t *testing.T) {
 api, cleanup := newTestAPI(t, func(c *Config) {
  c.CookieSecure = false
  c.CookieHTTPOnly = true
  c.SessionTTL = 30 * time.Minute
 })
 defer cleanup()

 // Register and login
 if _, err := api.Register(httptest.NewRequest("GET", "/", nil).Context(), "c@example.com", "password123"); err != nil {
  t.Fatalf("register: %v", err)
 }
 w := httptest.NewRecorder()
 r := httptest.NewRequest(http.MethodPost, "/login", nil)
 if _, err := api.Login(w, r, "c@example.com", "password123"); err != nil {
  t.Fatalf("login: %v", err)
 }
 var sc *http.Cookie
 for _, c := range w.Result().Cookies() {
  if c.Name == api.cfg.SessionName {
   sc = c
   break
  }
 }
 if sc == nil {
  t.Fatalf("Set-Cookie not found")
 }
 if !sc.HttpOnly || sc.Secure {
  t.Fatalf("cookie flags unexpected: httpOnly=%v secure=%v", sc.HttpOnly, sc.Secure)
 }
 if sc.Expires.IsZero() || sc.MaxAge <= 0 {
  t.Fatalf("cookie expiry not set")
 }

 // Clear on logout
 w2 := httptest.NewRecorder()
 r2 := httptest.NewRequest(http.MethodPost, "/logout", nil)
 r2.AddCookie(sc)
 if err := api.Logout(w2, r2); err != nil {
  t.Fatalf("logout: %v", err)
 }
 // Expect clearing Set-Cookie
 found := false
 for _, c := range w2.Result().Cookies() {
  if c.Name == api.cfg.SessionName {
   found = true
   // Deleted cookie should have MaxAge==0 per parser and Expires in the past
   if c.MaxAge != 0 {
    t.Fatalf("expected MaxAge=0, got %d", c.MaxAge)
   }
  }
 }
 if !found {
  t.Fatalf("expected clearing cookie")
 }
}