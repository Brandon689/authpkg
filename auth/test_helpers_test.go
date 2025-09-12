package auth

import (
 "net/http"
 "net/http/httptest"
 "path/filepath"
 "testing"
 "time"
)

func newTestAPI(t *testing.T, mutate ...func(*Config)) (*API, func()) {
 t.Helper()
 dir := t.TempDir()
 dbPath := filepath.Join(dir, "test.db")

 base := time.Unix(1_700_000_000, 0)
 cfg := Config{
  DBPath:         dbPath,
  SessionName:    "session",
  SessionTTL:     time.Hour,
  CookieHTTPOnly: true,
  CookieSecure:   false,
  BcryptCost:     4, // Fast for tests
  Now: func() time.Time {
   return base
  },
 }

 for _, fn := range mutate {
  fn(&cfg)
 }

 api, err := New(cfg)
 if err != nil {
  t.Fatalf("New: %v", err)
 }

 cleanup := func() {
  _ = api.Close()
 }
 return api, cleanup
}

func mustLogin(t *testing.T, api *API, email, pass string) *http.Cookie {
 t.Helper()
 w := httptest.NewRecorder()
 r := httptest.NewRequest(http.MethodPost, "/login", nil)
 if _, err := api.Login(w, r, email, pass); err != nil {
  t.Fatalf("login: %v", err)
 }
 res := w.Result()
 for _, c := range res.Cookies() {
  if c.Name == api.cfg.SessionName {
   return c
  }
 }
 t.Fatalf("session cookie not set")
 return nil
}

func newReqWithCookie(method, target string, c *http.Cookie) *http.Request {
 r := httptest.NewRequest(method, target, nil)
 if c != nil {
  r.AddCookie(c)
 }
 return r
}