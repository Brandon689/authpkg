package auth

import (
  "net/http"
  "testing"
  "time"

  "golang.org/x/crypto/bcrypt"
)

func TestDefaultsApplied(t *testing.T) {
  api, cleanup := newTestAPI(t, func(c *Config) {
    // Intentionally leave most fields zero-valued except DBPath from helper
    c.SessionName = ""
    c.SessionTTL = 0
    c.CookieSameSite = 0
    c.BcryptCost = 0
    // Do not set CookieHTTPOnly; leaving it nil should default to true
  })
  defer cleanup()

  if api.cfg.SessionName != "session" {
    t.Fatalf("SessionName default: got %q", api.cfg.SessionName)
  }
  if api.cfg.SessionTTL != 24*time.Hour {
    t.Fatalf("SessionTTL default: got %v", api.cfg.SessionTTL)
  }
  if api.cfg.CookieSameSite != http.SameSiteLaxMode {
    t.Fatalf("CookieSameSite default: got %v", api.cfg.CookieSameSite)
  }
  if api.cfg.CookieHTTPOnly == nil || !*api.cfg.CookieHTTPOnly {
    t.Fatalf("CookieHTTPOnly default: got %v", api.cfg.CookieHTTPOnly)
  }
  if api.cfg.BcryptCost != bcrypt.DefaultCost {
    t.Fatalf("BcryptCost default: got %v", api.cfg.BcryptCost)
  }
}

func TestSetBcryptCostValidation(t *testing.T) {
  api, cleanup := newTestAPI(t)
  defer cleanup()

  if err := api.SetBcryptCost(3); err == nil {
    t.Fatalf("expected error for cost 3")
  }
  if err := api.SetBcryptCost(32); err == nil {
    t.Fatalf("expected error for cost 32")
  }
  if err := api.SetBcryptCost(5); err != nil {
    t.Fatalf("unexpected error: %v", err)
  }
}
