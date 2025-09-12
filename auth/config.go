package auth

import (
 "fmt"
 "net/http"
 "time"

 "golang.org/x/crypto/bcrypt"
)

func applyDefaults(cfg *Config) {
 if cfg.DBPath == "" {
  cfg.DBPath = "auth.db"
 }
 if cfg.SessionName == "" {
  cfg.SessionName = "session"
 }
 if cfg.SessionTTL <= 0 {
  cfg.SessionTTL = 24 * time.Hour
 }
 if cfg.CookieSameSite == 0 {
  cfg.CookieSameSite = http.SameSiteLaxMode
 }
 // Default HttpOnly to true if caller didn't explicitly set it.
 if !cfg.CookieHTTPOnly {
  cfg.CookieHTTPOnly = true
 }
 if cfg.BcryptCost == 0 {
  cfg.BcryptCost = bcrypt.DefaultCost
 }
}

func validateBcryptCost(cost int) error {
 if cost < 4 || cost > 31 {
  return fmt.Errorf("bcrypt cost must be in [4,31]; got %d", cost)
 }
 return nil
}