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
 if cfg.CookieHTTPOnly == nil {
  t := true
  cfg.CookieHTTPOnly = &t
 }
 if cfg.BcryptCost == 0 {
  cfg.BcryptCost = bcrypt.DefaultCost
 }
 if cfg.MinPasswordLength <= 0 {
  cfg.MinPasswordLength = 8
 }
 // RequireStrongPasswords defaults to false; leave as-is.

 if cfg.PruneInterval <= 0 {
  cfg.PruneInterval = time.Hour
 }
 if cfg.MaxOpenConns <= 0 {
  cfg.MaxOpenConns = 1
 }
 if cfg.MaxIdleConns <= 0 {
  cfg.MaxIdleConns = 1
 }
}

func validateBcryptCost(cost int) error {
 if cost < 4 || cost > 31 {
  return fmt.Errorf("bcrypt cost must be in [4,31]; got %d", cost)
 }
 return nil
}