package auth

import (
 "strings"
 "time"
)

func (a *API) now() time.Time {
 if a.cfg.Now != nil {
  return a.cfg.Now()
 }
 return time.Now()
}

func normalizeEmail(e string) string {
 return strings.TrimSpace(strings.ToLower(e))
}

func validEmailBasic(e string) bool {
 // Minimal sanity check without full RFC validation.
 if e == "" || !strings.Contains(e, "@") {
  return false
 }
 parts := strings.Split(e, "@")
 if len(parts) != 2 {
  return false
 }
 if parts[0] == "" || parts[1] == "" || !strings.Contains(parts[1], ".") {
  return false
 }
 return true
}