package auth

import (
  "net/url"
  "strings"
  "time"
  "fmt"
  "net/http"
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

// validatePasswordPolicy enforces minimal length and optional strength requirements.
func validatePasswordPolicy(pw string, minLen int, requireStrong bool) error {
 if len(pw) < minLen {
  return fmt.Errorf("password too short (min %d)", minLen)
 }
 if requireStrong && !hasLetterAndDigit(pw) {
  return fmt.Errorf("password must contain at least one letter and one digit")
 }
 return nil
}

func hasLetterAndDigit(s string) bool {
 var hasL, hasD bool
 for _, r := range s {
  switch {
  case r >= '0' && r <= '9':
   hasD = true
  case (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z'):
   hasL = true
  }
  if hasL && hasD {
   return true
  }
 }
 return false
}

// SameOrigin performs a basic same-origin check using the Origin header.
// If Origin is absent (e.g., non-CORS same-site requests), it returns true.
// It compares the Host in Origin with r.Host (scheme is ignored).
func SameOrigin(r *http.Request) bool {
  origin := r.Header.Get("Origin")
  if origin != "" {
    u, err := url.Parse(origin)
    if err != nil {
      return false
    }
    return strings.EqualFold(u.Host, r.Host)
  }
  // Fallback to Referer for unsafe methods.
  if isUnsafeMethod(r.Method) {
    ref := r.Header.Get("Referer")
    if ref == "" {
      return false
    }
    u, err := url.Parse(ref)
    if err != nil {
      return false
    }
    return strings.EqualFold(u.Host, r.Host)
  }
  // Allow safe methods when Origin is absent.
  return true
}

func isUnsafeMethod(m string) bool {
  switch m {
  case http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete:
    return true
  default:
    return false
  }
}

func (a *API) logf(format string, args ...any) {
  if a != nil && a.cfg.Logf != nil {
    a.cfg.Logf(format, args...)
  }
}