// Package auth provides a classic, production-friendly authentication layer
// for Go web apps using:
//   - Cookie-based, server-side sessions stored in SQLite
//   - Password hashing via bcrypt (configurable cost at setup time)
//   - Minimal, framework-agnostic API and HTTP helpers
//
// This file is the public, self-documenting API surface. The internal
// implementation is split across other files in this package.
//
// Quick start:
//   1) Place this package in: yourmodule/auth
//   2) go get github.com/mattn/go-sqlite3 golang.org/x/crypto/bcrypt
//   3) Example usage:
//
//       package main
//
//       import (
//         "log"
//         "net/http"
//         "time"
//         "yourmodule/auth"
//       )
//
//       func main() {
//         httpOnly := true
//         api, err := auth.New(auth.Config{
//           DBPath:           "app.db",
//           SessionName:      "session",
//           SessionTTL:       24 * time.Hour,
//           CookieSecure:     false, // true in production (HTTPS)
//           CookieHTTPOnly:   &httpOnly, // tri-state; default is true if nil
//           CookieSameSite:   http.SameSiteLaxMode,
//           BcryptCost:       12,
//           MinPasswordLength: 8,
//           RequireStrongPasswords: false, // set true to require letters+digits
//           PruneInterval:    time.Hour,   // periodically prune expired sessions
//           MaxOpenConns:     1,           // recommended for SQLite
//           MaxIdleConns:     1,
//         })
//         if err != nil {
//           log.Fatal(err)
//         }
//         defer api.Close()
//
//         mux := http.NewServeMux()
//
//         // POST /register
//         mux.HandleFunc("/register", func(w http.ResponseWriter, r *http.Request) {
//           if r.Method != http.MethodPost {
//             http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
//             return
//           }
//           // Basic CSRF hardening: enforce same-origin for state-changing POST
//           if !auth.SameOrigin(r) {
//             http.Error(w, "forbidden", http.StatusForbidden)
//             return
//           }
//           email := r.FormValue("email")
//           password := r.FormValue("password")
//           _, err := api.Register(r.Context(), email, password)
//           if err != nil {
//             // Do not leak internal errors; log if needed
//             http.Error(w, "invalid input", http.StatusBadRequest)
//             return
//           }
//           w.WriteHeader(http.StatusCreated)
//           _, _ = w.Write([]byte("registered"))
//         })
//
//         // POST /login
//         mux.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
//           if r.Method != http.MethodPost {
//             http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
//             return
//           }
//           if !auth.SameOrigin(r) {
//             http.Error(w, "forbidden", http.StatusForbidden)
//             return
//           }
//           email := r.FormValue("email")
//           password := r.FormValue("password")
//           _, err := api.Login(w, r, email, password)
//           if err != nil {
//             http.Error(w, "invalid credentials", http.StatusUnauthorized)
//             return
//           }
//           _, _ = w.Write([]byte("logged in"))
//         })
//
//         // GET /me (requires session middleware)
//         mux.Handle("/me", api.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
//           user, ok := auth.FromContext(r.Context())
//           if !ok {
//             http.Error(w, "unauthenticated", http.StatusUnauthorized)
//             return
//           }
//           _, _ = w.Write([]byte("hello " + user.Email))
//         })))
//
//         // POST /logout (method-locked and same-origin check)
//         mux.HandleFunc("/logout", func(w http.ResponseWriter, r *http.Request) {
//           if r.Method != http.MethodPost {
//             http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
//             return
//           }
//           if !auth.SameOrigin(r) {
//             http.Error(w, "forbidden", http.StatusForbidden)
//             return
//           }
//           if err := api.Logout(w, r); err != nil {
//             http.Error(w, "internal error", http.StatusInternalServerError)
//             return
//           }
//           _, _ = w.Write([]byte("logged out"))
//         })
//
//         log.Println("listening on :8080")
//         log.Fatal(http.ListenAndServe(":8080", mux))
//       }
//
// Security notes:
//   - Set CookieSecure=true in production (HTTPS).
//   - Choose an appropriate BcryptCost (10–14 typical). Higher cost => more CPU.
//   - Session tokens are random 32-byte values, stored server-side.
//   - Sessions expire after SessionTTL and are refreshed in Middleware.
//   - Basic CSRF hardening in example: POST-only and same-origin checks.
//
// Driver note:
//   - Uses github.com/mattn/go-sqlite3 (cgo). To use a pure-Go driver, replace
//     the side-effect import in store_sqlite_driver.go with modernc.org/sqlite.
//
// API overview:
//   - type Config
//   - type API
//   - type User
//   - func New(Config) (*API, error)
//   - func (*API) Close() error
//   - func (*API) Register(ctx, email, password) (User, error)
//   - func (*API) Login(w, r, email, password) (User, error)
//   - func (*API) Logout(w, r) error
//   - func (*API) CurrentUser(w, r) (User, bool, error)
//   - func (*API) Middleware(next http.Handler) http.Handler
//   - func (*API) RequireAuth(next http.Handler) http.Handler
//   - func FromContext(ctx) (User, bool)
//   - func (*API) PruneExpiredSessions(ctx) error
//   - func (*API) RevokeAllSessions(ctx, userID) error
//   - func (*API) ChangePassword(ctx, userID, newPassword) error
package auth

import (
  "context"
  "net/http"
  "time"
  "sync"
)

// Config controls the behavior of the auth package.
// All fields are optional; defaults are applied in New.
type Config struct {
 // DBPath is the filename for the SQLite database. Example: "app.db"
 DBPath string

 // SessionName is the cookie name for the session token. Default: "session".
 SessionName string

 // SessionTTL controls session lifetime. Default: 24h.
 SessionTTL time.Duration

 // CookieDomain sets the cookie domain (empty => host-only).
 CookieDomain string

 // CookieSecure should be true in production (HTTPS). Default: false.
 CookieSecure bool

 // CookieHTTPOnly controls HttpOnly on the cookie. Default: true if nil.
 // Tri-state: nil => default true; &true or &false to force.
 CookieHTTPOnly *bool

 // CookieSameSite controls the SameSite attribute. Default: http.SameSiteLaxMode.
 CookieSameSite http.SameSite

 // BcryptCost controls password hashing difficulty (4..31). Typical: 10–14.
 // Default: bcrypt.DefaultCost. Setup-only: must be provided in Config.
 BcryptCost int

 // Password policy (optional).
 // Default MinPasswordLength=8, RequireStrongPasswords=false.
 MinPasswordLength     int
 RequireStrongPasswords bool

 // Now allows overriding the time source (useful in tests). Default: time.Now.
 Now func() time.Time

 // Session maintenance: periodically prune expired sessions if > 0. Default: 1h.
 PruneInterval time.Duration

 // SQLite pool tuning. Defaults suitable for SQLite: 1/1.
 MaxOpenConns int
 MaxIdleConns int

 // Logf is an optional logger hook (printf-style). If nil, logging is disabled.
 Logf func(format string, args ...any)
}

// API is the main entry point for authentication operations.
// It is safe to share a single instance across handlers.
type API struct {
  db     dbHandle
  cfg    Config
  stopCh chan struct{}
  wg     sync.WaitGroup
}

// User is a minimal representation returned by the API (no password fields).
type User struct {
 ID        int64
 Email     string
 CreatedAt time.Time
}

// New initializes the SQLite database, runs migrations, and returns an API.
func New(cfg Config) (*API, error) {
 return newAPI(cfg)
}

// Close releases underlying resources (e.g., DB connections) and stops background jobs.
func (a *API) Close() error {
 return a.closeInternal()
}

// Register creates a new user with a bcrypt-hashed password.
// - Email is normalized to lower-case and trimmed.
// - Password must meet configured policy (min length, optional strength).
// Returns the created User (without password).
func (a *API) Register(ctx context.Context, email, password string) (User, error) {
 return a.registerInternal(ctx, email, password)
}

// Login verifies credentials, creates a server-side session, and sets a secure cookie.
// Returns the authenticated User on success. The cookie contains an opaque token;
// session state (user, expiry) is stored in SQLite.
func (a *API) Login(w http.ResponseWriter, r *http.Request, email, password string) (User, error) {
 return a.loginInternal(w, r, email, password)
}

// Logout removes the current session (if any) and clears the cookie.
func (a *API) Logout(w http.ResponseWriter, r *http.Request) error {
 return a.logoutInternal(w, r)
}

// CurrentUser resolves the session from the request cookie and returns:
//   - User: the associated user
//   - ok: whether a valid session was found
//   - err: unexpected errors (db, etc.)
func (a *API) CurrentUser(w http.ResponseWriter, r *http.Request) (User, bool, error) {
 return a.currentUserInternal(w, r)
}

// Middleware resolves the current user (if any) and injects it into the request context.
// It also refreshes sessions close to expiry.
func (a *API) Middleware(next http.Handler) http.Handler {
 return a.middlewareInternal(next)
}

// RequireAuth ensures a valid user is present in context (e.g., after Middleware).
// If not authenticated, it returns 401 and stops the chain.
func (a *API) RequireAuth(next http.Handler) http.Handler {
 return a.requireAuthInternal(next)
}

// FromContext retrieves the current user injected by Middleware.
func FromContext(ctx context.Context) (User, bool) {
 return fromContext(ctx)
}

// PruneExpiredSessions deletes expired sessions immediately.
func (a *API) PruneExpiredSessions(ctx context.Context) error {
 return a.pruneExpiredSessionsInternal(ctx)
}

// RevokeAllSessions deletes all sessions for the given user (e.g., after password change).
func (a *API) RevokeAllSessions(ctx context.Context, userID int64) error {
 return a.revokeAllSessionsInternal(ctx, userID)
}

// ChangePassword updates the user's password hash and revokes all their sessions.
func (a *API) ChangePassword(ctx context.Context, userID int64, newPassword string) error {
 return a.changePasswordInternal(ctx, userID, newPassword)
}