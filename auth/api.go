// Package auth provides a classic, production-friendly authentication layer
// for Go web apps using:
//   - Cookie-based, server-side sessions stored in SQLite
//   - Password hashing via bcrypt (configurable cost)
//   - Minimal, framework-agnostic API and HTTP helpers
//
// This file is the public, self-documenting API surface. You can paste this
// file into an LLM to understand how to use the package. The internal
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
//         api, err := auth.New(auth.Config{
//           DBPath:         "app.db",
//           SessionName:    "session",
//           SessionTTL:     24 * time.Hour,
//           CookieSecure:   false, // true in production (HTTPS)
//           CookieHTTPOnly: true,
//           CookieSameSite: http.SameSiteLaxMode,
//           BcryptCost:     12,
//         })
//         if err != nil {
//           log.Fatal(err)
//         }
//         defer api.Close()
//
//         mux := http.NewServeMux()
//
//         mux.HandleFunc("/register", func(w http.ResponseWriter, r *http.Request) {
//           if r.Method != http.MethodPost {
//             http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
//             return
//           }
//           email := r.FormValue("email")
//           password := r.FormValue("password")
//           _, err := api.Register(r.Context(), email, password)
//           if err != nil {
//             http.Error(w, err.Error(), http.StatusBadRequest)
//             return
//           }
//           w.WriteHeader(http.StatusCreated)
//           _, _ = w.Write([]byte("registered"))
//         })
//
//         mux.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
//           if r.Method != http.MethodPost {
//             http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
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
//         mux.Handle("/me", api.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
//           user, ok := auth.FromContext(r.Context())
//           if !ok {
//             http.Error(w, "unauthenticated", http.StatusUnauthorized)
//             return
//           }
//           _, _ = w.Write([]byte("hello " + user.Email))
//         })))
//
//         mux.HandleFunc("/logout", func(w http.ResponseWriter, r *http.Request) {
//           if err := api.Logout(w, r); err != nil {
//             http.Error(w, err.Error(), http.StatusInternalServerError)
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
//
// Driver note:
//   - Uses github.com/mattn/go-sqlite3 (cgo). To use a pure-Go driver, replace
//     the side-effect import in store.go** with modernc.org/sqlite and keep code identical.
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
//   - func (*API) SetBcryptCost(cost int) error
package auth

import (
 "context"
 "net/http"
 "time"
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

 // CookieHTTPOnly controls HttpOnly on the cookie. Default: true.
 CookieHTTPOnly bool

 // CookieSameSite controls the SameSite attribute. Default: http.SameSiteLaxMode.
 CookieSameSite http.SameSite

 // BcryptCost controls password hashing difficulty (4..31). Typical: 10–14.
 // Default: bcrypt.DefaultCost.
 BcryptCost int

 // Now allows overriding the time source (useful in tests). Default: time.Now.
 Now func() time.Time
}

// API is the main entry point for authentication operations.
// It is safe to share a single instance across handlers.
type API struct {
 db  dbHandle
 cfg Config
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

// Close releases underlying resources (e.g., DB connections).
func (a *API) Close() error {
 return a.closeInternal()
}

// Register creates a new user with a bcrypt-hashed password.
// - Email is normalized to lower-case and trimmed.
// - Password must be at least 8 characters.
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

// SetBcryptCost allows changing the hashing cost at runtime for subsequent registrations.
// Existing password hashes remain valid.
func (a *API) SetBcryptCost(cost int) error {
 return a.setBcryptCostInternal(cost)
}