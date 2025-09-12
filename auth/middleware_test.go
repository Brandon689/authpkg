package auth

import (
 "context"
 "net/http"
 "net/http/httptest"
 "strings"
 "testing"
)

func TestMiddlewareInjectsUser(t *testing.T) {
 api, cleanup := newTestAPI(t)
 defer cleanup()

 ctx := context.Background()
 if _, err := api.Register(ctx, "mw@example.com", "password123"); err != nil {
  t.Fatalf("register: %v", err)
 }
 c := mustLogin(t, api, "mw@example.com", "password123")

 mux := http.NewServeMux()
 mux.Handle("/me", api.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
  u, ok := FromContext(r.Context())
  if !ok {
   http.Error(w, "no user", http.StatusUnauthorized)
   return
  }
  w.WriteHeader(http.StatusOK)
  _, _ = w.Write([]byte(u.Email))
 })))

 w := httptest.NewRecorder()
 r := newReqWithCookie(http.MethodGet, "/me", c)
 mux.ServeHTTP(w, r)

 if w.Code != http.StatusOK {
  t.Fatalf("status: %d", w.Code)
 }
 if !strings.Contains(w.Body.String(), "mw@example.com") {
  t.Fatalf("expected email in body, got %q", w.Body.String())
 }
}

func TestRequireAuth(t *testing.T) {
 api, cleanup := newTestAPI(t)
 defer cleanup()

 protected := api.RequireAuth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
  w.WriteHeader(http.StatusOK)
 }))

 // Without user in context -> 401
 w1 := httptest.NewRecorder()
 r1 := httptest.NewRequest(http.MethodGet, "/protected", nil)
 protected.ServeHTTP(w1, r1)
 if w1.Code != http.StatusUnauthorized {
  t.Fatalf("expected 401, got %d", w1.Code)
 }

 // With user in context (simulate Middleware result)
 w2 := httptest.NewRecorder()
 r2 := httptest.NewRequest(http.MethodGet, "/protected", nil)
 r2 = r2.WithContext(withUser(r2.Context(), User{ID: 1, Email: "x@y.z"}))
 protected.ServeHTTP(w2, r2)
 if w2.Code != http.StatusOK {
  t.Fatalf("expected 200, got %d", w2.Code)
 }
}