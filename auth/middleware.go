package auth

import (
  "net/http"
)

func (a *API) middlewareInternal(next http.Handler) http.Handler {
  return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
    user, ok, err := a.currentUserInternal(w, r)
    if err != nil {
      a.logf("currentUser error: %v", err)
      http.Error(w, "internal error", http.StatusInternalServerError)
      return
    }
    if ok {
      next.ServeHTTP(w, r.WithContext(withUser(r.Context(), user)))
      return
    }
    next.ServeHTTP(w, r)
  })
}

func (a *API) requireAuthInternal(next http.Handler) http.Handler {
 return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
  if _, ok := fromContext(r.Context()); !ok {
   http.Error(w, "unauthorized", http.StatusUnauthorized)
   return
  }
  next.ServeHTTP(w, r)
 })
}