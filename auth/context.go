package auth

import (
 "context"
)

type ctxKey string

var ctxUserKey ctxKey = "auth.user"

func fromContext(ctx context.Context) (User, bool) {
 u, ok := ctx.Value(ctxUserKey).(User)
 return u, ok
}

func withUser(ctx context.Context, u User) context.Context {
 return context.WithValue(ctx, ctxUserKey, u)
}