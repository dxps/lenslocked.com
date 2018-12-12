package context

import (
	"context"

	"lenslocked.com/models/users"
)

type privateKey string

const (
	userKey privateKey = "user"
)

func WithUser(ctx context.Context, user *users.User) context.Context {
	return context.WithValue(ctx, userKey, user)
}

func User(ctx context.Context) *users.User {
	if temp := ctx.Value(userKey); temp != nil {
		if user, ok := temp.(*users.User); ok {
			return user
		}
	}
	return nil
}
