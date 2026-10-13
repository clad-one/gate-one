package mcpserver

import (
	"context"
)

type UserContext struct {
	UserID   string
	Username string
	Email    string
	Roles    []string
}

type userContextKey struct{}

func WithUserContext(
	ctx context.Context,
	user UserContext,
) context.Context {

	return context.WithValue(
		ctx,
		userContextKey{},
		user,
	)
}

func GetUserContext(
	ctx context.Context,
) (UserContext, bool) {

	user, ok := ctx.Value(
		userContextKey{},
	).(UserContext)

	return user, ok
}
