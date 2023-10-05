package authn

import (
	"context"
	"errors"

	"github.com/golang-jwt/jwt/v4"
	"github.com/rs/zerolog/log"

	"github.com/real-evolution/recloak"
)

// tokenContextKey is a context key for the token
type tokenContextKey struct{}

var (
	// TokenContextKey is a context key for the token
	TokenContextKey = tokenContextKey{}

	// ErrUnauthenticated is returned when the token is not found for a
	// context.
	ErrUnauthenticated = errors.New("unauthenticated")

	// ErrInvalidToken is returned when the token is invalid.
	ErrInvalidToken = errors.New("invalid token")
)

// Token is a type that represents a JWT token.
type Token struct {
	*jwt.Token

	Claims *Claims // Custom claims
}

// DecodeAccessToken decodes a bearer access token and returns a Token instance
func DecodeAccessToken(
	ctx context.Context,
	client *recloak.ReCloak,
	tokenString string,
) (Token, error) {
	if err := client.RefreshIfExpired(ctx); err != nil {
		return Token{}, err
	}

	claims := &Claims{}
	token, err := client.Client().DecodeAccessTokenCustomClaims(
		ctx,
		tokenString,
		client.Config().Realm,
		claims,
	)
	if err != nil {
		return Token{}, err
	}

	return Token{token, claims}, nil
}

// WrapContext wraps the claims in the context.
func (t Token) WrapContext(ctx context.Context) context.Context {
	return context.WithValue(ctx, TokenContextKey, t)
}

// TokenFromContext returns a token from the context
func TokenFromContext(ctx context.Context) (Token, error) {
	dynToken := ctx.Value(tokenContextKey{})
	if dynToken == nil {
		return Token{}, ErrUnauthenticated
	}

	token, ok := dynToken.(Token)
	if !ok || token.Token == nil || !token.Valid {
		return Token{}, ErrInvalidToken
	}

	return token, nil
}

// EnsureTokenFromContext returns a token from the context or panics
func EnsureTokenFromContext(ctx context.Context) Token {
	token, err := TokenFromContext(ctx)
	if err != nil {
		log.Panic().Err(err).Msg("could not get token from context")
	}

	return token
}
