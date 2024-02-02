package recloak

import (
	"context"
	"errors"
	"slices"

	"github.com/golang-jwt/jwt/v5"
	"github.com/rs/zerolog/log"
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

// RolesClaim is a type that represents the roles claim of a JWT token
type RolesClaim struct {
	Roles []string `json:"roles"`
}

// Claims is a type that represents the claims of a JWT token
type Claims struct {
	jwt.RegisteredClaims

	// Custom claims
	PreferredUsername string                `json:"preferred_username"`
	RealmAcess        RolesClaim            `json:"realm_access,omitempty"`
	ResourceAcess     map[string]RolesClaim `json:"resource_access,omitempty"`
}

// DecodeAccessToken decodes a bearer access token and returns a Token instance
func (c *ReCloak) DecodeAccessToken(
	ctx context.Context,
	tokenString string,
) (Token, error) {
	if err := c.RefreshIfExpired(ctx); err != nil {
		return Token{}, err
	}

	claims := &Claims{}
	token, err := c.Client().DecodeAccessTokenCustomClaims(
		ctx,
		tokenString,
		c.config.Realm,
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

// ClaimsFromContext extracts the claims from the context.
func ClaimsFromContext(ctx context.Context) (*Claims, error) {
	token, err := TokenFromContext(ctx)
	if err != nil {
		return nil, err
	}

	return token.Claims, nil
}

// EnsureClaimsFromContext extracts the claims from the context or panics.
func EnsureClaimsFromContext(ctx context.Context) *Claims {
	return EnsureTokenFromContext(ctx).Claims
}

// HasRole checks if the user has the given role.
func (c RolesClaim) HasRole(role string) bool {
	idx := slices.Index(c.Roles, role)

	return idx != -1
}

func (c *Claims) GetExpirationTime() (*jwt.NumericDate, error) {
  return c.ExpiresAt, nil
}

func (c *Claims) GetIssuedAt() (*jwt.NumericDate, error) {
  return c.IssuedAt, nil
}

func (c *Claims) GetNotBefore() (*jwt.NumericDate, error) {
  return c.NotBefore, nil
}

func (c *Claims) GetIssuer() (string, error) {
  return c.Issuer, nil
}

func (c *Claims) GetSubject() (string, error) {
  return c.Subject, nil
}

func (c *Claims) GetAudience() (jwt.ClaimStrings, error) {
  return c.Audience, nil
}
