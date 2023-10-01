package recloak

import (
	"context"
	"log"

	"github.com/golang-jwt/jwt/v4"
)

// ContextKey is the type used to store values in the context.
type ContextKey string

const (
	// AuthTokenKey is the key used to store the JWT token in the context.
	AuthTokenKey ContextKey = "authToken"
)

// AuthClaims is a wrapper around `jwt.RegisteredClaims`, adding Keycloak
// specific claims, namely `realm_access` and `resource_access`.
type AuthClaims struct {
	jwt.RegisteredClaims

	PreferredUsername string `json:"preferred_username,omitempty"`

	RealmAccess struct {
		Roles []string `json:"roles,omitempty"`
	} `json:"realm_access,omitempty"`

	ResourceAccess map[string]struct {
		Roles []string `json:"roles,omitempty"`
	} `json:"resource_access,omitempty"`
}

// AuthToken is a wrapper around `jwt.Token` and `jwt.RegisteredClaims`.
type AuthToken struct {
	Token  *jwt.Token
	Claims *AuthClaims
	Header string
}

// Decode the given `accessToken` and return the resulting token.
func (c *Client) DecodeAccessToken(
	ctx context.Context,
	accessTokenHeader string,
) (AuthToken, error) {
	claims := &AuthClaims{}
	token, err := c.inner.DecodeAccessTokenCustomClaims(
		ctx,
		accessTokenHeader,
		c.Realm,
		claims,
	)

	return AuthToken{token, claims, accessTokenHeader}, err
}

// Raw returns the raw token string.
func (t AuthToken) String() string {
	return t.Token.Raw
}

// Checks whether the token has the given realm `role`.
func (t AuthToken) HasRealmRole(role string) bool {
	return arrayContains(t.Claims.RealmAccess.Roles, role)
}

// Checks whether the claims has the given realm `role`.
func (c AuthClaims) HasRealmRole(role string) bool {
	return arrayContains(c.RealmAccess.Roles, role)
}

// Checks whether the token has all of the given realm `roles`.
func (t AuthToken) HasAllRealmRoles(roles ...string) bool {
	return arrayContainsAll(t.Claims.RealmAccess.Roles, roles)
}

// Checks whether the token has any of the given realm `roles`.
func (t AuthToken) HasAnyRealmRole(roles ...string) bool {
	return arrayContainsAny(t.Claims.RealmAccess.Roles, roles)
}

// Checks whether the token has the given client `role`.
func (t AuthToken) HasClientRole(client, role string) bool {
	if clientRoles, ok := t.Claims.ResourceAccess[client]; ok {
		return arrayContains(clientRoles.Roles, role)
	}

	return false
}

// Checks whether the token has the given client `role`.
func (c AuthClaims) HasClientRole(client, role string) bool {
	if clientRoles, ok := c.ResourceAccess[client]; ok {
		return arrayContains(clientRoles.Roles, role)
	}

	return false
}

// Checks whether the token has all of the given client `roles`.
func (t AuthToken) HasAllClientRoles(client string, roles ...string) bool {
	if clientRoles, ok := t.Claims.ResourceAccess[client]; ok {
		return arrayContainsAll(clientRoles.Roles, roles)
	}

	return false
}

// Checks whether the token has any of the given client `roles`.
func (t AuthToken) HasAnyClientRole(client string, roles ...string) bool {
	if clientRoles, ok := t.Claims.ResourceAccess[client]; ok {
		return arrayContainsAny(clientRoles.Roles, roles)
	}

	return false
}

// WrapContext wraps the given context with the token.
func (t AuthToken) WrapContext(ctx context.Context) context.Context {
	return context.WithValue(ctx, AuthTokenKey, t)
}

// NewAuthTokenFromContext returns the token from the given context.
func NewAuthTokenFromContext(ctx context.Context) (AuthToken, bool) {
	token, ok := ctx.Value(AuthTokenKey).(AuthToken)

	return token, ok
}

func EnsureTokenFromContext(ctx context.Context) AuthToken {
	token, ok := NewAuthTokenFromContext(ctx)
	if !ok {
		log.Panic("no token found in context")
	}

	return token
}
