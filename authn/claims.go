package authn

import (
	"context"
	"log"
	"slices"

	"github.com/golang-jwt/jwt/v4"
)

// ClaimsContextKey is the key used to store the claims in the context
type claimsContextKey struct{}

// ClaimsContextKey is the key used to store the claims in the context
var ClaimsContextKey = claimsContextKey{}

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

// WrapContext wraps the claims in the context.
func (c *Claims) WrapContext(ctx context.Context) context.Context {
	return context.WithValue(ctx, ClaimsContextKey, c)
}

// ClaimsFromContext extracts the claims from the context.
func ClaimsFromContext(ctx context.Context) (*Claims, bool) {
	claims, ok := ctx.Value(ClaimsContextKey).(*Claims)
	return claims, ok
}

// EnsureClaimsFromContext extracts the claims from the context and panics if they are not found.
func EnsureClaimsFromContext(ctx context.Context) *Claims {
	claims, ok := ClaimsFromContext(ctx)

	if !ok {
		log.Panic("claims not found in context")
	}

	return claims
}

// InRealmRole checks if the user has the given role in the realm.
func (c *Claims) InRealmRole(role string) bool {
	return c.RealmAcess.HasRole(role)
}

// InClientRole checks if the user has the given role for the given client.
func (c *Claims) InClientRole(client, role string) bool {
	clientRoles, ok := c.ResourceAcess[client]

	return ok && clientRoles.HasRole(role)
}

// HasRole checks if the user has the given role.
func (c *RolesClaim) HasRole(role string) bool {
	idx := slices.Index(c.Roles, role)

	return idx != -1
}
