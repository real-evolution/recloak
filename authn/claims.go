package authn

import (
	"context"
	"slices"

	"github.com/golang-jwt/jwt/v4"
)

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

// ClaimsFromContext extracts the claims from the context.
func ClaimsFromContext(ctx context.Context) (*Claims, error) {
	token, err := TokenFromContext(ctx)
	if err != nil {
		return nil, err
	}

	return token.Claims, nil
}

// EnsureClaimsFromContext extracts the claims from the context and panics if they are not found.
func EnsureClaimsFromContext(ctx context.Context) *Claims {
	token := EnsureTokenFromContext(ctx)
	return token.Claims
}

// HasRole checks if the user has the given role.
func (c *RolesClaim) HasRole(role string) bool {
	idx := slices.Index(c.Roles, role)

	return idx != -1
}
