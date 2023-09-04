package recloak

import (
	"github.com/Nerzal/gocloak/v13"
)

// AuthRole is a wrapper around `gocloak.Role`, adding convenience methods.
type AuthRole = gocloak.Role

// AuthRoles is a wrapper around `[]*AuthRole`, adding convenience methods.
type AuthRoles []*AuthRole

// Checks whether the token has the given realm `role`.
func (r AuthRoles) Contains(role string) bool {
	return r.Get(role) != nil
}

// Gets the role with the given name from the token.
func (r AuthRoles) Get(role string) *AuthRole {
	for _, r := range r {
		if *r.Name == role {
			return r
		}
	}

	return nil
}

// Gets the roles with the given names from the token.
func (r AuthRoles) GetMany(roles ...string) AuthRoles {
	var ret []*AuthRole

	for _, role := range roles {
		if r := r.Get(role); r != nil {
			ret = append(ret, r)
		}
	}

	return ret
}

// Checks whether the token has all of the given realm `roles`.
func (r AuthRoles) ContainsAll(roles ...string) bool {
	for _, role := range roles {
		if !r.Contains(role) {
			return false
		}
	}

	return true
}

// Checks whether the token has any of the given realm `roles`.
func (r AuthRoles) ContainsAny(roles ...string) bool {
	for _, role := range roles {
		if r.Contains(role) {
			return true
		}
	}

	return false
}

// Returns the underlying `gocloak.Role` slice.
func (r AuthRoles) AsInner() []*AuthRole {
	return r
}

// Returns an owned copy of the underlying `gocloak.Role` slice.
func (r AuthRoles) Owned() []AuthRole {
	owned := make([]AuthRole, 0, len(r))

	for _, role := range r {
		owned = append(owned, *role)
	}

	return owned
}
