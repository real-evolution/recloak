package recloak

import (
	"github.com/Nerzal/gocloak/v13"
)

// Role is a wrapper around `gocloak.Role`, adding convenience methods.
type Role = gocloak.Role

// Roles is a wrapper around `[]*AuthRole`, adding convenience methods.
type Roles []*Role

// Checks whether the token has the given realm `role`.
func (r Roles) Contains(role string) bool {
	return r.Get(role) != nil
}

// Gets the role with the given name from the token.
func (r Roles) Get(role string) *Role {
	for _, r := range r {
		if *r.Name == role {
			return r
		}
	}

	return nil
}

// Gets the roles with the given names from the token.
func (r Roles) GetMany(roles ...string) Roles {
	var ret []*Role

	for _, role := range roles {
		if r := r.Get(role); r != nil {
			ret = append(ret, r)
		}
	}

	return ret
}

// Checks whether the token has all of the given realm `roles`.
func (r Roles) ContainsAll(roles ...string) bool {
	for _, role := range roles {
		if !r.Contains(role) {
			return false
		}
	}

	return true
}

// Checks whether the token has any of the given realm `roles`.
func (r Roles) ContainsAny(roles ...string) bool {
	for _, role := range roles {
		if r.Contains(role) {
			return true
		}
	}

	return false
}

// Returns the underlying `gocloak.Role` slice.
func (r Roles) AsInner() []*Role {
	return r
}

// Returns an owned copy of the underlying `gocloak.Role` slice.
func (r Roles) Owned() []Role {
	owned := make([]Role, 0, len(r))

	for _, role := range r {
		owned = append(owned, *role)
	}

	return owned
}
