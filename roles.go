package recloak

import (
	"context"

	"github.com/Nerzal/gocloak/v13"
	"github.com/rs/zerolog/log"
)

// Role is a wrapper around `gocloak.Role`, adding convenience methods.
type Role = gocloak.Role

// Roles is a wrapper around `[]*AuthRole`, adding convenience methods.
type Roles []*Role

// Gets the roles corresponding to the given `names`.
func (c *Client) GetClientRolesByName(
	ctx context.Context,
	accessToken string,
	roleNames ...string,
) (Roles, error) {
	if err := c.RefreshIfExpired(ctx); err != nil {
		return nil, err
	}

	log.Debug().
		Strs("roles", roleNames).
		Msg("getting client roles by name")

	roles := make([]*Role, len(roleNames))

	for i, name := range roleNames {
		if role, ok := c.rolesCache[name]; ok {
			roles[i] = role
		} else {
			role, err := c.inner.GetClientRole(ctx, accessToken, c.Realm, c.IDOfClient, name)
			if err != nil {
				return nil, err
			}

			c.rolesCache[name] = role

			roles[i] = role
		}
	}

	return roles, nil
}

// Gets client roles for the given `userID`.
func (c *Client) GetClientRolesByUserID(
	ctx context.Context,
	accessToken string,
	userID string,
) (Roles, error) {
	if err := c.RefreshIfExpired(ctx); err != nil {
		return nil, err
	}

	log.Debug().
		Str("userId", userID).
		Msg("getting client roles by user id")

	roles, err := c.inner.GetClientRolesByUserID(
		ctx,
		accessToken,
		c.Realm,
		c.IDOfClient,
		userID,
	)
	if err != nil {
		return nil, err
	}

	c.cacheRoles(roles...)

	return Roles(roles), err
}

// Gets client roles for the given `userID`.
func (c *Client) AddClientRolesToUser(
	ctx context.Context,
	accessToken string,
	userID string,
	roleNames ...string,
) error {
	log.Info().
		Str("userId", userID).
		Strs("roles", roleNames).
		Msg("adding client roles to user")

	roles, err := c.GetClientRolesByName(ctx, accessToken, roleNames...)
	if err != nil {
		return err
	}

	return c.inner.AddClientRolesToUser(
		ctx,
		accessToken,
		c.Realm,
		c.IDOfClient,
		userID,
		roles.Owned(),
	)
}

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

// Cache the given `roles` localy.
func (c *Client) cacheRoles(roles ...*Role) {
	if c.rolesCache == nil {
		c.rolesCache = make(map[string]*Role, len(roles))
	}

	for _, role := range roles {
		c.rolesCache[*role.Name] = role
	}
}
