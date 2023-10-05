package admin

import (
	"context"
	"errors"
	"net/http"

	"github.com/Nerzal/gocloak/v13"

	"github.com/real-evolution/recloak"
)

// ErrUserNotInRole is returned when an operation is attempted on a user that
// is not in the role.
var ErrUserNotInRole = errors.New("user is not in role")

// Role is a wrapper around `gocloak.Role`, adding convenience methods.
type Role = gocloak.Role

// Roles is a slice of Role pointers.
type Roles []*Role

// RolesManager is a type that provides role management capabilities.
type ClientRolesManager struct {
	client     *recloak.ReCloak
	rolesCache map[string]*Role
}

// NewClientRolesManager creates a new ClientRolesManager instance.
func NewClientRolesManager(client *recloak.ReCloak) *ClientRolesManager {
	return &ClientRolesManager{
		client:     client,
		rolesCache: make(map[string]*Role),
	}
}

// GetRolesByName returns a list of client roles by their names.
func (m *ClientRolesManager) GetRolesByName(
	ctx context.Context,
	roleNames ...string,
) (Roles, error) {
	token, repr, err := m.getTokenAndRepresentation(ctx)
	if err != nil {
		return nil, err
	}

	roles := make([]*Role, len(roleNames))
	for i, roleName := range roleNames {
		if role, ok := m.rolesCache[roleName]; ok {
			roles[i] = role
			continue
		}

		role, err := m.client.Client().GetClientRole(
			ctx,
			token.Raw,
			m.client.Config().Realm,
			*repr.ID,
			roleName,
		)
		if err != nil {
			return nil, err
		}

		m.rolesCache[roleName] = role
		roles[i] = role
	}

	return roles, nil
}

// GetUserRoles returns a list of client roles by user ID.
func (m *ClientRolesManager) GetUserRoles(
	ctx context.Context,
	userID string,
) ([]*Role, error) {
	token, repr, err := m.getTokenAndRepresentation(ctx)
	if err != nil {
		return nil, err
	}

	roles, err := m.client.Client().GetClientRolesByUserID(
		ctx,
		token.Raw,
		m.client.Config().Realm,
		*repr.ID,
		userID,
	)
	if err != nil {
		return nil, err
	}

	for _, role := range roles {
		m.rolesCache[*role.Name] = role
	}

	return roles, nil
}

// AddRolesToUser adds roles to a user.
func (m *ClientRolesManager) AddRolesToUser(
	ctx context.Context,
	userID string,
	roleNames ...string,
) error {
	token, repr, err := m.getTokenAndRepresentation(ctx)
	if err != nil {
		return err
	}

	roles, err := m.GetRolesByName(ctx, roleNames...)
	if err != nil {
		return err
	}

	return m.client.Client().AddClientRolesToUser(
		ctx,
		token.Raw,
		m.client.Config().Realm,
		*repr.ID,
		userID,
		roles.owned(),
	)
}

// RemoveRolesFromUser removes roles from a user.
func (m *ClientRolesManager) RemoveRolesFromUser(
	ctx context.Context,
	userID string,
	roleNames ...string,
) error {
	token, repr, err := m.getTokenAndRepresentation(ctx)
	if err != nil {
		return err
	}

	roles, err := m.GetRolesByName(ctx, roleNames...)
	if err != nil {
		var kcErr *gocloak.APIError
		if errors.As(err, &kcErr) && kcErr.Code == http.StatusNotFound {
			return ErrUserNotInRole
		}

		return err
	}

	return m.client.Client().DeleteClientRolesFromUser(
		ctx,
		token.Raw,
		m.client.Config().Realm,
		*repr.ID,
		userID,
		roles.owned(),
	)
}

// ContainsRole checks if the user has the given role in the client.
func (m *ClientRolesManager) ContainsRole(claims *recloak.Claims, role string) bool {
	return claims.ResourceAcess[m.client.Config().ClientID].HasRole(role)
}

func (m *ClientRolesManager) getTokenAndRepresentation(
	ctx context.Context,
) (recloak.Token, *gocloak.Client, error) {
	token, err := recloak.TokenFromContext(ctx)
	if err != nil {
		return recloak.Token{}, nil, err
	}

	repr, err := m.client.GetRepresentation(ctx)
	if err != nil {
		return recloak.Token{}, nil, err
	}

	return token, repr, nil
}

// Returns an owned copy of the underlying `gocloak.Role` slice.
func (r Roles) owned() []Role {
	owned := make([]Role, 0, len(r))

	for _, role := range r {
		owned = append(owned, *role)
	}

	return owned
}
