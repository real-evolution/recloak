package recloak

import (
	"context"

	"github.com/Nerzal/gocloak/v13"
	"github.com/eko/gocache/lib/v4/cache"
	"github.com/rs/zerolog/log"
)

// A type wrapping `gocloak` client to provide a more convenient API.
type Client struct {
	inner *gocloak.GoCloak // wrapped gocloak client

	AuthServerURL string // URL of the keycloak server
	Realm         string // the id of the realm keycloak realm
	IDOfClient    string // the internal id of the client
	ClientID      string // the human-readable id of the client
	clientSecret  string // the secret of the client

	permsCache *cache.Cache[*gocloak.RequestingPartyPermission]
	token      *gocloak.JWT     // current client token state
	clientRepr *gocloak.Client  // the client representation
	rolesCache map[string]*Role // cache of roles by name
}

// Create a new `Client` with the given `basePath`.
func NewClient(keycloakURL, realm, idOfClient, clientID, clientSecret string) *Client {
	inner := gocloak.NewClient(keycloakURL)

	return &Client{
		inner:         inner,
		AuthServerURL: keycloakURL,
		Realm:         realm,
		IDOfClient:    idOfClient,
		ClientID:      clientID,
		clientSecret:  clientSecret,
	}
}

// Gets a user by identifier from the keycloak server.
func (c *Client) GetUserByID(
	ctx context.Context,
	userID string,
) (*gocloak.User, error) {
	if err := c.RefreshIfExpired(ctx); err != nil {
		return nil, err
	}

	return c.inner.GetUserByID(ctx, c.token.AccessToken, c.Realm, userID)
}

// Gets client roles for the given `userID`.
func (c *Client) GetClientRolesByUserID(
	ctx context.Context,
	accessToken string,
	userID string,
) (Roles, error) {
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

func (c *Client) GetRepresentation(
	ctx context.Context,
	forceUpdate bool,
) (*gocloak.Client, error) {
	if c.clientRepr != nil && !forceUpdate {
		return c.clientRepr, nil
	}

	log.Debug().
		Bool("forceUpdate", forceUpdate).
		Msg("getting client representation")

	if err := c.RefreshIfExpired(ctx); err != nil {
		return nil, err
	}

	client, err := c.inner.GetClientRepresentation(
		ctx,
		c.token.AccessToken,
		c.Realm,
		c.ClientID,
	)
	if err != nil {
		return nil, err
	}

	c.clientRepr = client

	return client, nil
}

// Gets the roles corresponding to the given `names`.
func (c *Client) GetClientRolesByName(
	ctx context.Context,
	accessToken string,
	roleNames ...string,
) (Roles, error) {
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

// Cache the given `roles` localy.
func (c *Client) cacheRoles(roles ...*Role) {
	if c.rolesCache == nil {
		c.rolesCache = make(map[string]*Role, len(roles))
	}

	for _, role := range roles {
		c.rolesCache[*role.Name] = role
	}
}
