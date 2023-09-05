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
	ClientID      string // the human-readable id of the client
	clientSecret  string // the secret of the client

	permsCache *cache.Cache[*gocloak.RequestingPartyPermission]
	token      *gocloak.JWT     // current client token state
	clientRepr *gocloak.Client  // the client representation
	rolesCache map[string]*Role // cache of roles by name
}

// Create a new `Client` with the given `basePath`.
func NewClient(keycloakURL, realm, clientID, clientSecret string) *Client {
	inner := gocloak.NewClient(keycloakURL)

	return &Client{
		inner:         inner,
		AuthServerURL: keycloakURL,
		Realm:         realm,
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

// Gets client representation from the keycloak server.
func (c *Client) GetRepresentation(
	ctx context.Context,
	accessToken string,
	forceUpdate bool,
) (*gocloak.Client, error) {
	if err := c.RefreshIfExpired(ctx); err != nil {
		return nil, err
	}

	log.Debug().
		Bool("forceUpdate", forceUpdate).
		Msg("getting client representation")

	if c.clientRepr != nil && !forceUpdate {
		return c.clientRepr, nil
	}

	client, err := c.inner.GetClientRepresentation(
		ctx,
		accessToken,
		c.Realm,
		c.ClientID,
	)
	if err != nil {
		return nil, err
	}

	c.clientRepr = client

	return client, nil
}
