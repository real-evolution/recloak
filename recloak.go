package recloak

import (
	"context"

	"github.com/Nerzal/gocloak/v13"
	"github.com/eko/gocache/lib/v4/cache"
	"github.com/golang-jwt/jwt/v4"
	"github.com/rs/zerolog/log"
)

// A type wrapping `gocloak` client to provide a more convenient API.
type Client struct {
	inner        *gocloak.GoCloak // wrapped gocloak client
	keycloakURL  string           // URL of the keycloak server
	clientSecret string           // the secret of the client
	token        *gocloak.JWT     // current client token state
	permsCache   *cache.Cache[*gocloak.RequestingPartyPermission]
	Realm         string // the id of the realm keycloak realm
	ClientID      string // the human-readable id of the client
}

// Create a new `Client` with the given `basePath`.
func NewClient(keycloakURL, realm, clientID, clientSecret string) *Client {
	inner := gocloak.NewClient(keycloakURL)

	return &Client{
		inner:        inner,
		keycloakURL:  keycloakURL,
		realm:        realm,
		clientID:     clientID,
		clientSecret: clientSecret,
		token:        nil,
	}
}

// Decode the given `accessToken` and return the resulting token.
func (c *Client) DecodeAccessToken(
	ctx context.Context,
	accessToken string,
) (*jwt.Token, error) {
	return c.inner.DecodeAccessTokenCustomClaims(
		ctx,
		accessToken,
		c.realm,
		&jwt.RegisteredClaims{},
	)
}

// Gets a user by identifier from the keycloak server.
func (c *Client) GetUserByID(
	ctx context.Context,
	userID string,
) (*gocloak.User, error) {
	if err := c.RefreshIfExpired(ctx); err != nil {
		return nil, err
	}

	return c.inner.GetUserByID(ctx, c.token.AccessToken, c.realm, userID)
}

// Gets client roles for the given `userID`.
func (c *Client) GetUserClientRoles(
	ctx context.Context,
	userID string,
) ([]*gocloak.Role, error) {
	if err := c.RefreshIfExpired(ctx); err != nil {
		return nil, err
	}

	log.Info().Str("clietId", c.clientID).Msg("getting client roles")

	return c.inner.GetClientRolesByUserID(
		ctx,
		c.token.AccessToken,
		c.realm,
		c.clientID,
		userID,
	)
}
