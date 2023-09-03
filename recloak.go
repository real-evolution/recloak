package recloak

import (
	"context"

	"github.com/Nerzal/gocloak/v13"
	"github.com/eko/gocache/lib/v4/cache"
	"github.com/golang-jwt/jwt/v4"
)

// A type wrapping `gocloak` client to provide a more convenient API.
type Client struct {
	inner        *gocloak.GoCloak // wrapped gocloak client
	keycloakURL  string           // URL of the keycloak server
	realm        string           // the id of the realm keycloak realm
	clientID     string           // the id of the client
	clientSecret string           // the secret of the client
	token        *gocloak.JWT     // current client token state
	permsCache   *cache.Cache[*gocloak.RequestingPartyPermission]
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
