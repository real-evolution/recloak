package recloak

import (
	"context"

	"github.com/Nerzal/gocloak/v13"
	"github.com/rs/zerolog/log"
)

// Performs a user login with the given `username` and `password` using the client credentials and returns the
// resulting JWT.
func (c *Client) Login(
	ctx context.Context,
	username, password string,
) (*gocloak.JWT, error) {
	return c.inner.Login(ctx, c.ClientID, c.clientSecret, c.Realm, username, password)
}

// Introspects the given `token` and returns the introspection result.
func (c *Client) Introspect(
	ctx context.Context,
	token string,
) (*gocloak.IntroSpectTokenResult, error) {
	if err := c.RefreshIfExpired(ctx); err != nil {
		return nil, err
	}

	return c.inner.RetrospectToken(
		ctx,
		token,
		c.ClientID,
		c.clientSecret,
		c.Realm,
	)
}

// Refreshes the client token if necessary.
//
//   - If `force` is `true`, the token will be refreshed regardless of its
//     expiration status.
//
//   - If `force` is `false`, the token will only be refreshed if it does not
//     exist (first time) or is expired.
func (c *Client) Refresh(ctx context.Context, force bool) error {
	if c.token != nil {
		if !isTimestampExpired(int64(c.token.ExpiresIn)) && !force {
			return nil
		}

		log.Debug().
			Str("clientId", c.ClientID).
			Msg("access token is expired, refreshing using refresh token")

		if !isTimestampExpired(int64(c.token.RefreshExpiresIn)) {
			log.Debug().
				Str("clientId", c.ClientID).
				Bool("force", force).
				Msg("refrshing access token")

			token, err := c.inner.RefreshToken(
				ctx,
				c.token.RefreshToken,
				c.ClientID,
				c.clientSecret,
				c.Realm,
			)
			if err != nil {
				return err
			}

			c.token = token
			return nil
		}

		log.Debug().
			Str("clientId", c.ClientID).
			Bool("force", force).
			Msg("refresh token is expired, logging in")
	}

	log.Info().
		Str("clientId", c.ClientID).
		Msg("logging in to keycloak to acquire a new token pair")

	token, err := c.inner.LoginClient(ctx, c.ClientID, c.clientSecret, c.Realm)
	if err != nil {
		return err
	}

	c.token = token
	return nil
}

// Refreshes the access token of the client if it is expired.
//
// This method logs the client in if it has not been logged in before.
func (c *Client) RefreshIfExpired(ctx context.Context) error {
	return c.Refresh(ctx, false)
}

// Refreshes the access token will be refreshed regardless of its expiration status.
func (c *Client) RefreshNow(ctx context.Context) error {
	return c.Refresh(ctx, true)
}
