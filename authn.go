package recloak

import (
	"context"

	"github.com/Nerzal/gocloak/v13"
)

// Introspects the given `token` and returns the introspection result.
func (c *Client) Introspect(
	ctx context.Context,
	token string,
) (*gocloak.IntroSpectTokenResult, error) {
	return c.inner.RetrospectToken(
		ctx,
		token,
		c.clientID,
		c.clientSecret,
		c.realm,
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
		if !force && !isTimestampExpired(int64(c.token.ExpiresIn)) {
			return nil
		}

		if !isTimestampExpired(int64(c.token.RefreshExpiresIn)) {
			token, err := c.inner.RefreshToken(
				ctx,
				c.token.RefreshToken,
				c.clientID,
				c.clientSecret,
				c.realm,
			)
			if err != nil {
				return err
			}

			c.token = token
			return err
		}
	}

	token, err := c.inner.LoginClient(ctx, c.clientID, c.clientSecret, c.realm)
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
