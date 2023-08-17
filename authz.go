package recloak

import (
	"context"

	"github.com/Nerzal/gocloak/v13"
)

var (
	// The `grant_type` for obtaining a UMA 2 AuthZ ticket from the token endpoint.
	umaTicketGrantType = "urn:ietf:params:oauth:grant-type:uma-ticket"

	// Whether to include the resource name in permission requests' responses.
	includeResourceName = true
)

// Checks whether the given `token` can is granted the given `permissions`.
func (c *Client) CheckAccess(ctx context.Context, rpt *string, permissions ...string) error {
	if err := c.RefreshIfExpired(ctx); err != nil {
		return err
	}

	result, err := c.inner.GetRequestingPartyPermissionDecision(
		ctx,
		c.token.AccessToken,
		c.realm,
		gocloak.RequestingPartyTokenOptions{
			GrantType:   &umaTicketGrantType,
			Audience:    &c.clientID,
			RPT:         rpt,
			Permissions: &permissions,
		},
	)
	if err != nil {
		return err
	}

	if !*result.Result {
		panic("invalid server response")
	}

	return nil
}
