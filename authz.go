package recloak

import (
	"context"

	"github.com/Nerzal/gocloak/v13"
	"github.com/rs/zerolog/log"
)

var (
	// The `grant_type` for obtaining a UMA 2 AuthZ ticket from the token endpoint.
	umaTicketGrantType = "urn:ietf:params:oauth:grant-type:uma-ticket"

	// Whether to include the resource name in permission requests' responses.
	includeResourceName = true
)

// Checks whether the given `token` can is granted the given `permissions`.
func (c *Client) CheckAccess(
	ctx context.Context,
	rpt *string,
	permissions ...string,
) error {
	if err := c.RefreshIfExpired(ctx); err != nil {
		return err
	}

	log.Debug().
		Str("clientId", c.ClientID).
		Strs("permissions", permissions).
		Msg("checking access")

	result, err := c.inner.GetRequestingPartyPermissionDecision(
		ctx,
		c.token.AccessToken,
		c.Realm,
		gocloak.RequestingPartyTokenOptions{
			GrantType:   &umaTicketGrantType,
			Audience:    &c.ClientID,
			RPT:         rpt,
			Permissions: &permissions,
		},
	)
	if err != nil {
		return err
	}

	if !*result.Result {
		log.Panic().
			Str("clientId", c.ClientID).
			Msg("invalid server response (got false)")
	}

	return nil
}
