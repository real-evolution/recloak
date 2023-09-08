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

type CheckAccessParams struct {
	AccessToken *string
	Permissions []string
}

// Checks whether the given `token` can is granted the given `permissions`.
func (c *Client) CheckAccess(
	ctx context.Context,
	params CheckAccessParams,
) error {
	if err := c.RefreshIfExpired(ctx); err != nil {
		return err
	}

	log.Debug().
		Str("clientId", c.ClientID).
		Strs("permissions", params.Permissions).
		Msg("checking access")

	opts := gocloak.RequestingPartyTokenOptions{
		GrantType:   &umaTicketGrantType,
		Audience:    &c.ClientID,
		Permissions: &params.Permissions,
	}
	result, err := c.inner.GetRequestingPartyPermissionDecision(
		ctx,
		c.token.AccessToken,
		c.Realm,
		opts,
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
