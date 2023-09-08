package recloak

import (
	"context"
	"encoding/base64"
	"encoding/json"

	"github.com/Nerzal/gocloak/v13"
	"github.com/rs/zerolog/log"
)

var (
	// The `grant_type` for obtaining a UMA 2 AuthZ ticket from the token endpoint.
	umaTicketGrantType = "urn:ietf:params:oauth:grant-type:uma-ticket"

	// The `claim_token_format` for the UMA 2 AuthZ ticket.
	ClaimTokenFormat = "urn:ietf:params:oauth:token-type:jwt"

	// Whether to include the resource name in permission requests' responses.
	includeResourceName = true
)

type CheckAccessParams struct {
	AccessToken *string
	Permissions []string
	Claims      map[string]interface{}
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
		Any("claims", params.Claims).
		Strs("permissions", params.Permissions).
		Msg("checking access")

	opts := gocloak.RequestingPartyTokenOptions{
		GrantType:   &umaTicketGrantType,
		Audience:    &c.ClientID,
		Permissions: &params.Permissions,
	}

	if params.Claims != nil && len(params.Claims) > 0 {
		claimJSON, err := json.Marshal(params.Claims)
		if err != nil {
			return err
		}

		claimToken := base64.RawStdEncoding.EncodeToString([]byte(claimJSON))

		opts.ClaimToken = &claimToken
		opts.ClaimTokenFormat = &ClaimTokenFormat
	}

	result, err := c.inner.GetRequestingPartyPermissionDecision(
		ctx,
		*params.AccessToken,
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
