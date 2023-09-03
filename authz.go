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
		Str("clientId", c.clientID).
		Strs("permissions", permissions).
		Msg("checking access")

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
		log.Panic().
			Str("clientId", c.clientID).
			Msg("invalid server response (got false)")
	}

	return nil
}

// Checks whether the user with the given `userID` has all of the given `roles`.
func (c *Client) HasAllRoles(
	ctx context.Context,
	userID string,
	roles ...string,
) (bool, error) {
	user, err := c.GetUserByID(ctx, userID)
	if err != nil {
		return false, err
	}

	if user.RealmRoles == nil || len(*user.RealmRoles) < len(roles) {
		return false, nil
	}

	exists := make(map[string]bool, len(roles))
	for _, role := range roles {
		exists[role] = true
	}

	for _, role := range *user.RealmRoles {
		if !exists[role] {
			return false, nil
		}
	}

	return true, nil
}

// Checks whether the user with the given `userID` has any of the given `roles`.
func (c *Client) HasAnyRole(
	ctx context.Context,
	userID string,
	roles ...string,
) (bool, error) {
	user, err := c.GetUserByID(ctx, userID)
	if err != nil {
		return false, err
	}

	if user.RealmRoles == nil {
		return false, nil
	}

	for _, requiredRole := range roles {
		for _, actualRole := range *user.RealmRoles {
			if requiredRole == actualRole {
				return true, nil
			}
		}
	}

	return false, nil
}
