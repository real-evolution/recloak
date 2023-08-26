package enforcer

import (
	"context"

	"github.com/rs/zerolog/log"

	"github.com/real-evolution/recloak"
)

type PolicyEnforcer interface {
	// CheckAccess checks whether the given `token` can access the resource
	// defined by the given `permFactories`.
	CheckAccess(
		ctx context.Context,
		token *string,
		permFactories ...PermissionFactory,
	) error
}

// RecloakPolicyEnforcer is a PolicyEnforcer that uses Recloak as its backend.
type RecloakPolicyEnforcer struct {
	client *recloak.Client
	resMap *ResourceMap
}

// NewRecloakPolicyEnforcer creates a new RecloakPolicyEnforcer.
func NewRecloakPolicyEnforcer(
	client *recloak.Client,
	resMap *ResourceMap,
) *RecloakPolicyEnforcer {
	return &RecloakPolicyEnforcer{
		client: client,
		resMap: resMap,
	}
}

// CheckResourceAccess checks whether the given `token` can access the resource
// defined by the given `permFactories`.
func (e *RecloakPolicyEnforcer) CheckAccess(
	ctx context.Context,
	token *string,
	permFactories ...PermissionFactory,
) error {
	perms, err := e.resMap.GetPermissions(permFactories...)
	if err != nil {
		log.Warn().
			Err(err).
			Msg("could not generate permission strings, check your map definitions")

		return err
	}

	return e.client.CheckAccess(ctx, token, perms...)
}
