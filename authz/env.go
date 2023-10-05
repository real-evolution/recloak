package authz

import (
	"github.com/real-evolution/recloak"
)

// AuthzEnv is an environment that is passed to the policy expression during
// evaluation.
type AuthzEnv struct {
	Config  *AuthzConfig
	Claims  *recloak.Claims
	Request any
}

// InRealmRole checks if the user has the given role in the realm.
func (e AuthzEnv) InRealmRole(role string) bool {
	return e.Claims.RealmAcess.HasRole(role)
}

// InClientRole checks if the user has the given role for the given client.
func (e AuthzEnv) InRole(role string) bool {
	clientRoles, ok := e.Claims.ResourceAcess[e.Config.ClientID]

	return ok && clientRoles.HasRole(role)
}
