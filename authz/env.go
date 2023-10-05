package authz

import (
	"github.com/real-evolution/recloak/authn"
)

// AuthzEnv is an environment that is passed to the policy expression during
// evaluation.
type AuthzEnv struct {
	Config  *AuthzConfig
	Claims  *authn.Claims
	Request any
}

// InRealmRole checks if the user has the given role in the realm.
func (e AuthzEnv) InRealmRole(role string) bool {
	return e.Claims.InRealmRole(role)
}

// InClientRole checks if the user has the given role for the given client.
func (e AuthzEnv) InRole(role string) bool {
	return e.Claims.InClientRole(e.Config.ClientID, role)
}