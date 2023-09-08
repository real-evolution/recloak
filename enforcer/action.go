package enforcer

import (
	"strings"
)

const (
	ResourceClaimResourceRequest ResourceClaimSource = "request"
)

// ActionClaim is a claim that can be used to access a resource.
type ActionClaim struct {
	Source ResourceClaimSource `json:"source" yaml:"source"`
	Name   ResourceName        `json:"name"   yaml:"name"`
	Alias  string              `json:"alias"  yaml:"alias"`
}

// Action is an action that can be performed on a resource that is protected
// by a set of scopes.
type Action struct {
	Method     ActionMethod  `json:"method"           yaml:"method"`
	Scopes     []string      `json:"scopes"           yaml:"scopes"`
	Claims     []ActionClaim `json:"claims,omitempty" yaml:"claims,omitempty,flow"`
	Permission string
}

// Creates a new action with the given `method` and `scopes`.
func NewAction(method ActionMethod, scopes []string, claims []ActionClaim) Action {
	return Action{
		Method: method,
		Scopes: scopes,
		Claims: claims,
	}
}

// Checks whether the action has the given `scope`.
func (a Action) HasScope(scope string) bool {
	for _, s := range a.Scopes {
		if s == scope {
			return true
		}
	}

	return false
}

// Checks whether the action has all the given `scopes`.
func (a Action) HasAllScopes(scopes ...string) bool {
	for _, scope := range scopes {
		if !a.HasScope(scope) {
			return false
		}
	}

	return true
}

// Checks whether the action has any of the given `scopes`.
func (a Action) HasAnyScope(scopes ...string) bool {
	for _, scope := range scopes {
		if a.HasScope(scope) {
			return true
		}
	}

	return false
}

// Gets the scopes of the action as comma-separated string.
func (a Action) getScopesStr() string {
	return strings.Join(a.Scopes, ",")
}
