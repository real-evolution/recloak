package enforcer

import "strings"

// Action is an action that can be performed on a resource that is protected
// by a set of scopes.
type Action struct {
	Method ActionMethod `json:"method" yaml:"method"`
	Scopes []string     `json:"scopes" yaml:"scopes"`
}

// Creates a new action with the given `method` and `scopes`.
func NewAction(method ActionMethod, scopes ...string) Action {
	return Action{
		Method: method,
		Scopes: scopes,
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
