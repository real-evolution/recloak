package authz

import (
	"fmt"
	"strings"

	"gopkg.in/yaml.v3"
)

type (
	// EnforcementMode is an enum that represents the policy evaluation
	// enforcement mode.
	EnforcementMode int

	// IntrospectionMode is an enum that indicates whether to introspect
	// user token before evaluating policies.
	IntrospectionMode int
)

const (
	// EnforcementModeEnforcing is the enforcement mode that causes the
	// evaluation to fail if a resource has no policy associated with it.
	EnforcementModeEnforcing EnforcementMode = iota

	// EnforcementModePermissive is the enforcement mode that causes the
	// evaluation to succeed if a resource has no policy associated with it.
	EnforcementModePermissive

	// EnforcementModeDisabled is the enforcement mode that causes the
	// evaluation to succeed regardless of whether a resource has a policy
	// associated with it.
	EnforcementModeDisabled
)

const (
	// IntrospectionModeDisabled is the introspection mode that causes the
	// evaluation to not introspect user token before evaluating policies,
	// and instead try to decode & verify the token locally.
	IntrospectionModeDisabled IntrospectionMode = iota

	// IntrospectionModeAlways is the introspection mode that causes the
	// evaluation to always introspect user token before evaluating policies.
	IntrospectionModeAlways
)

// AuthzConfig is a struct that holds the authorization configuration.
type AuthzConfig struct {
	// The path separator.
	PathSeparator string `yaml:"pathSeparator"`

	// The enforcement mode.
	EnforcementMode EnforcementMode `yaml:"enforcementMode"`

	// Whether to introspect user token before evaluating policies.
	IntrospectionMode IntrospectionMode `yaml:"introspection"`

	// Whether to print debug information.
	Debug bool `yaml:"debug"`

	// The ID of the client.
	ClientID string `yaml:"clientID"`

	// Authorization policies.
	Policies []Policy `yaml:"policies,flow"`

	// Resources.
	Resources []Resource `yaml:"resources,flow"`
}

// parseEnforcementMode parses enforcement mode from a string.
func parseEnforcementMode(modeStr string) (EnforcementMode, error) {
	switch strings.ToLower(modeStr) {
	case "enforcing":
		return EnforcementModeEnforcing, nil

	case "permissive":
		return EnforcementModePermissive, nil

	case "disabled":
		return EnforcementModeDisabled, nil

	default:
		return EnforcementModeEnforcing, fmt.Errorf(
			"invalid enforcement mode: %s",
			modeStr,
		)
	}
}

// parseIntrospectionMode parses introspection mode from a string.
func parseIntrospectionMode(modeStr string) (IntrospectionMode, error) {
	switch strings.ToLower(modeStr) {
	case "never":
		return IntrospectionModeDisabled, nil

	case "always":
		return IntrospectionModeAlways, nil

	default:
		return IntrospectionModeDisabled, fmt.Errorf(
			"invalid introspection mode: %s",
			modeStr,
		)
	}
}

func (s *EnforcementMode) UnmarshalYAML(value *yaml.Node) (err error) {
	*s, err = parseEnforcementMode(value.Value)

	return
}

func (s *IntrospectionMode) UnmarshalYAML(value *yaml.Node) (err error) {
	*s, err = parseIntrospectionMode(value.Value)

	return
}

func (s EnforcementMode) String() string {
	switch s {
	case EnforcementModeEnforcing:
		return "enforcing"

	case EnforcementModePermissive:
		return "permissive"

	case EnforcementModeDisabled:
		return "disabled"

	default:
		return "unknown"
	}
}

func (s IntrospectionMode) String() string {
	switch s {
	case IntrospectionModeDisabled:
		return "disabled"

	case IntrospectionModeAlways:
		return "always"

	default:
		return "unknown"
	}
}
