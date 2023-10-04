package authz

import (
	"errors"

	"gopkg.in/yaml.v3"
)

// Policy is a struct that holds authorization logic for a resource.
type Policy struct {
	// The display name of the policy.
	Name string `yaml:"name,omitempty"`

	// The description of the policy.
	Description string `yaml:"description,omitempty"`

	// The description of the policy.
	Expression string `yaml:"expression,omitempty"`
}

// PolicySpec is a struct that enables to specify a policy either in place or
// by reference.
type PolicySpec struct {
	InPlace *Policy `yaml:"inPlace,omitempty"`
	Ref     string  `yaml:"policyRef,omitempty"`
}

func (s *PolicySpec) UnmarshalYAML(value *yaml.Node) error {
	if value == nil {
		return nil
	}

	switch value.Kind {
	case yaml.ScalarNode:
		if err := value.Decode(&s.Ref); err != nil {
			return err
		}

	case yaml.MappingNode:
		var inPlace Policy
		if err := value.Decode(&inPlace); err != nil {
			return err
		}
		s.InPlace = &inPlace

	default:
		return errors.New("invalid policy spec")
	}

	return nil
}
