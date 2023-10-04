package authz

import "fmt"

// PolicyMap is a set of policies.
type PolicyMap struct {
	policies map[string]Policy
}

// NewEmptyPolicyMap creates a new empty policy set.
func NewEmptyPolicyMap() PolicyMap {
	return PolicyMap{
		policies: make(map[string]Policy),
	}
}

// NewPolicyMap creates a new policy set.
func NewPolicyMap(config *AuthzConfig) (PolicyMap, error) {
	policySet := PolicyMap{
		policies: make(map[string]Policy),
	}

	for _, policy := range config.Policies {
		if err := policySet.Add(policy); err != nil {
			return PolicyMap{}, err
		}
	}

	for _, resource := range config.Resources {
		if err := policySet.AddFromResource(&resource); err != nil {
			return PolicyMap{}, err
		}
	}

	return policySet, nil
}

// Add adds a policy to the set.
func (s *PolicyMap) Add(policy Policy) error {
	if _, ok := s.policies[policy.Name]; ok {
		return fmt.Errorf("duplicate policy name: %s", policy.Name)
	}

	s.policies[policy.Name] = policy
	return nil
}

// AddFromResource adds a policy from a resource to the set.
func (s *PolicyMap) AddFromResource(resource *Resource) error {
	if resource == nil || resource.Policy == nil ||
		resource.Policy.InPlace == nil || resource.Policy.InPlace.Name == "" {
		return nil
	}

	if err := s.Add(*resource.Policy.InPlace); err != nil {
		return err
	}

	for _, childResource := range resource.Children {
		if err := s.AddFromResource(&childResource); err != nil {
			return err
		}
	}

	return nil
}

// Get gets a policy from the set by name.
func (p *PolicyMap) Get(name string) (policy Policy, ok bool) {
	policy, ok = p.policies[name]
	return
}

// HasKey checks if a policy exists in the set by name.
func (p *PolicyMap) HasPolicy(name string) bool {
	_, ok := p.policies[name]

	return ok
}
