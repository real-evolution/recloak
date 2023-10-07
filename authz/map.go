package authz

import (
	"errors"
	"fmt"
	"log"
	"strings"
)

const PolicyIncludePrefix = '@'

// PolicyMap is a set of policies.
type PolicyMap struct {
	policies           map[string]Policy
	unresolvedIncludes map[string][]string
}

// NewEmptyPolicyMap creates a new empty policy set.
func NewEmptyPolicyMap() PolicyMap {
	return PolicyMap{
		policies:           make(map[string]Policy),
		unresolvedIncludes: make(map[string][]string),
	}
}

// NewPolicyMap creates a new policy set.
func NewPolicyMap(config *AuthzConfig) (PolicyMap, error) {
	policyMap := NewEmptyPolicyMap()

	for _, policy := range config.Policies {
		if err := policyMap.Add(policy); err != nil {
			return PolicyMap{}, err
		}
	}

	for _, resource := range config.Resources {
		if err := policyMap.AddFromResource(&resource); err != nil {
			return PolicyMap{}, err
		}
	}

	return policyMap, nil
}

// Add adds a policy to the set.
func (s *PolicyMap) Add(policy Policy) error {
	if _, ok := s.policies[policy.Name]; ok {
		return fmt.Errorf("duplicate policy name: %s", policy.Name)
	}

	s.policies[policy.Name] = policy

	includes, err := getIncludes(policy.Expression)
	if err != nil {
		return err
	}

	if len(includes) > 0 {
		s.unresolvedIncludes[policy.Name] = includes
	}

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

func (p *PolicyMap) resolveIncludes() error {
	for name, incs := range p.unresolvedIncludes {
		policy, ok := p.Get(name)
		if !ok {
			return fmt.Errorf("policy %s not found", name)
		}

		policyExpr := policy.Expression

		for _, inc := range incs {
			incPolicy, ok := p.Get(inc)
			if !ok {
				return fmt.Errorf("unresolved reference `%s` in %s", inc, name)
			}

			incExpr := fmt.Sprintf("(%s)", incPolicy.Expression)
			incLabel := fmt.Sprintf("@%s", inc)
			policyExpr = strings.ReplaceAll(policyExpr, incLabel, incExpr)
		}

		policy.Expression = policyExpr
		p.policies[name] = policy
	}

	return nil
}

func getIncludes(expr string) ([]string, error) {
	refs := make([]string, 0)

	inSingleQuote := false
	inDoubleQuote := false

	for i := 0; i < len(expr); i++ {
		switch expr[i] {
		case '\'':
			inSingleQuote = !inSingleQuote

		case '"':
			inDoubleQuote = !inDoubleQuote
		}

		if inSingleQuote || inDoubleQuote {
			continue
		}

		if expr[i] == PolicyIncludePrefix {
			i += 1
			j := i

			for ; j < len(expr); j++ {
				if expr[j] == ' ' {
					break
				}
			}

			refs = append(refs, expr[i:j])
		}
	}

	if inSingleQuote || inDoubleQuote {
		return nil, errors.New("unterminated quote")
	}

	return refs, nil
}
