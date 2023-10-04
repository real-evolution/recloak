package authz

import (
	"fmt"

	"github.com/real-evolution/recloak/authn"
)

var ErrorNoPolicyForPath = fmt.Errorf("no policy for path")

// Engine is a struct that is used to evaluate authorization policies.
type Engine struct {
	config           *AuthzConfig
	rawPolicies      PolicyMap
	compiledPolicies map[string]CompiledPolicy
}

// NewEngine creates a new authorization engine.
func NewEngine(config *AuthzConfig) (*Engine, error) {
	rawPolicies, err := NewPolicyMap(config)
	if err != nil {
		return nil, err
	}

	engine := &Engine{
		config:           config,
		rawPolicies:      rawPolicies,
		compiledPolicies: make(map[string]CompiledPolicy),
	}

	if err := engine.fillFromResources(); err != nil {
		return nil, err
	}

	return engine, nil
}

// Authorize evaluates a policy for a path, with the given claims and request.
func (e *Engine) Authorize(path string, claims *authn.Claims, request any) error {
	if e.config.EnforcementMode == EnforcementModeDisabled {
		return nil
	}

	if policy, ok := e.compiledPolicies[path]; ok {
		return policy.Evaluate(claims, request)
	}

	if e.config.EnforcementMode == EnforcementModeEnforcing {
		return ErrorNoPolicyForPath
	}

	return nil
}

func (e *Engine) SetEnforcementMode(mode EnforcementMode) {
	e.config.EnforcementMode = mode
}

func (e *Engine) fillFromResources() error {
	for _, resource := range e.config.Resources {
		if err := e.addResource(resource, "", PolicyCompiler{}); err != nil {
			return err
		}
	}

	return nil
}

func (e *Engine) addResource(
	resource Resource,
	currentPath string,
	compiler PolicyCompiler,
) error {
	if resource.Name == "" {
		return fmt.Errorf("resource name is empty")
	}

	if currentPath == "" {
		currentPath = resource.Name
	} else {
		currentPath = fmt.Sprintf("%s%s%s", currentPath, e.config.PathSeparator, resource.Name)
	}

	if _, ok := e.compiledPolicies[currentPath]; ok {
		return fmt.Errorf("duplicate resource name: %s", currentPath)
	}

	if resource.Policy != nil {
		var policy Policy
		var ok bool

		if resource.Policy.InPlace != nil {
			policy = *resource.Policy.InPlace
		} else if resource.Policy.Ref != "" {
			if policy, ok = e.rawPolicies.Get(resource.Policy.Ref); !ok {
				return fmt.Errorf("policy %s not found", resource.Policy.Ref)
			}
		} else {
			return fmt.Errorf("policy is empty")
		}

		compiler = compiler.And(policy.Expression)
		compliledPolicy, err := compiler.Compile()
		if err != nil {
			return err
		}

		e.compiledPolicies[currentPath] = compliledPolicy
	}

	for _, child := range resource.Children {
		if err := e.addResource(child, currentPath, compiler); err != nil {
			return err
		}
	}

	return nil
}
