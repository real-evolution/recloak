package authz

import (
	"fmt"
	"strings"

	"github.com/antonmedv/expr"
	"github.com/antonmedv/expr/vm"

	"github.com/real-evolution/recloak/authn"
)

var ErrUnauthorized = fmt.Errorf("unauthorized")

// PolicyEnv is an environment that is passed to the policy expression during
// evaluation.
type PolicyEnv struct {
	Claims  *authn.Claims
	Request any
}

// CompiledPolicy is a compiled policy that can be evaluated against a request
// and a set of claims at runtime.
type CompiledPolicy struct {
	source  string
	program *vm.Program
}

// PolicyCompiler is a builder for a compiled policy.
type PolicyCompiler struct {
	currentExpr string
}

// Evaluate evaluates the policy against the given claims and request.
func (p CompiledPolicy) Evaluate(claims *authn.Claims, request any) error {
	env := PolicyEnv{
		Claims:  claims,
		Request: request,
	}

	result, err := vm.Run(p.program, env)
	if err != nil {
		return err
	}

	if result.(bool) {
		return nil
	} else {
		return ErrUnauthorized
	}
}

// NewPolicyCompiler creates a new policy compiler.
func NewPolicyCompiler(baseExpr string) PolicyCompiler {
	return PolicyCompiler{currentExpr: baseExpr}
}

// Or adds a logical OR to the current expression.
func (b PolicyCompiler) Or(exprs ...string) PolicyCompiler {
	normalizedExprs := make([]string, 0, len(exprs))
	for _, exprStr := range exprs {
		if exprStr != "" {
			exprStr = fmt.Sprintf("(%s)", exprStr)
			normalizedExprs = append(normalizedExprs, exprStr)
		}
	}
	exprStr := strings.Join(normalizedExprs, " || ")

	if b.currentExpr == "" {
		return b
	} else {
		b.currentExpr = fmt.Sprintf("(%s) || %s", b.currentExpr, exprStr)
	}

	return b
}

// And adds a logical AND to the current expression.
func (b PolicyCompiler) And(exprs ...string) PolicyCompiler {
	normalizedExprs := make([]string, 0, len(exprs))
	for _, exprStr := range exprs {
		if exprStr != "" {
			exprStr = fmt.Sprintf("(%s)", exprStr)
			normalizedExprs = append(normalizedExprs, exprStr)
		}
	}
	exprStr := strings.Join(normalizedExprs, " && ")

	if b.currentExpr == "" {
		b.currentExpr = exprStr
	} else {
		b.currentExpr = fmt.Sprintf("(%s) && %s", b.currentExpr, exprStr)
	}

	return b
}

// Compile builds a compiled policy from the current expression.
func (b PolicyCompiler) Compile() (CompiledPolicy, error) {
	program, err := expr.Compile(
		b.currentExpr,
		expr.Env(PolicyEnv{}),
		expr.Optimize(true),
		expr.AsBool(),
	)
	if err != nil {
		return CompiledPolicy{}, err
	}

	return CompiledPolicy{
		source:  b.currentExpr,
		program: program,
	}, nil
}
