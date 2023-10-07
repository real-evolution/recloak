package authz

import (
	"fmt"
	"strings"

	"github.com/antonmedv/expr"
	"github.com/antonmedv/expr/vm"
)

var ErrUnauthorized = fmt.Errorf("unauthorized")

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

// CompilePolicy compiles the given policy from the given source expression.
func CompilePolicy(source string) (CompiledPolicy, error) {
	program, err := expr.Compile(
		source,
		expr.Env(AuthzEnv{}),
		expr.Optimize(true),
		expr.AsBool(),
	)
	if err != nil {
		return CompiledPolicy{}, err
	}

	return CompiledPolicy{
		source:  source,
		program: program,
	}, nil
}

// Evaluate evaluates the policy against the given claims and request.
func (p CompiledPolicy) Evaluate(env AuthzEnv) error {
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
	return CompilePolicy(b.currentExpr)
}

func (b *PolicyCompiler) IsEmpty() bool {
	return b.currentExpr == ""
}
