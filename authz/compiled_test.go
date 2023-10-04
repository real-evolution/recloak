package authz

import (
	"fmt"
	"testing"

	"github.com/go-faker/faker/v4"
	"github.com/stretchr/testify/require"
)

func TestPolicyCompiler(t *testing.T) {
	var testRequest struct {
		Foo string
		Bar string
		Baz int
	}

	err := faker.FakeData(&testRequest)
	require.NoError(t, err)

	compiler := NewPolicyCompiler("true").
		And(fmt.Sprintf("Request.Foo == '%s'", testRequest.Foo)).
		And(fmt.Sprintf("Request.Bar == '%s'", testRequest.Bar)).
		And(fmt.Sprintf("Request.Baz == %d", testRequest.Baz)).
		Or("false", "1 != 1")

	const expectedExprFmt = "((((true) && " +
		"(Request.Foo == '%s')) && " +
		"(Request.Bar == '%s')) && " +
		"(Request.Baz == %d)) || " +
		"(false) || (1 != 1)"

	expectedExpr := fmt.Sprintf(
		expectedExprFmt,
		testRequest.Foo,
		testRequest.Bar,
		testRequest.Baz,
	)

	require.Equal(t, expectedExpr, compiler.currentExpr)

	compiledPol, err := compiler.Compile()
	require.NoError(t, err)
	require.Equal(t, expectedExpr, compiledPol.source)
	require.NotNil(t, compiledPol.program)

	result := compiledPol.Evaluate(nil, testRequest)
	require.NoError(t, result)

	testRequest.Foo = "not foo"
	result = compiledPol.Evaluate(nil, testRequest)
	require.Error(t, result)
}
