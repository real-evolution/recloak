package enforcer

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// TestHasScope tests whether `HasScope` works as expected.
func TestHasScope(t *testing.T) {
	a := NewAction("", "a", "b", "c")

	require.True(t, a.HasScope("a"))
	require.True(t, a.HasScope("b"))
	require.True(t, a.HasScope("c"))
	require.True(t, !a.HasScope("d"))
}

// TestActionHasAllScopes tests whether `HasAllScopes` works as expected.
func TestHasAllScopes(t *testing.T) {
	a := NewAction("", "a", "b", "c")

	require.True(t, a.HasAllScopes("a", "b", "c"))
	require.True(t, !a.HasAllScopes("a", "b", "c", "d"))
}

// TestActionHasAnyScope tests whether `HasAnyScope` works as expected.
func TestHasAnyScope(t *testing.T) {
	a := NewAction("", "a", "b", "c")

	require.True(t, a.HasAnyScope("a", "b", "c"))
	require.True(t, a.HasAnyScope("a", "b", "c", "d"))
	require.True(t, !a.HasAnyScope("d"))
}

// TestActionHasScope tests whether `getScopesStr` returns the correct string.
func TestScopesStr(t *testing.T) {
	a := NewAction("", "a", "b", "c")

	require.Equal(t, "a,b,c", a.getScopesStr())
}
