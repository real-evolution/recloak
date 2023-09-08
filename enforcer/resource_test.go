package enforcer

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// TestNewResourceBasic tests whether basic NewResource usage works as expected.
func TestNewResourceBasic(t *testing.T) {
	r := NewResource(
		"test",
		"/test",
		NewAction("GET", []string{"a", "b", "c"}, nil),
	)

	require.Equal(t, ResourceName("test"), r.Name)
	require.Equal(t, "/test", r.Path)

	perm, ok := r.GetAction("GET")
	require.True(t, ok)
	require.Equal(t, "test#a,b,c", perm.Permission)
}

// TestNewResourceWithInvalidName tests whether NewResource panics when given
// an invalid name.
func TestNewResourceWithInvalidName(t *testing.T) {
	require.Panics(t, func() {
		NewResource(
			"test#",
			"/test",
			NewAction("GET", []string{"a", "b", "c"}, nil),
		)
	})
}

// TestHasAction tests whether `HasAction` works as expected.
func TestHasAction(t *testing.T) {
	r := NewResource("test", "/test", NewAction("GET", []string{"a", "b", "c"}, nil))

	require.True(t, r.HasAction("GET"))
	require.True(t, !r.HasAction("POST"))
}
