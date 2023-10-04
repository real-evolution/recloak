package authz

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestEngine(t *testing.T) {
	type testRequest struct {
		Name string
	}

	expectedConfig := AuthzConfig{
		PathSeparator:   ".",
		EnforcementMode: EnforcementModeEnforcing,
		Policies: []Policy{
			{
				Name:        "allow-all",
				Description: "The first policy in this test",
				Expression:  "true",
			},
			{
				Name:        "deny-all",
				Description: "The second policy in this test",
				Expression:  "false",
			},
			{
				Name:        "allow-foo",
				Description: "The third policy in this test",
				Expression:  `Request.Name == "foo"`,
			},
		},
		Resources: []Resource{
			{
				Name:        "public",
				DisplayName: "The first resource in this test",
				Policy: &PolicySpec{
					Ref: "allow-all",
				},
			},
			{
				Name:        "private",
				DisplayName: "The second resource in this test",
				Policy: &PolicySpec{
					Ref: "deny-all",
				},
			},
			{
				Name:        "foo",
				DisplayName: "The third resource in this test",
				Policy: &PolicySpec{
					Ref: "allow-foo",
				},
			},
			{
				Name:        "bar",
				DisplayName: "The fourth resource in this test",
				Policy: &PolicySpec{
					InPlace: &Policy{
						Name:        "allow-bar",
						Description: "The fourth policy in this test",
						Expression:  `Request.Name == "bar"`,
					},
				},
				Children: []Resource{
					{
						Name:        "baz",
						DisplayName: "The fifth resource in this test",
						Policy: &PolicySpec{
							Ref: "allow-bar",
						},
					},
				},
			},
		},
	}

	engine, err := NewEngine(&expectedConfig)
	require.NoError(t, err)
	require.NotNil(t, engine)

	t.Run("allow-all", func(t *testing.T) {
		err := engine.Authorize("public", nil, testRequest{Name: "anonymous"})
		require.NoError(t, err)
	})

	t.Run("deny-all", func(t *testing.T) {
		err := engine.Authorize("private", nil, testRequest{Name: "admin"})
		require.Error(t, err)
		require.ErrorIs(t, err, ErrUnauthorized)
	})

	t.Run("allow-foo", func(t *testing.T) {
		err := engine.Authorize("foo", nil, testRequest{Name: "foo"})
		require.NoError(t, err)
	})

	t.Run("allow-bar", func(t *testing.T) {
		err := engine.Authorize("bar", nil, testRequest{Name: "bar"})
		require.NoError(t, err)
	})

	t.Run("allow-bar-baz", func(t *testing.T) {
		err := engine.Authorize("bar.baz", nil, testRequest{Name: "bar"})
		require.NoError(t, err)
	})

	t.Run("deny-bar-baz", func(t *testing.T) {
		err := engine.Authorize("bar.baz", nil, testRequest{Name: "baz"})
		require.Error(t, err)
		require.ErrorIs(t, err, ErrUnauthorized)
	})

	t.Run("deny-unknown-resource", func(t *testing.T) {
		err := engine.Authorize("unknown", nil, testRequest{Name: "anonymous"})
		require.Error(t, err)
		require.ErrorIs(t, err, ErrorNoPolicyForPath)
	})

	t.Run("allow-unknown-resource", func(t *testing.T) {
		engine.SetEnforcementMode(EnforcementModePermissive)
		err := engine.Authorize("unknown", nil, testRequest{Name: "anonymous"})
		require.NoError(t, err)
	})

	t.Run("allow-any-resource", func(t *testing.T) {
		engine.SetEnforcementMode(EnforcementModeDisabled)

		req := testRequest{Name: "anonymous"}
		paths := []string{"public", "private", "foo", "bar", "bar.baz"}

		for _, path := range paths {
			err := engine.Authorize(path, nil, req)
			require.NoError(t, err)
		}
	})
}
