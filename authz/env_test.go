package authz

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/real-evolution/recloak"
)

func TestEnvInRole(t *testing.T) {
	env := AuthzEnv{
		Config: &AuthzConfig{
			ClientID: "client",
		},
		Claims: &recloak.Claims{
			RealmAcess: recloak.RolesClaim{
				Roles: []string{"admin"},
			},
			ResourceAcess: map[string]recloak.RolesClaim{
				"client": {
					Roles: []string{"user"},
				},
			},
		},
	}

	t.Run("in realm role", func(t *testing.T) {
		err := evalPolicy(`InRealmRole("admin")`, env)
		require.NoError(t, err)
	})

	t.Run("in client role", func(t *testing.T) {
		err := evalPolicy(`InRole("user")`, env)
		require.NoError(t, err)
	})
}

func evalPolicy(expr string, env AuthzEnv) error {
	policy, err := CompilePolicy(expr)
	if err != nil {
		return err
	}

	return policy.Evaluate(env)
}
