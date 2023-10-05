package authz

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/real-evolution/recloak/authn"
)

func TestEnvInRole(t *testing.T) {
	env := AuthzEnv{
		Config: &AuthzConfig{
			ClientID: "client",
		},
		Claims: &authn.Claims{
			RealmAcess: authn.RolesClaim{
				Roles: []string{"admin"},
			},
			ResourceAcess: map[string]authn.RolesClaim{
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
