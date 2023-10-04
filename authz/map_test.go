package authz

import (
	"testing"

	"github.com/go-faker/faker/v4"
	"github.com/stretchr/testify/require"
)

func TestPolicyMapAdd(t *testing.T) {
	var policies []Policy
	err := faker.FakeData(&policies)

	require.NoError(t, err)

	uniquePolicies := make(map[string]Policy)
	for _, policy := range policies {
		if _, ok := uniquePolicies[policy.Name]; !ok {
			uniquePolicies[policy.Name] = policy
		}
	}

	policyMap := NewEmptyPolicyMap()
	for _, policy := range policies {
		require.False(t, policyMap.HasPolicy(policy.Name))

		err := policyMap.Add(policy)
		require.NoError(t, err)
		require.True(t, policyMap.HasPolicy(policy.Name))

		err = policyMap.Add(policy)
		require.Error(t, err)
		require.True(t, policyMap.HasPolicy(policy.Name))
	}

	require.Equal(t, len(uniquePolicies), len(policyMap.policies))

	for _, policy := range policies {
		require.Equal(t, policy, policyMap.policies[policy.Name])
	}
}
