package authz

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

func TestDecodeEnforcementModeFromYAML(t *testing.T) {
	testData := []struct {
		yaml     string
		expected EnforcementMode
		hasError bool
	}{
		{
			yaml:     "",
			expected: EnforcementModeEnforcing,
			hasError: false,
		},
		{
			yaml:     "enforcing",
			expected: EnforcementModeEnforcing,
			hasError: false,
		},
		{
			yaml:     "permissive",
			expected: EnforcementModePermissive,
			hasError: false,
		},
		{
			yaml:     "disabled",
			expected: EnforcementModeDisabled,
			hasError: false,
		},
		{
			yaml:     "permissivee",
			expected: EnforcementModeEnforcing,
			hasError: true,
		},
	}

	for _, data := range testData {
		var actual EnforcementMode

		err := yaml.Unmarshal([]byte(data.yaml), &actual)
		require.Equal(t, data.expected, actual)

		if data.hasError {
			require.Error(t, err)
		} else {
			require.NoError(t, err)
		}
	}
}

func TestDecodeConfigFromYAML(t *testing.T) {
	const expectedPathSeparator = "/"
	const expectedEnforcementMode = EnforcementModePermissive
	const expectedIntrospectionMode = IntrospectionModeAlways
	const expectedPolicyName = "first-policy"
	const expectedPolicyDescription = "The first policy in this test"
	const expectedPolicyExpression = "Some expression of the first policy"
	const expectedResourceName = "first-resource"
	const expectedResourceDisplayName = "The first resource in this test"
	const expectedResourcePolicyRef = "first-policy"

	const expectedYAMLFmt = `
---
pathSeparator: %s
enforcementMode: %s
introspection: %s
policies:
  - name: %s
    description: %s
    expression: %s
resources:
  - name: %s
    displayName: %s
    policy: %s
`

	expectedYAML := fmt.Sprintf(
		expectedYAMLFmt,
		expectedPathSeparator,
		expectedEnforcementMode,
		expectedIntrospectionMode,
		expectedPolicyName,
		expectedPolicyDescription,
		expectedPolicyExpression,
		expectedResourceName,
		expectedResourceDisplayName,
		expectedResourcePolicyRef,
	)

	expected := AuthzConfig{
		PathSeparator:     expectedPathSeparator,
		EnforcementMode:   expectedEnforcementMode,
		IntrospectionMode: expectedIntrospectionMode,
		Policies: []Policy{
			{
				Name:        expectedPolicyName,
				Description: expectedPolicyDescription,
				Expression:  expectedPolicyExpression,
			},
		},
		Resources: []Resource{
			{
				Name:        expectedResourceName,
				DisplayName: expectedResourceDisplayName,
				Policy: &PolicySpec{
					Ref: expectedResourcePolicyRef,
				},
			},
		},
	}

	var actual AuthzConfig
	err := yaml.Unmarshal([]byte(expectedYAML), &actual)
	require.NoError(t, err)
	require.Equal(t, expected, actual)
}
