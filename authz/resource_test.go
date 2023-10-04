package authz

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

func TestDecodeResourceFromYAML(t *testing.T) {
	const expectedName = "first-resource"
	const expectedDisplayName = "The first resource in this test"
	const expectedPolicyRef = "first-policy"
	const expectedChildName = "child-resource"
	const expectedChildDisplayName = "A child resource"
	const expectedChildPolicyRef = "A child policy reference"
	const expectedChildPolicyName = "A child policy name"
	const expectedChildPolicyDescription = "Some description of the child policy"
	const expectedChildPolicyExpression = "Some expression of the child policy"

	const expectedYAMLFmt = `
---
name: %s
displayName: %s
policy: %s
children:
  - name: "%s #0"
    displayName: "%s #0"
    policy: "%s #0"
  - name: "%s #1"
    displayName: "%s #1"
    policy: "%s #1"
  - name: "%s #2"
    displayName: "%s #2"
    policy:
      name: "%s #2"
      description: "%s #2"
      expression: "%s #2"
`

	expectedYAML := fmt.Sprintf(
		expectedYAMLFmt,
		expectedName,
		expectedDisplayName,
		expectedPolicyRef,
		expectedChildName,
		expectedChildDisplayName,
		expectedChildPolicyRef,
		expectedChildName,
		expectedChildDisplayName,
		expectedChildPolicyRef,
		expectedChildName,
		expectedChildDisplayName,
		expectedChildPolicyName,
		expectedChildPolicyDescription,
		expectedChildPolicyExpression,
	)

	var actual Resource
	err := yaml.Unmarshal([]byte(expectedYAML), &actual)
	require.NoError(t, err)

	require.Equal(t, expectedName, actual.Name)
	require.Equal(t, expectedDisplayName, actual.DisplayName)
	require.Equal(t, expectedPolicyRef, actual.Policy.Ref)

	require.Equal(t, 3, len(actual.Children))
	for i, child := range actual.Children {

		childName := fmt.Sprintf("%s #%d", expectedChildName, i)
		childDisplayName := fmt.Sprintf("%s #%d", expectedChildDisplayName, i)
		require.Equal(t, childName, child.Name)
		require.Equal(t, childDisplayName, child.DisplayName)

		if child.Policy.InPlace != nil {
			childPolicy := *child.Policy.InPlace
			childPolicyName := fmt.Sprintf("%s #%d", expectedChildPolicyName, i)
			childPolicyDescription := fmt.Sprintf(
				"%s #%d",
				expectedChildPolicyDescription,
				i,
			)
			childPolicyExpression := fmt.Sprintf(
				"%s #%d",
				expectedChildPolicyExpression,
				i,
			)

			require.Equal(t, childPolicyName, childPolicy.Name)
			require.Equal(t, childPolicyDescription, childPolicy.Description)
			require.Equal(t, childPolicyExpression, childPolicy.Expression)
		} else {
			childDisplayPolicyRef := fmt.Sprintf(
				"%s #%d",
				expectedChildPolicyRef,
				i,
			)

			require.Equal(t, childDisplayPolicyRef, child.Policy.Ref)
		}
	}
}
