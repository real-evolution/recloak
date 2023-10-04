package authz

import (
	"fmt"
	"testing"

	"github.com/go-faker/faker/v4"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

func TestDecodePolicyFromYAML(t *testing.T) {
	const expectedYAMLFmt = `
---
name: %s
description: %s
expression: %s
`
	expected := Policy{}

	err := faker.FakeData(&expected)
	require.NoError(t, err)

	expectedYAML := fmt.Sprintf(
		expectedYAMLFmt,
		expected.Name,
		expected.Description,
		expected.Expression,
	)

	var actual Policy
	err = yaml.Unmarshal([]byte(expectedYAML), &actual)
	require.NoError(t, err)

	require.Equal(t, expected, actual)
}

func TestDecodeInPlacePolicySpecFromYAML(t *testing.T) {
	const expectedYAMLFmt = `
---
name: %s
description: %s
expression: %s
`

	expected := Policy{}

	err := faker.FakeData(&expected)
	require.NoError(t, err)

	expectedYAML := fmt.Sprintf(
		expectedYAMLFmt,
		expected.Name,
		expected.Description,
		expected.Expression,
	)

	var actual PolicySpec
	err = yaml.Unmarshal([]byte(expectedYAML), &actual)
	require.NoError(t, err)

	require.Equal(t, expected, *actual.InPlace)
}

func TestDecodeRefPolicySpecFromYAML(t *testing.T) {
	const expectedYAMLFmt = `
---
policyRef: %s
`

	type decodeTestContainer struct {
		PolicyRef PolicySpec `yaml:"policyRef"`
	}

	var expectedRef string
	err := faker.FakeData(&expectedRef)
	require.NoError(t, err)

	expectedYAML := fmt.Sprintf(expectedYAMLFmt, expectedRef)
	var actual decodeTestContainer
	err = yaml.Unmarshal([]byte(expectedYAML), &actual)
	require.NoError(t, err)

	require.Equal(t, expectedRef, actual.PolicyRef.Ref)
}
