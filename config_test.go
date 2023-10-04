package recloak

import (
	"fmt"
	"testing"

	"github.com/go-faker/faker/v4"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

func TestDecodeFromYAML(t *testing.T) {
	expectedScheme := faker.Word()
	expectedUsername := faker.Username()
	expectedPassword := faker.Password()
	expectedHost := faker.DomainName()
	expectedPort, _ := faker.RandomInt(1, 65535, 1)
	expectedRealm := faker.Word()
	expectedAuthServerURL := fmt.Sprintf(
		"%s://%s:%d",
		expectedScheme,
		expectedHost,
		expectedPort[0],
	)

	const expectedYAMLFmt = `
---
authServerUrl: %s://%s:%d
realm: %s
clientId: %s
clientSecret: %s
`

	expectedYAML := fmt.Sprintf(
		expectedYAMLFmt,
		expectedScheme,
		expectedHost,
		expectedPort[0],
		expectedRealm,
		expectedUsername,
		expectedPassword,
	)

	var actual ClientConfig
	err := yaml.Unmarshal([]byte(expectedYAML), &actual)
	require.NoError(t, err)

	require.Equal(t, expectedAuthServerURL, actual.AuthServerURL)
	require.Equal(t, expectedRealm, actual.Realm)
	require.Equal(t, expectedUsername, actual.ClientID)
	require.Equal(t, expectedPassword, actual.ClientSecret)
}

func TestDecodeFromURL(t *testing.T) {
	expectedScheme := faker.Word()
	expectedUsername := faker.Username()
	expectedPassword := faker.Password()
	expectedHost := faker.DomainName()
	expectedPort, _ := faker.RandomInt(1, 65535, 1)
	expectedRealm := faker.Word()

	expectedURL := fmt.Sprintf(
		"%s://%s:%s@%s:%d/%s",
		expectedScheme,
		expectedUsername,
		expectedPassword,
		expectedHost,
		expectedPort[0],
		expectedRealm,
	)

	fmt.Println(expectedURL)

	var actual ClientConfig
	err := yaml.Unmarshal([]byte(expectedURL), &actual)
	require.NoError(t, err)
	require.NotNil(t, actual)

	actualURL, err := actual.ToURL()

	require.NoError(t, err)
	require.NotNil(t, actualURL)
	require.Equal(t, expectedURL, actualURL.String())
}
