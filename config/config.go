package config

import (
	"io"
	"os"

	"gopkg.in/yaml.v3"

	"github.com/real-evolution/recloak"
	"github.com/real-evolution/recloak/authz"
)

type ReCloakConfig struct {
	// Client is the ReCloak client configuration
	Client recloak.ClientConfig `yaml:"client,flow"`

	// Authz is the authorization configuration
	Authz authz.AuthzConfig `yaml:"authz,flow"`
}

func LoadConfig(path string) (*ReCloakConfig, error) {
	configFile, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer configFile.Close()

	fileContent, err := io.ReadAll(configFile)
	if err != nil {
		return nil, err
	}

	var config ReCloakConfig
	if err := yaml.Unmarshal(fileContent, &config); err != nil {
		return nil, err
	}

	// TODO: get a better way to do this
	config.Authz.ClientID = config.Client.ClientID

	return &config, nil
}
