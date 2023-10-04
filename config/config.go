package config

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

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
	fileExt := strings.ToLower(filepath.Ext(path))
	if fileExt != ".yaml" && fileExt != ".yml" {
		return nil, fmt.Errorf("unsupported file format: %s", fileExt)
	}

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

	return &config, nil
}
