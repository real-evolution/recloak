package enforcer

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/real-evolution/recloak"
)

// ErrUnsupportedConfigType is returned when the config file has an unsupported
// extension.
var ErrUnsupportedConfigType = errors.New(
	"unsupported config type (only .json and .yaml are supported",
)

// RecloakPolicyEnforcer is a PolicyEnforcer that uses Recloak as its backend.
type PolicyEnforcer struct {
	client *recloak.Client
	resMap *ResourceMap
}

// NewRecloakPolicyEnforcer creates a new RecloakPolicyEnforcer.
func NewPolicyEnforcer(
	client *recloak.Client,
	resMap *ResourceMap,
) *PolicyEnforcer {
	return &PolicyEnforcer{
		client: client,
		resMap: resMap,
	}
}

// NewFilePolicyEnforcer creates a new PolicyEnforcer from a config file.
func NewFilePolicyEnforcer(
	client *recloak.Client,
	configPath string,
) (*PolicyEnforcer, error) {
	cfgExt := strings.ToLower(filepath.Ext(configPath))

	switch cfgExt {
	case ".json":
		return getPolicyEnforcerFromClient(configPath, client, json.Unmarshal)

	case ".yaml", ".yml":
		return getPolicyEnforcerFromClient(configPath, client, yaml.Unmarshal)

	default:
		return nil, ErrUnsupportedConfigType
	}
}

// Client returns the Recloak client used by this PolicyEnforcer.
func (e *PolicyEnforcer) Client() *recloak.Client {
	return e.client
}

// ResourceMap returns the ResourceMap used by this PolicyEnforcer.
func (e *PolicyEnforcer) ResourceMap() *ResourceMap {
	return e.resMap
}

func getPolicyEnforcerFromClient(
	path string,
	client *recloak.Client,
	de func([]byte, interface{}) error,
) (*PolicyEnforcer, error) {
	authzConfig, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	resMap := new(ResourceMap)
	if err := de(authzConfig, resMap); err != nil {
		return nil, err
	}

	return NewPolicyEnforcer(client, resMap), nil
}
