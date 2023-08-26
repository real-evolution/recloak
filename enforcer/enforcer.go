package enforcer

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"

	"github.com/rs/zerolog/log"
	"gopkg.in/yaml.v3"

	"github.com/real-evolution/recloak"
)

// ErrUnsupportedConfigType is returned when the config file has an unsupported
// extension.
var ErrUnsupportedConfigType = errors.New(
	"unsupported config type (only .json and .yaml are supported",
)

type PolicyEnforcer interface {
	// CheckAccess checks whether the given `token` can access the resource
	// defined by the given `permFactories`.
	CheckAccess(
		ctx context.Context,
		token *string,
		permFactories ...PermissionFactory,
	) error
}

// RecloakPolicyEnforcer is a PolicyEnforcer that uses Recloak as its backend.
type RecloakPolicyEnforcer struct {
	client *recloak.Client
	resMap *ResourceMap
}

// NewRecloakPolicyEnforcer creates a new RecloakPolicyEnforcer.
func NewPolicyEnforcer(
	client *recloak.Client,
	resMap *ResourceMap,
) PolicyEnforcer {
	return &RecloakPolicyEnforcer{
		client: client,
		resMap: resMap,
	}
}

// NewFilePolicyEnforcer creates a new PolicyEnforcer from a config file.
func NewFilePolicyEnforcer(
	client *recloak.Client,
	configPath string,
) (PolicyEnforcer, error) {
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

// CheckResourceAccess checks whether the given `token` can access the resource
// defined by the given `permFactories`.
func (e *RecloakPolicyEnforcer) CheckAccess(
	ctx context.Context,
	token *string,
	permFactories ...PermissionFactory,
) error {
	perms, err := e.resMap.GetPermissions(permFactories...)
	if err != nil {
		log.Warn().
			Err(err).
			Msg("could not generate permission strings, check your map definitions")

		return err
	}

	return e.client.CheckAccess(ctx, token, perms...)
}

func getPolicyEnforcerFromClient(
	path string,
	client *recloak.Client,
	de func([]byte, interface{}) error,
) (PolicyEnforcer, error) {
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
