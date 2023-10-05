package authz

import (
	"context"

	"github.com/Nerzal/gocloak/v13"

	"github.com/real-evolution/recloak"
)

type Enforcer struct {
	client *recloak.ReCloak
	engine *Engine
	config *AuthzConfig
}

// NewEnforcer creates a new authorization enforcer.
func NewEnforcer(client *recloak.ReCloak, config *AuthzConfig) (*Enforcer, error) {
	engine, err := NewEngine(config)
	if err != nil {
		return nil, err
	}

	return &Enforcer{
		client: client,
		engine: engine,
	}, nil
}

// Authorize evaluates a policy for a path, with the given claims and request.
func (e *Enforcer) Authorize(
	ctx context.Context,
	accessToken string,
	path string,
	request any,
) (recloak.Token, error) {
	if e.engine.config.EnforcementMode == EnforcementModeDisabled {
		return recloak.Token{}, nil
	}

	if e.config.IntrospectionMode == IntrospectionModeAlways {
		result, err := e.introspectToken(ctx, accessToken)
		if err != nil {
			return recloak.Token{}, err
		}

		if result.Active == nil || !*result.Active {
			return recloak.Token{}, ErrUnauthorized
		}
	}

	claims := &recloak.Claims{}
	decodedToken, err := e.client.Client().DecodeAccessTokenCustomClaims(
		ctx,
		accessToken,
		e.client.Config().Realm,
		claims,
	)
	if err != nil {
		return recloak.Token{}, err
	}

	if !decodedToken.Valid {
		return recloak.Token{}, ErrUnauthorized
	}

	err = e.engine.Authorize(path, claims, request)
	if err != nil {
		return recloak.Token{}, err
	}

	return recloak.Token{
		Token:  decodedToken,
		Claims: claims,
	}, nil
}

// SetEnforcementMode sets the enforcement mode.
func (e *Enforcer) SetEnforcementMode(mode EnforcementMode) {
	e.config.EnforcementMode = mode
}

func (e *Enforcer) introspectToken(
	ctx context.Context,
	accessToken string,
) (*gocloak.IntroSpectTokenResult, error) {
	cfg := e.client.Config()

	return e.client.Client().RetrospectToken(
		ctx,
		accessToken,
		cfg.ClientID,
		cfg.ClientSecret,
		cfg.Realm,
	)
}
