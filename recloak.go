package recloak

import (
	"context"
	"time"

	"github.com/Nerzal/gocloak/v13"
)

// ReCloak is a type that provides additional authorization capabilities
// over `gocloak` library
type ReCloak struct {
	client *gocloak.GoCloak
	config *ClientConfig
	token  *gocloak.JWT
	repr   *gocloak.Client
}

// NewClient creates a new ReCloak instance
func NewClient(config *ClientConfig) (*ReCloak, error) {
	client := gocloak.NewClient(config.AuthServerURL)

	return &ReCloak{client, config, nil, nil}, nil
}

// Client returns the gocloak client
func (r *ReCloak) Client() *gocloak.GoCloak {
	return r.client
}

// Config returns the client configuration
func (r *ReCloak) Config() *ClientConfig {
	return r.config
}

// Token returns the current token
func (r *ReCloak) Token() *gocloak.JWT {
	return r.token
}

// Login logs in the client
func (r *ReCloak) Login(ctx context.Context) error {
	token, err := r.client.LoginClient(
		ctx,
		r.config.ClientID,
		r.config.ClientSecret,
		r.config.Realm,
	)
	if err != nil {
		return err
	}

	r.token = token

	return nil
}

// Refresh refreshes the token
func (r *ReCloak) Refresh(ctx context.Context) error {
	if r.token == nil || r.token.RefreshToken == "" {
		return r.Login(ctx)
	}

	token, err := r.client.RefreshToken(
		ctx,
		r.token.RefreshToken,
		r.config.ClientID,
		r.config.ClientSecret,
		r.config.Realm,
	)
	if err != nil {
		return err
	}

	r.token = token

	return nil
}

// RefreshIfExpired refreshes the token if it is expired
func (r *ReCloak) RefreshIfExpired(ctx context.Context) error {
	if r.token == nil || isTimestampExpired(int64(r.token.ExpiresIn)) {
		return r.Refresh(ctx)
	}

	return nil
}

// Gets client representation from the keycloak server.
func (r *ReCloak) GetRepresentation(ctx context.Context) (*gocloak.Client, error) {
	token, err := TokenFromContext(ctx)
	if err != nil {
		return nil, err
	}

	if r.repr != nil {
		return r.repr, nil
	}

	if err = r.RefreshIfExpired(ctx); err != nil {
		return nil, err
	}

	repr, err := r.client.GetClientRepresentation(
		ctx,
		token.Raw,
		r.config.Realm,
		r.config.ClientID,
	)
	if err != nil {
		return nil, err
	}

	r.repr = repr

	return repr, nil
}

// Checks whether the given timestamp is expired (in the past) or not.
func isTimestampExpired(timestamp int64) bool {
	exp := time.Unix(timestamp, 0)
	now := time.Now()

	return exp.After(now)
}
