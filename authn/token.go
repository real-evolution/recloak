package authn

import (
	"context"

	"github.com/golang-jwt/jwt/v4"

	"github.com/real-evolution/recloak"
)

// Token is a type that represents a JWT token.
type Token struct {
	*jwt.Token

	Claims *Claims // Custom claims
}

// DecodeAccessToken decodes a bearer access token and returns a Token instance
func DecodeAccessToken(
	ctx context.Context,
	client *recloak.ReCloak,
	tokenString string,
) (Token, error) {
	if err := client.RefreshIfExpired(ctx); err != nil {
		return Token{}, err
	}

	claims := &Claims{}
	token, err := client.Client().DecodeAccessTokenCustomClaims(
		ctx,
		tokenString,
		client.Config().Realm,
		claims,
	)
	if err != nil {
		return Token{}, err
	}

	return Token{token, claims}, nil
}
