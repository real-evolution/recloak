package grpc

import (
	"context"
	"strings"

	"google.golang.org/grpc/metadata"
)

func extractAuthorizationHeader(ctx context.Context) (string, error) {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return "", ErrMissingRequestMetadata
	}

	// get authorization header
	values := md["authorization"]
	if len(values) == 0 {
		return "", ErrMissingAuthorizationHeader
	}

	return values[0], nil
}

func extractBearerToken(header string) (string, error) {
	if len(header) < 7 || strings.ToLower(header[:6]) != "bearer" {
		return "", ErrInvalidAuthorizationHeader
	}

	return header[7:], nil
}
