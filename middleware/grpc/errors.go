package grpc

import (
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

var (
	// ErrMissingRequestMetadata is returned when the request metadata is missing.
	ErrMissingRequestMetadata = status.Error(
		codes.Unauthenticated,
		"missing request metadata",
	)

	// ErrInvalidAuthorizationHeader is returned when the authorization header
	// is missing from the request metadata.
	ErrMissingAuthorizationHeader = status.Error(
		codes.Unauthenticated,
		"missing authorization header",
	)

	// ErrInvalidAuthorizationHeader is returned when the authorization header
	// is invalid.
	ErrInvalidAuthorizationHeader = status.Error(
		codes.Unauthenticated,
		"invalid authorization header",
	)
)
