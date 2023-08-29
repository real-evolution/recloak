package interceptors

import (
	"context"
	"strings"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	"github.com/rs/zerolog/log"

	e "github.com/real-evolution/recloak/enforcer"
)

// AuthInterceptor is a gRPC server interceptor that performs authorization
type AuthInterceptor struct {
	enforcer e.PolicyEnforcer
}

// NewAuthInterceptor creates a new AuthInterceptor with the given PolicyEnforcer.
func NewAuthInterceptor(enforcer e.PolicyEnforcer) AuthInterceptor {
	return AuthInterceptor{enforcer}
}

// Unary returns a new unary server interceptors that performs authorization
// on unary RPC calls.
func (i AuthInterceptor) Unary() grpc.UnaryServerInterceptor {
	return func(
		ctx context.Context,
		req interface{},
		info *grpc.UnaryServerInfo,
		handler grpc.UnaryHandler,
	) (interface{}, error) {
		if err := i.authorize(ctx, info.FullMethod); err != nil {
			return nil, err
		}

		return handler(ctx, req)
	}
}

// Stream returns a new streaming server interceptor that performs authorization
// on streaming RPC calls.
func (i AuthInterceptor) Stream() grpc.StreamServerInterceptor {
	return func(
		srv interface{},
		stream grpc.ServerStream,
		info *grpc.StreamServerInfo,
		handler grpc.StreamHandler,
	) error {
		if err := i.authorize(stream.Context(), info.FullMethod); err != nil {
			return err
		}

		return handler(srv, stream)
	}
}

func (i *AuthInterceptor) authorize(
	ctx context.Context,
	fullMethod string,
) error {
	token, err := getAccessTokenFrom(ctx)
	if err != nil {
		return err
	}

	path, action := splitFullMethod(fullMethod)
	err = i.enforcer.CheckAccess(ctx, &token, e.ByPath(path, action))

	if err != nil {
		log.Warn().
			Err(err).
			Str("path", path).
			Str("action", string(action)).
			Msg("access to resource was denied")
		return status.Error(codes.PermissionDenied, "access denied")
	}

	return nil
}

func getAccessTokenFrom(ctx context.Context) (string, error) {
	const tokenPrefix = "bearer "

	// get metadata from context
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return "", status.Error(codes.Unauthenticated, "missing request metadata")
	}

	// get authorization header
	values := md["authorization"]
	if len(values) == 0 {
		return "", status.Error(codes.Unauthenticated, "missing access token")
	}

	// validate access token format
	token := values[0]
	if len(token) < 7 || strings.ToLower(token[:7]) != "bearer " {
		return "", status.Error(codes.Unauthenticated, "invalid access token")
	}

	return token[7:], nil
}

func splitFullMethod(
	fullMethod string,
) (string, e.ActionMethod) {
	const SLASH = 0x2F

	lastSlashIdx := strings.LastIndexByte(fullMethod, SLASH)

	// check for invalid format
	if lastSlashIdx == -1 || lastSlashIdx == len(fullMethod)-1 {
		log.Panic().
			Str("fullMethod", fullMethod).
			Int("lastSlashIdx", lastSlashIdx).
			Msg("invalid method format")
	}

	path := fullMethod[:lastSlashIdx]
	method := fullMethod[lastSlashIdx+1:]

	return path, e.ActionMethod(method)
}
