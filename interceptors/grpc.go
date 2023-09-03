package interceptors

import (
	"context"
	"strings"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	"github.com/golang-jwt/jwt/v4"
	"github.com/rs/zerolog/log"

	e "github.com/real-evolution/recloak/enforcer"
)

// ContextKey is the type used to store values in the context.
type ContextKey string

const (
	// AuthTokenKey is the key used to store the JWT token in the context.
	AuthTokenKey ContextKey = "authToken"
)

// AuthToken is a wrapper around `jwt.Token` and `jwt.RegisteredClaims`.
type AuthToken struct {
	Token  *jwt.Token
	Claims *jwt.RegisteredClaims
}

// AuthInterceptor is a gRPC server interceptor that performs authorization
type AuthInterceptor struct {
	enforcer *e.PolicyEnforcer
}

// NewAuthInterceptor creates a new AuthInterceptor with the given PolicyEnforcer.
func NewAuthInterceptor(enforcer *e.PolicyEnforcer) AuthInterceptor {
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
	) (ret interface{}, err error) {
		if ctx, err = i.authorize(ctx, info.FullMethod); err != nil {
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
		ctx, err := i.authorize(stream.Context(), info.FullMethod)
		if err != nil {
			return err
		}

		return handler(srv, &WrappedServerStream{stream, ctx})
	}
}

func (i *AuthInterceptor) authorize(
	ctx context.Context,
	fullMethod string,
) (context.Context, error) {
	authHeader, err := getAuthorizationHeaderFrom(ctx)
	if err != nil {
		return nil, err
	}

	token, err := i.enforcer.Client().DecodeAccessToken(ctx, authHeader)
	if err != nil {
		log.Warn().
			Err(err).
			Str("token", authHeader).
			Str("fullMethod", fullMethod).
			Msg("Unauthenticated request")

		return nil, status.Error(codes.Unauthenticated, "invalid access token")
	}

	claims, ok := token.Claims.(*jwt.RegisteredClaims)
	if !ok {
		log.Panic().Msg("invalid token claims")
	}

	path, action := splitFullMethod(fullMethod)
	if err := i.enforcer.CheckAccess(ctx, &token.Raw, e.ByPath(path, action)); err != nil {
		log.Warn().
			Err(err).
			Str("path", path).
			Str("action", string(action)).
			Msg("access to resource was denied")

		return nil, status.Error(codes.PermissionDenied, "access denied")
	}

	return context.WithValue(ctx, AuthTokenKey, AuthToken{token, claims}), nil
}

func getAuthorizationHeaderFrom(ctx context.Context) (string, error) {
	// get metadata from context
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return "", status.Error(codes.Unauthenticated, "missing request metadata")
	}

	// get authorization header
	values := md["authorization"]
	if len(values) == 0 {
		return "", status.Error(codes.Unauthenticated, "missing authorization header")
	}

	return values[0], nil
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
