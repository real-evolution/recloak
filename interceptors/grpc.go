package interceptors

import (
	"context"
	"strings"

	"github.com/rs/zerolog/log"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	e "github.com/real-evolution/recloak/enforcer"
)

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
			Str("fullMethod", fullMethod).
			Msg("could not decode access token")

		return nil, status.Error(codes.Unauthenticated, "invalid access token")
	}

	err = i.enforcer.CheckAccess(ctx, &token.Token.Raw, getByPathPerm(fullMethod))
	if err != nil {
		log.Warn().
			Err(err).
			Str("fullMethod", fullMethod).
			Msg("access to resource was denied")

		return nil, status.Error(codes.PermissionDenied, "access denied")
	}

	return token.WrapContext(ctx), nil
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

func getByPathPerm(fullMethod string) e.PermissionFactory {
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

	return e.ByPath(path, e.ActionMethod(method))
}
