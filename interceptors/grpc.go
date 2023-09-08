package interceptors

import (
	"context"
	"strings"

	"github.com/rs/zerolog/log"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"

	// "google.golang.org/protobuf/reflect/protoreflect"

	"github.com/real-evolution/recloak"
	e "github.com/real-evolution/recloak/enforcer"
)

var ErrPermissionDenied = status.Error(codes.PermissionDenied, "access denied")

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
		if ctx, err = i.authorize(ctx, info.FullMethod, req); err != nil {
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
		ctx, err := i.authorize(stream.Context(), info.FullMethod, nil)
		if err != nil {
			return err
		}

		return handler(srv, &WrappedServerStream{stream, ctx})
	}
}

func (i *AuthInterceptor) authorize(
	ctx context.Context,
	fullMethod string,
	req interface{},
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

	actions, err := i.enforcer.ResourceMap().GetActions(getByPathPerm(fullMethod))
	if err != nil {
		log.Error().
			Err(err).
			Msg("could not generate permission strings, check your map definitions")

		return nil, status.Error(codes.Internal, "internal server error")
	}

	opts := recloak.CheckAccessParams{
		AccessToken: &token.Token.Raw,
		Permissions: make([]string, 0),
		Claims:      make(map[string]interface{}),
	}

	for _, action := range actions {
		opts.Permissions = append(opts.Permissions, action.Permission)
		emitActionClaims(action, req, &opts.Claims)
	}

	if err := i.enforcer.Client().CheckAccess(ctx, opts); err != nil {
		log.Warn().
			Err(err).
			Str("fullMethod", fullMethod).
			Msg("access to resource was denied")

		return nil, ErrPermissionDenied
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

func getByPathPerm(fullMethod string) e.ActionSelector {
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

// Gets the permission string of the action.
func emitActionClaims(action e.Action, input any, out *map[string]any) {
	if len(action.Claims) == 0 {
		return
	}

	inputMsg, ok := input.(proto.Message)
	if !ok {
		log.Error().
			Str("action", string(action.Method)).
			Msg("invalid or nil input for action claims")

		return
	}

	refInputMsg := inputMsg.ProtoReflect()
	inputFields := refInputMsg.Descriptor().Fields()

	for _, claim := range action.Claims {
		switch claim.Source {
		case e.ResourceClaimResourceRequest:
			field := inputFields.ByName(protoreflect.Name(claim.Name))

			if field == nil {
				log.Error().
					Str("action", string(action.Method)).
					Str("claimName", string(claim.Name)).
					Msg("action claim requested but not found, setting to nil")

				(*out)[string(claim.Name)] = nil
				continue
			}

			var fieldKey string
			if claim.Alias != "" {
				fieldKey = string(claim.Alias)
			} else {
				fieldKey = string(claim.Name)
			}

			fieldVal := refInputMsg.Get(field)

			if field.IsList() {
				(*out)[fieldKey] = fieldVal.Interface()
			} else {
				claims := make([]any, 1)
				claims[0] = fieldVal.Interface()

				(*out)[fieldKey] = claims
			}
		}
	}
}
