package grpc

import (
	"context"

	"github.com/rs/zerolog/log"
	"google.golang.org/grpc"

	"github.com/real-evolution/recloak/authz"
)

// Interceptor is a gRPC interceptor that checks the request against the enforcer.
type Interceptor struct {
	enforcer *authz.Enforcer
}

// NewGrpcInterceptor creates a new gRPC interceptor.
func NewGrpcInterceptor(e *authz.Enforcer) Interceptor {
	return Interceptor{enforcer: e}
}

// Unary returns a new unary server interceptors that performs authorization
// on unary RPC calls.
func (i *Interceptor) Unary() grpc.UnaryServerInterceptor {
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
func (i *Interceptor) Stream() grpc.StreamServerInterceptor {
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

func (i *Interceptor) authorize(
	ctx context.Context,
	fullMethod string,
	req any,
) (context.Context, error) {
	wrappedCtx, err := i.doAuthorize(ctx, fullMethod, req)
	if err != nil {
		log.Warn().Err(err).Str("fullMethod", fullMethod).Msg("authorization failed")
		return nil, err
	}

	return wrappedCtx, nil
}

func (i *Interceptor) doAuthorize(
	ctx context.Context,
	fullMethod string,
	req any,
) (context.Context, error) {
	log.Debug().Str("fullMethod", fullMethod).Msg("authorizing request")

	header, err := extractAuthorizationHeader(ctx)
	if err != nil {
		return nil, err
	}

	rawToken, err := extractBearerToken(header)
	if err != nil {
		return nil, err
	}

	token, err := i.enforcer.Authorize(ctx, rawToken, fullMethod, req)
	if err != nil {
		return nil, err
	}

	return token.WrapContext(ctx), nil
}
