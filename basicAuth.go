package basic_auth

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"github.com/go-kratos/kratos/v2/errors"
	"github.com/go-kratos/kratos/v2/middleware"
	"github.com/go-kratos/kratos/v2/transport"
)

const (
	reason                = "UNAUTHORIZED"
	basic                 = "Basic"
	defaultRealm          = "Restricted"
	authorizationKey      = "Authorization"
	wwwAuthenticateHeader = "WWW-Authenticate"
)

var (
	ErrUnauthorized    = errors.Unauthorized(reason, "Not authorized")
	ErrValidatorNotSet = errors.Unauthorized(reason, "basic auth validator is not set")
)

func Server(opts ...Option) middleware.Middleware {
	o := &options{}
	for _, opt := range opts {
		opt(o)
	}
	if o.realm == "" {
		o.realm = defaultRealm
	}

	return func(handler middleware.Handler) middleware.Handler {
		return func(ctx context.Context, req interface{}) (reply interface{}, err error) {
			if o.validator == nil {
				return nil, ErrValidatorNotSet
			}
			if tr, ok := transport.FromServerContext(ctx); ok {
				auth := tr.RequestHeader().Get(authorizationKey)
				l := len(basic)
				if len(auth) > l+1 && strings.EqualFold(auth[:l], basic) {
					// Invalid base64 shouldn't be treated as error
					// instead should be treated as invalid client input
					b, err := base64DecodeRealm(auth[l+1:])
					if err != nil {
						return nil, err
					}
					cred := unsafeString(b)
					for i := 0; i < len(cred); i++ {
						if cred[i] == ':' {
							// Verify credentials
							valid, err := o.validator(cred[:i], cred[i+1:], ctx)
							if err != nil {
								return nil, err
							}
							if valid {
								return handler(ctx, req)
							}
							break
						}
					}
				}
				// Unauthorized
				realm := defaultRealm
				if o.realm != defaultRealm {
					realm = strconv.Quote(realm)
				}

				//  return `401` to let browsers to pop-up login box.
				tr.ReplyHeader().Set(wwwAuthenticateHeader, fmt.Sprintf("%s realm=%s", basic, realm))

			}
			return nil, ErrUnauthorized
		}
	}
}

func Client(opts ...Option) middleware.Middleware {
	o := &options{}
	for _, opt := range opts {
		opt(o)
	}
	if o.realm == "" {
		o.realm = defaultRealm
	}
	return func(handler middleware.Handler) middleware.Handler {
		return func(ctx context.Context, req interface{}) (interface{}, error) {
			if o.validator == nil {
				return nil, ErrValidatorNotSet
			}
			if tr, ok := transport.FromClientContext(ctx); ok {
				realm := defaultRealm
				if o.realm != defaultRealm {
					realm = base64EncodeRealm(o.realm)
				}
				tr.RequestHeader().Set(authorizationKey, basic+" realm="+realm)
				return handler(ctx, req)
			}
			return nil, ErrUnauthorized
		}
	}
}
