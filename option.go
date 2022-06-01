package basic_auth

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
)

type Validator func(string, string, context.Context) (bool, error)

var (
	defaultValidatorProvider = func(opt *options, ctx context.Context) Validator {
		return func(username string, password string, ctx context.Context) (bool, error) {
			usernameHash := sha256.Sum256([]byte(username))
			passwordHash := sha256.Sum256([]byte(password))
			usernameMatch := subtle.ConstantTimeCompare(usernameHash[:], opt.expectUser[:]) == 1
			passwordMatch := subtle.ConstantTimeCompare(passwordHash[:], opt.expectUserPassword[:]) == 1
			return usernameMatch && passwordMatch, nil
		}
	}
)

type options struct {
	// Validator is a function to validate BasicAuth credentials.
	// Required.
	validator Validator

	// realm is a string to define realm attribute of BasicAuth.
	// Default value "Restricted".
	realm string

	expectUser         [32]byte
	expectUserPassword [32]byte
}

type Option func(config *options)

// WithValidator allow user to impl username and passwordCheck
func WithValidator(validator Validator) Option {
	return func(opt *options) {
		if opt.validator != nil {
			// if user use WithAuthentication,avoid overwrite
			return
		}
		opt.validator = validator
	}
}

// WithRealm sets the realm attribute of BasicAuth.
// the realm identifies the system to authenticate against
// and can be used by clients to save credentials
// Optional. Default: "Restricted".
// see https://datatracker.ietf.org/doc/html/rfc2617#section-2
func WithRealm(realm string) Option {
	return func(opt *options) {
		opt.realm = realm
	}
}

// WithAuthentication use user specified userName and password for checking
func WithAuthentication(userName, password string) Option {
	return func(opt *options) {
		opt.expectUser = sha256.Sum256(unsafeBytes(userName))
		opt.expectUserPassword = sha256.Sum256(unsafeBytes(password))
		opt.validator = defaultValidatorProvider(opt, context.Background())
	}
}
