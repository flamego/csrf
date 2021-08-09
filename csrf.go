// Copyright 2021 Flamego. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

// Package csrf is a middleware that generates and validates CSRF tokens for Flamego.
package csrf

import (
	"crypto/rand"
	"fmt"
	r "math/rand"
	"net/http"
	"reflect"
	"time"

	"github.com/flamego/flamego"
	"github.com/flamego/flamego/inject"
	"github.com/flamego/session"
)

// CSRF represents a CSRF service and is used to get the current token and
// validate a suspect token.
type CSRF interface {
	// Token returns the current token. This is typically used to populate a hidden
	// form in an HTML template.
	Token() string
	// ValidToken validates the passed token against the existing Secret and ID.
	ValidToken(t string) bool
	// Error executes the error function with given http.ResponseWriter.
	Error(w http.ResponseWriter)
	// Validate validates CSRF using given context. It attempts to get the token
	// from the HTTP header and then the form value. If any of these is found, the
	// token will be validated using ValidToken. If the validation fails, custom
	// Error is sent as the response. If neither the header nor form value is found,
	// http.StatusBadRequest is sent.
	Validate(ctx flamego.Context)
}

type csrf struct {
	// Header name value for setting and getting CSRF token.
	header string
	// Form name value for setting and getting CSRF token.
	form string
	// Token generated to pass via header or hidden form value.
	token string
	// The value to uniquely identify a user.
	id string
	// Secret used along with the unique id above to generate the token.
	secret string
	// The custom function that replies to the request when ValidToken fails.
	errorFunc func(w http.ResponseWriter)
}

func (c *csrf) Token() string {
	return c.token
}

func (c *csrf) ValidToken(t string) bool {
	return ValidToken(t, c.secret, c.id, http.MethodPost)
}

func (c *csrf) Error(w http.ResponseWriter) {
	c.errorFunc(w)
}

func (c *csrf) Validate(ctx flamego.Context) {
	if token := ctx.Request().Header.Get(c.header); token != "" {
		if !c.ValidToken(token) {
			c.Error(ctx.ResponseWriter())
		}
		return
	}

	if token := ctx.Request().FormValue(c.form); token != "" {
		if !c.ValidToken(token) {
			c.Error(ctx.ResponseWriter())
		}
		return
	}

	http.Error(ctx.ResponseWriter(), "Bad Request: no CSRF token present", http.StatusBadRequest)
}

// Options contains options for the csrf.Csrfer middleware.
type Options struct {
	// Secret is the secret value used to generate tokens. Default is an
	// auto-generated 10-char random string.
	Secret string
	// Header specifies which HTTP header to be used to set and get token. Default
	// is "X-CSRF-Token".
	Header string
	// Form specifies which form value to be used to set and get token. Default is
	// "_csrf".
	Form string
	// SessionKey is the session key used to get the unique ID of users. Default is
	// "userID".
	SessionKey string
	// SetHeader indicates whether to send token via Header. Default is false.
	SetHeader bool
	// NoOrigin indicates whether to disallow Origin appear in the request header.
	// Default is false.
	NoOrigin bool
	// ErrorFunc defines the function to be executed when ValidToken fails.
	ErrorFunc func(w http.ResponseWriter)
}

// randomBytes generates n random []byte.
func randomBytes(n int) []byte {
	const alphanum = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
	var bytes = make([]byte, n)
	var randby bool
	if num, err := rand.Read(bytes); num != n || err != nil {
		r.Seed(time.Now().UnixNano())
		randby = true
	}
	for i, b := range bytes {
		if randby {
			bytes[i] = alphanum[r.Intn(len(alphanum))]
		} else {
			bytes[i] = alphanum[b%byte(len(alphanum))]
		}
	}
	return bytes
}

var _ inject.FastInvoker = (*csrfInvoker)(nil)

// csrfInvoker is an inject.FastInvoker implementation of `func(flamego.Context, session.Session)`.
type csrfInvoker func(flamego.Context, session.Session)

func (invoke csrfInvoker) Invoke(args []interface{}) ([]reflect.Value, error) {
	invoke(args[0].(flamego.Context), args[1].(session.Session))
	return nil, nil
}

const (
	defaultHeader     = "X-CSRF-Token"
	defaultForm       = "_csrf"
	defaultSessionKey = "userID"
)

const tokenExpiredAtKey = "flamego::csrf::tokenExpiredAt"

// Csrfer returns a middleware handler that injects csrf.CSRF into the request
// context, and only generates a new CSRF token on every GET request.
func Csrfer(opts ...Options) flamego.Handler {
	var opt Options
	if len(opts) > 0 {
		opt = opts[0]
	}

	parseOptions := func(opts Options) Options {
		if opt.Secret == "" {
			opt.Secret = string(randomBytes(10))
		}

		if opt.Header == "" {
			opt.Header = defaultHeader
		}

		if opt.Form == "" {
			opt.Form = defaultForm
		}

		if opt.SessionKey == "" {
			opt.SessionKey = defaultSessionKey
		}

		if opt.ErrorFunc == nil {
			opt.ErrorFunc = func(w http.ResponseWriter) {
				http.Error(w, "Bad Request: invalid CSRF token", http.StatusBadRequest)
			}
		}
		return opt
	}

	opt = parseOptions(opt)
	return csrfInvoker(func(c flamego.Context, s session.Session) {
		x := &csrf{
			secret:    opt.Secret,
			header:    opt.Header,
			form:      opt.Form,
			errorFunc: opt.ErrorFunc,
		}
		c.MapTo(x, (*CSRF)(nil))

		id := s.Get(opt.SessionKey)
		if id != nil {
			x.id = fmt.Sprintf("%v", id)
		} else {
			x.id = "0"
		}

		const oldIDKey = "flamego::csrf::oldID"
		const tokenKey = "flamego::csrf::token"
		needsNewToken := func(s session.Session, x *csrf) bool {
			if opt.NoOrigin && c.Request().Header.Get("Origin") != "" {
				return false
			}

			// The value of ID can change upon user authentication, we need to generate a
			// new CSRF token whenever the old and the current ID do not match.
			oldID, ok := s.Get(oldIDKey).(string)
			if !ok || oldID != x.id {
				return true
			}

			// Check if the current CSRF token has expired.
			if expiredAt, ok := s.Get(tokenExpiredAtKey).(time.Time); !ok || !expiredAt.After(time.Now()) {
				return true
			}

			// Check if the session already has a CSRF token, and so map the existing one.
			if token, ok := s.Get(tokenKey).(string); ok && token != "" {
				x.token = token
				return false
			}

			if c.Request().Method != http.MethodGet {
				return false
			}

			return true
		}

		if !needsNewToken(s, x) {
			return
		}

		x.token = GenerateToken(x.secret, x.id, http.MethodPost)
		s.Set(oldIDKey, x.id)
		s.Set(tokenKey, x.token)
		s.Set(tokenExpiredAtKey, time.Now().Add(timeout).Add(-1*time.Minute)) // Renew token before the hard timeout

		if opt.SetHeader && x.token != "" {
			c.ResponseWriter().Header().Set(opt.Header, x.token)
		}
	})
}

// Validate should be used as a per route middleware to validate CSRF tokens.
func Validate(ctx flamego.Context, x CSRF) {
	x.Validate(ctx)
}
