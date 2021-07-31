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
	"time"

	"github.com/flamego/flamego"
	"github.com/flamego/session"
)

// CSRF represents a CSRF service and is used to get the current token and validate a suspect token.
type CSRF interface {
	// Return HTTP header to search for token.
	HeaderName() string
	// Return form value to search for token.
	FormName() string
	// Return cookie name to search for token.
	CookieName() string
	// Return cookie path
	CookiePath() string
	// Return the flag value used for the csrf token.
	CookieHttpOnly() bool
	// Return the token.
	Token() string
	// Validate by token.
	ValidToken(t string) bool
	// Error replies to the request with a custom function when ValidToken fails.
	Error(w http.ResponseWriter)
}

type csrf struct {
	// Header name value for setting and getting csrf token.
	header string
	// Form name value for setting and getting csrf token.
	form string
	// Cookie name value for setting and getting csrf token.
	cookie string
	// Cookie domain
	cookieDomain string
	// Cookie path
	cookiePath string
	// Cookie HttpOnly flag value used for the csrf token.
	cookieHttpOnly bool
	// Token generated to pass via header, cookie, or hidden form value.
	token string
	// This value must be unique per user.
	id string
	// Secret used along with the unique id above to generate the Token.
	secret string
	// ErrorFunc is the custom function that replies to the request when ValidToken fails.
	errorFunc func(w http.ResponseWriter)
}

// HeaderName returns the name of the HTTP header for csrf token.
func (c *csrf) HeaderName() string {
	return c.header
}

// FormName returns the name of the form value for csrf token.
func (c *csrf) FormName() string {
	return c.form
}

// CookieName returns the name of the cookie for csrf token.
func (c *csrf) CookieName() string {
	return c.cookie
}

// CookiePath returns the path of the cookie for csrf token.
func (c *csrf) CookiePath() string {
	return c.cookiePath
}

// CookieHttpOnly returns the flag value used for the csrf token.
func (c *csrf) CookieHttpOnly() bool {
	return c.cookieHttpOnly
}

// Token returns the current token. This is typically used
// to populate a hidden form in an HTML template.
func (c *csrf) Token() string {
	return c.token
}

// ValidToken validates the passed token against the existing Secret and ID.
func (c *csrf) ValidToken(t string) bool {
	return ValidToken(t, c.secret, c.id, "POST")
}

// Error replies to the request when ValidToken fails.
func (c *csrf) Error(w http.ResponseWriter) {
	c.errorFunc(w)
}

// Options maintains options to manage behavior of Generate.
type Options struct {
	// The global secret value used to generate Tokens.
	Secret string
	// HTTP header used to set and get token.
	Header string
	// Form value used to set and get token.
	Form string
	// Cookie value used to set and get token.
	Cookie string
	// Cookie domain.
	CookieDomain string
	// Cookie path.
	CookiePath string
	// Enable cookie HttpOnly attribute.
	CookieHttpOnly bool
	// Key used for getting the unique ID per user.
	SessionKey string
	// oldSeesionKey saves old value corresponding to SessionKey.
	oldSeesionKey string
	// If true, send token via X-CSRFToken header.
	SetHeader bool
	// If true, send token via _csrf cookie.
	SetCookie bool
	// Set the Secure flag to true on the cookie.
	Secure bool
	// Disallow Origin appear in request header.
	Origin bool
	// The function called when Validate fails.
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

func prepareOptions(options []Options) Options {
	var opt Options
	if len(options) > 0 {
		opt = options[0]
	}

	// Defaults.
	if len(opt.Secret) == 0 {
		opt.Secret = string(randomBytes(10))
	}
	if len(opt.Header) == 0 {
		opt.Header = "X-CSRFToken"
	}
	if len(opt.Form) == 0 {
		opt.Form = "_csrf"
	}
	if len(opt.Cookie) == 0 {
		opt.Cookie = "_csrf"
	}
	if len(opt.CookiePath) == 0 {
		opt.CookiePath = "/"
	}
	if len(opt.SessionKey) == 0 {
		opt.SessionKey = "uid"
	}
	opt.oldSeesionKey = "_old_" + opt.SessionKey
	if opt.ErrorFunc == nil {
		opt.ErrorFunc = func(w http.ResponseWriter) {
			http.Error(w, "Invalid csrf token.", http.StatusBadRequest)
		}
	}

	return opt
}

// Generate maps CSRF to each request. If this request is a Get request, it will generate a new token.
// Additionally, depending on options set, generated tokens will be sent via Header and/or Cookie.
func Generate(options ...Options) flamego.Handler {
	opt := prepareOptions(options)
	return func(ctx flamego.Context, sess session.Session) {
		x := &csrf{
			secret:         opt.Secret,
			header:         opt.Header,
			form:           opt.Form,
			cookie:         opt.Cookie,
			cookieDomain:   opt.CookieDomain,
			cookiePath:     opt.CookiePath,
			cookieHttpOnly: opt.CookieHttpOnly,
			errorFunc:      opt.ErrorFunc,
		}
		ctx.MapTo(x, (*CSRF)(nil))

		if opt.Origin && len(ctx.Request().Header.Get("Origin")) > 0 {
			return
		}

		x.id = "0"
		uid := sess.Get(opt.SessionKey)
		if uid != nil {
			x.id = fmt.Sprintf("%s", uid)
		}

		needsNew := false
		oldUid := sess.Get(opt.oldSeesionKey)
		if oldUid == nil || oldUid.(string) != x.id {
			needsNew = true
			sess.Set(opt.oldSeesionKey, x.id)
		} else {
			// If cookie present, map existing token, else generate a new one.
			if cookie := ctx.Cookie(opt.Cookie); len(cookie) > 0 {
				// FIXME: test coverage
				x.token = cookie
			} else {
				needsNew = true
			}
		}

		if needsNew {
			// FIXME: actionId.
			x.token = GenerateToken(x.secret, x.id, "POST")
			if opt.SetCookie {
				cookie := http.Cookie{
					Name:     opt.Cookie,
					Value:    x.token,
					Path:     opt.CookiePath,
					Domain:   opt.CookieDomain,
					HttpOnly: opt.CookieHttpOnly,
					Secure:   opt.Secure,
					Expires:  time.Now().AddDate(0, 0, 1),
					MaxAge:   0,
				}
				ctx.SetCookie(cookie)
			}
		}

		if opt.SetHeader {
			ctx.ResponseWriter().Header().Add(opt.Header, x.token)
		}
	}
}

// Csrfer maps CSRF to each request. If this request is a Get request, it will generate a new token.
// Additionally, depending on options set, generated tokens will be sent via Header and/or Cookie.
func Csrfer(options ...Options) flamego.Handler {
	return Generate(options...)
}

// Validate should be used as a per route middleware. It attempts to get a token from a "X-CSRFToken"
// HTTP header and then a "_csrf" form value. If one of these is found, the token will be validated
// using ValidToken. If this validation fails, custom Error is sent in the reply.
// If neither a header or form value is found, http.StatusBadRequest is sent.
func Validate(ctx flamego.Context, x CSRF) {
	if token := ctx.Request().Header.Get(x.HeaderName()); len(token) > 0 {
		if !x.ValidToken(token) {
			cookie := http.Cookie{
				Name:   x.CookieName(),
				Value:  "",
				Path:   x.CookiePath(),
				MaxAge: -1,
			}
			ctx.SetCookie(cookie)
			x.Error(ctx.ResponseWriter())
		}
		return
	}

	if token := ctx.Request().FormValue(x.FormName()); len(token) > 0 {
		if !x.ValidToken(token) {
			cookie := http.Cookie{
				Name:   x.CookieName(),
				Value:  "",
				Path:   x.CookiePath(),
				MaxAge: -1,
			}
			ctx.SetCookie(cookie)
			x.Error(ctx.ResponseWriter())
		}
		return
	}

	http.Error(ctx.ResponseWriter(), "Bad Request: no CSRF token present", http.StatusBadRequest)
}
