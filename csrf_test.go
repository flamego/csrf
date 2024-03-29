// Copyright 2021 Flamego. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

package csrf

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/flamego/session/redis"
	"github.com/stretchr/testify/assert"

	"github.com/flamego/flamego"
	"github.com/flamego/session"
)

func TestGenerateToken(t *testing.T) {
	f := flamego.NewWithLogger(&bytes.Buffer{})
	f.Use(session.Sessioner())
	f.Use(Csrfer())

	f.Get("/login", func(s session.Session, x CSRF) {
		s.Set(defaultSessionKey, "123456")
	})

	f.Combo("/private").
		Get(func(x CSRF) string { return x.Token() }). // Generate token via GET request
		Post(Validate, func() {})

	resp := httptest.NewRecorder()
	req, err := http.NewRequest(http.MethodGet, "/login", nil)
	assert.NoError(t, err)

	f.ServeHTTP(resp, req)

	// Obtain the session cookie
	cookie := resp.Header().Get("Set-Cookie")

	resp = httptest.NewRecorder()
	req, err = http.NewRequest(http.MethodGet, "/private", nil)
	assert.NoError(t, err)

	req.Header.Set("Cookie", cookie)
	f.ServeHTTP(resp, req)

	token := resp.Body.String()
	form := url.Values{}
	form.Set(defaultForm, token)

	resp = httptest.NewRecorder()
	req, err = http.NewRequest(http.MethodPost, "/private", strings.NewReader(form.Encode()))
	assert.NoError(t, err)

	req.Header.Set("Cookie", cookie)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	f.ServeHTTP(resp, req)

	assert.Equal(t, http.StatusOK, resp.Code)
}

func TestGenerateToken_Header(t *testing.T) {
	tests := []struct {
		name       string
		header     string
		wantHeader string
	}{
		{
			name:       "default",
			wantHeader: defaultHeader,
		},
		{
			name:       "default",
			header:     "X-Custom",
			wantHeader: "X-Custom",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			f := flamego.NewWithLogger(&bytes.Buffer{})
			f.Use(session.Sessioner())
			f.Use(
				Csrfer(
					Options{
						SetHeader: true,
						Header:    test.header,
					},
				),
			)

			f.Get("/login", func(s session.Session, x CSRF) {
				s.Set(defaultSessionKey, "123456")
			})

			f.Combo("/private").
				Get(func() {}). // Generate token via GET request
				Post(Validate, func() {})

			resp := httptest.NewRecorder()
			req, err := http.NewRequest(http.MethodGet, "/login", nil)
			assert.NoError(t, err)

			f.ServeHTTP(resp, req)

			// Obtain the session cookie
			cookie := resp.Header().Get("Set-Cookie")

			resp = httptest.NewRecorder()
			req, err = http.NewRequest(http.MethodGet, "/private", nil)
			assert.NoError(t, err)

			req.Header.Set("Cookie", cookie)
			f.ServeHTTP(resp, req)

			token := resp.Header().Get(test.wantHeader)
			assert.NotEmpty(t, token)

			resp = httptest.NewRecorder()
			req, err = http.NewRequest(http.MethodPost, "/private", nil)
			assert.NoError(t, err)

			req.Header.Set("Cookie", cookie)
			req.Header.Set(test.wantHeader, token)
			f.ServeHTTP(resp, req)

			assert.Equal(t, http.StatusOK, resp.Code)
		})
	}
}

func TestGenerateToken_NoOrigin(t *testing.T) {
	f := flamego.NewWithLogger(&bytes.Buffer{})
	f.Use(session.Sessioner())
	f.Use(
		Csrfer(
			Options{
				SetHeader: true,
				NoOrigin:  true,
			},
		),
	)

	f.Get("/login", func(sess session.Session) {
		sess.Set(defaultSessionKey, "123456")
	})

	// Generate token via GET request
	f.Get("/private", func() {})

	resp := httptest.NewRecorder()
	req, err := http.NewRequest(http.MethodGet, "/login", nil)
	assert.NoError(t, err)

	f.ServeHTTP(resp, req)

	// Obtain the session cookie
	cookie := resp.Header().Get("Set-Cookie")

	resp = httptest.NewRecorder()
	req, err = http.NewRequest(http.MethodGet, "/private", nil)
	assert.NoError(t, err)

	req.Header.Set("Cookie", cookie)
	req.Header.Set("Origin", "https://www.example.com")
	f.ServeHTTP(resp, req)

	assert.Empty(t, resp.Header().Get(defaultHeader))
}

func TestInvalid(t *testing.T) {
	tests := []struct {
		name     string
		options  Options
		wantCode int
		wantBody string
	}{
		{
			name:     "default error",
			options:  Options{},
			wantCode: http.StatusBadRequest,
			wantBody: "Bad Request: invalid CSRF token\n",
		},
		{
			name: "custom error",
			options: Options{
				ErrorFunc: func(w http.ResponseWriter) {
					http.Error(w, "custom error", http.StatusUnprocessableEntity)
				},
			},
			wantCode: http.StatusUnprocessableEntity,
			wantBody: "custom error\n",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			f := flamego.NewWithLogger(&bytes.Buffer{})
			f.Use(session.Sessioner())
			f.Use(Csrfer(test.options))

			f.Get("/login", func(sess session.Session) {
				sess.Set(defaultSessionKey, "123456")
			})

			f.Combo("/private").
				Get(func(x CSRF) string { return x.Token() }). // Generate token via GET request
				Post(Validate, func() {})

			resp := httptest.NewRecorder()
			req, err := http.NewRequest(http.MethodGet, "/login", nil)
			assert.NoError(t, err)

			f.ServeHTTP(resp, req)

			// Obtain the session cookie
			cookie := resp.Header().Get("Set-Cookie")

			resp = httptest.NewRecorder()
			req, err = http.NewRequest(http.MethodGet, "/private", nil)
			assert.NoError(t, err)

			req.Header.Set("Cookie", cookie)
			f.ServeHTTP(resp, req)

			t.Run("invalid form value", func(t *testing.T) {
				form := url.Values{}
				form.Set(defaultForm, "invalid")

				resp = httptest.NewRecorder()
				req, err = http.NewRequest(http.MethodPost, "/private", strings.NewReader(form.Encode()))
				assert.NoError(t, err)

				req.Header.Set("Cookie", cookie)
				req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
				f.ServeHTTP(resp, req)

				assert.Equal(t, test.wantCode, resp.Code)
				assert.Equal(t, test.wantBody, resp.Body.String())
			})

			t.Run("invalid HTTP header", func(t *testing.T) {
				resp = httptest.NewRecorder()
				req, err = http.NewRequest(http.MethodPost, "/private", nil)
				assert.NoError(t, err)

				req.Header.Set("Cookie", cookie)
				req.Header.Set(defaultHeader, "invalid")
				f.ServeHTTP(resp, req)

				assert.Equal(t, test.wantCode, resp.Code)
				assert.Equal(t, test.wantBody, resp.Body.String())
			})
		})
	}
}

func TestTokenExpired(t *testing.T) {
	f := flamego.NewWithLogger(&bytes.Buffer{})
	f.Use(session.Sessioner())
	f.Use(Csrfer())

	f.Get("/touch", func(x CSRF) string { return x.Token() })
	f.Post("/set-expired", Validate, func(s session.Session) {
		s.Set(tokenExpiredAtKey, time.Now())
	})

	resp := httptest.NewRecorder()
	req, err := http.NewRequest(http.MethodGet, "/touch", nil)
	assert.NoError(t, err)

	f.ServeHTTP(resp, req)

	// Obtain the session cookie and token
	cookie := resp.Header().Get("Set-Cookie")
	token := resp.Body.String()

	form := url.Values{}
	form.Set(defaultForm, token)

	resp = httptest.NewRecorder()
	req, err = http.NewRequest(http.MethodPost, "/set-expired", strings.NewReader(form.Encode()))
	assert.NoError(t, err)

	req.Header.Set("Cookie", cookie)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	f.ServeHTTP(resp, req)

	assert.Equal(t, http.StatusOK, resp.Code)

	// NOTE: It appears that time.Now().UnixNano() sometimes is the same if the test
	// runs too faster (within the same second) on Windows, which results generating
	// the same CSRF token. So let's sleep for one second on Windows.
	if runtime.GOOS == "windows" {
		time.Sleep(time.Second)
	}

	// Touch should now return a new token
	resp = httptest.NewRecorder()
	req, err = http.NewRequest(http.MethodGet, "/touch", nil)
	assert.NoError(t, err)

	req.Header.Set("Cookie", cookie)
	f.ServeHTTP(resp, req)

	assert.Equal(t, http.StatusOK, resp.Code)
	assert.NotEmpty(t, resp.Body.String())
	assert.NotEqual(t, token, resp.Body.String())
}

func TestGobSerialization(t *testing.T) {
	f := flamego.NewWithLogger(&bytes.Buffer{})

	const db = 15
	f.Use(session.Sessioner(session.Options{
		Initer: redis.Initer(),
		Config: redis.Config{
			Options: &redis.Options{
				Addr: os.ExpandEnv("$REDIS_HOST:$REDIS_PORT"),
				DB:   db,
			},
		},
	}))
	f.Use(Csrfer())

	var token string
	f.Get("/touch", func(x CSRF) string {
		token = x.Token()
		return token
	})

	resp := httptest.NewRecorder()
	req, err := http.NewRequest(http.MethodGet, "/touch", nil)
	assert.NoError(t, err)

	f.ServeHTTP(resp, req)
	assert.Equal(t, http.StatusOK, resp.Code)
	assert.Equal(t, token, resp.Body.String())
}
