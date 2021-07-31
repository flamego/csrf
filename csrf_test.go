// Copyright 2021 Flamego. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

package csrf

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/flamego/flamego"
	"github.com/flamego/session"
)

func TestGenerateToken(t *testing.T) {
	f := flamego.NewWithLogger(&bytes.Buffer{})
	f.Use(session.Sessioner())
	f.Use(Csrfer())

	// Simulate login.
	f.Get("/login", func(sess session.Session, x CSRF) {
		sess.Set("uid", "123456")
	})

	// Generate token via GET request
	f.Get("/private", func() {})

	resp := httptest.NewRecorder()
	req, err := http.NewRequest(http.MethodGet, "/login", nil)
	assert.NoError(t, err)

	f.ServeHTTP(resp, req)

	cookie := resp.Header().Get("Set-Cookie")

	resp = httptest.NewRecorder()
	req, err = http.NewRequest(http.MethodGet, "/private", nil)
	assert.NoError(t, err)

	req.Header.Set("Cookie", cookie)
	f.ServeHTTP(resp, req)
}

func TestGenerateHeader(t *testing.T) {
	t.Run("Generate token to header", func(t *testing.T) {
		f := flamego.NewWithLogger(&bytes.Buffer{})
		f.Use(session.Sessioner())
		f.Use(Csrfer(Options{
			SetHeader: true,
		}))

		f.Get("/login", func(sess session.Session) {
			sess.Set("uid", "123456")
		})

		// Generate header.
		f.Get("/private", func() {})

		resp := httptest.NewRecorder()
		req, err := http.NewRequest(http.MethodGet, "/login", nil)
		assert.NoError(t, err)
		f.ServeHTTP(resp, req)

		assert.Contains(t, resp.Header().Get("Set-Cookie"), "")

		resp = httptest.NewRecorder()
		req, err = http.NewRequest(http.MethodGet, "/private", nil)
		assert.NoError(t, err)

		f.ServeHTTP(resp, req)

		assert.NotEmpty(t, resp.Header().Get("X-CSRFToken"))
	})

	t.Run("Generate token to header with origin", func(t *testing.T) {
		f := flamego.NewWithLogger(&bytes.Buffer{})
		f.Use(session.Sessioner())
		f.Use(Csrfer(Options{
			SetHeader: true,
			NoOrigin:  true,
		}))

		f.Get("/login", func(sess session.Session) {
			sess.Set("uid", "123456")
		})

		// Generate header.
		f.Get("/private", func() {})

		resp := httptest.NewRecorder()
		req, err := http.NewRequest(http.MethodGet, "/login", nil)
		assert.NoError(t, err)
		f.ServeHTTP(resp, req)

		cookie := resp.Header().Get("Set-Cookie")

		resp = httptest.NewRecorder()
		req, err = http.NewRequest(http.MethodGet, "/private", nil)
		assert.NoError(t, err)

		req.Header.Set("Cookie", cookie)
		req.Header.Set("Origin", "https://www.example.com")
		f.ServeHTTP(resp, req)

		assert.Empty(t, resp.Header().Get("X-CSRFToken"))
	})

	t.Run("Generate token to custom header", func(t *testing.T) {
		f := flamego.NewWithLogger(&bytes.Buffer{})
		f.Use(session.Sessioner())
		f.Use(Csrfer(Options{
			SetHeader: true,
			Header:    "X-Custom",
		}))

		f.Get("/login", func(sess session.Session) {
			sess.Set("uid", "123456")
		})

		// Generate header.
		f.Get("/private", func() {})

		resp := httptest.NewRecorder()
		req, err := http.NewRequest(http.MethodGet, "/login", nil)
		assert.NoError(t, err)
		f.ServeHTTP(resp, req)

		cookie := resp.Header().Get("Set-Cookie")

		resp = httptest.NewRecorder()
		req, err = http.NewRequest(http.MethodGet, "/private", nil)
		assert.NoError(t, err)

		req.Header.Set("Cookie", cookie)
		f.ServeHTTP(resp, req)

		assert.NotEmpty(t, resp.Header().Get("X-Custom"))
	})
}

func TestValidate(t *testing.T) {
	t.Run("Validate token", func(t *testing.T) {
		f := flamego.NewWithLogger(&bytes.Buffer{})
		f.Use(session.Sessioner())
		f.Use(Csrfer())

		f.Get("/login", func(sess session.Session) {
			sess.Set("uid", "123456")
		})

		// Generate token via GET request
		f.Get("/private", func() {})

		resp := httptest.NewRecorder()
		req, err := http.NewRequest(http.MethodGet, "/login", nil)
		assert.NoError(t, err)
		f.ServeHTTP(resp, req)

		cookie := resp.Header().Get("Set-Cookie")

		resp = httptest.NewRecorder()
		req, err = http.NewRequest(http.MethodGet, "/private", nil)
		assert.NoError(t, err)

		req.Header.Set("Cookie", cookie)
		f.ServeHTTP(resp, req)

		token := resp.Body.String()

		// Post using _csrf form value.
		data := url.Values{}
		data.Set("_csrf", token)

		resp = httptest.NewRecorder()
		req, err = http.NewRequest(http.MethodPost, "/private", bytes.NewBufferString(data.Encode()))
		assert.NoError(t, err)

		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("Content-Length", strconv.Itoa(len(data.Encode())))
		req.Header.Set("Cookie", cookie)
		f.ServeHTTP(resp, req)

		assert.NotEqual(t, resp.Code, http.StatusBadRequest)

		// Post using X-CSRFToken HTTP header.
		resp = httptest.NewRecorder()
		req, err = http.NewRequest(http.MethodPost, "/private", nil)
		assert.NoError(t, err)

		req.Header.Set("X-CSRFToken", token)
		req.Header.Set("Cookie", cookie)
		f.ServeHTTP(resp, req)

		assert.NotEqual(t, resp.Code, http.StatusBadRequest)
	})

	t.Run("Validate custom token", func(t *testing.T) {
		f := flamego.NewWithLogger(&bytes.Buffer{})
		f.Use(session.Sessioner())
		f.Use(Csrfer(Options{
			Header: "X-Custom",
			Form:   "_custom",
		}))

		f.Get("/login", func(sess session.Session) {
			sess.Set("uid", "123456")
		})

		// Generate token via GET request
		f.Get("/private", func() {})

		resp := httptest.NewRecorder()
		req, err := http.NewRequest(http.MethodGet, "/login", nil)
		assert.NoError(t, err)
		f.ServeHTTP(resp, req)

		cookie := resp.Header().Get("Set-Cookie")

		resp = httptest.NewRecorder()
		req, err = http.NewRequest(http.MethodGet, "/private", nil)
		assert.NoError(t, err)

		req.Header.Set("Cookie", cookie)
		f.ServeHTTP(resp, req)

		token := resp.Body.String()

		// Post using _csrf form value.
		data := url.Values{}
		data.Set("_csrf", token)

		resp = httptest.NewRecorder()
		req, err = http.NewRequest(http.MethodPost, "/private", bytes.NewBufferString(data.Encode()))
		assert.NoError(t, err)

		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("Content-Length", strconv.Itoa(len(data.Encode())))
		req.Header.Set("Cookie", cookie)
		f.ServeHTTP(resp, req)

		assert.NotEqual(t, resp.Code, http.StatusBadRequest)

		// Post using X-Custom HTTP header.
		resp = httptest.NewRecorder()
		req, err = http.NewRequest(http.MethodPost, "/private", nil)
		assert.NoError(t, err)

		req.Header.Set("X-Custom", token)
		req.Header.Set("Cookie", cookie)
		f.ServeHTTP(resp, req)

		assert.NotEqual(t, resp.Code, http.StatusBadRequest)
	})

	t.Run("Validate token with custom error", func(t *testing.T) {
		f := flamego.NewWithLogger(&bytes.Buffer{})
		f.Use(session.Sessioner())
		f.Use(Csrfer(Options{
			ErrorFunc: func(w http.ResponseWriter) {
				http.Error(w, "custom error", http.StatusUnprocessableEntity)
			},
		}))

		f.Get("/login", func(sess session.Session) {
			sess.Set("uid", "123456")
		})

		// Generate token via GET request
		f.Get("/private", func(x CSRF) string {
			return x.Token()
		})

		f.Post("/private", Validate, func() {})

		resp := httptest.NewRecorder()
		req, err := http.NewRequest(http.MethodGet, "/login", nil)
		assert.NoError(t, err)
		f.ServeHTTP(resp, req)

		cookie := resp.Header().Get("Set-Cookie")

		resp = httptest.NewRecorder()
		req, err = http.NewRequest(http.MethodGet, "/private", nil)
		assert.NoError(t, err)

		req.Header.Set("Cookie", cookie)
		f.ServeHTTP(resp, req)

		// Post using _csrf form value.
		data := url.Values{}
		data.Set("_csrf", "invalid")

		resp = httptest.NewRecorder()
		req, err = http.NewRequest(http.MethodPost, "/private", bytes.NewBufferString(data.Encode()))
		assert.NoError(t, err)

		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("Content-Length", strconv.Itoa(len(data.Encode())))
		req.Header.Set("Cookie", cookie)
		f.ServeHTTP(resp, req)

		assert.Equal(t, resp.Code, http.StatusUnprocessableEntity)
		assert.Equal(t, resp.Body.String(), "custom error\n")

		// Post using X-CSRFToken HTTP header.
		resp = httptest.NewRecorder()
		req, err = http.NewRequest(http.MethodPost, "/private", nil)
		assert.NoError(t, err)

		req.Header.Set("X-CSRFToken", "invalid")
		req.Header.Set("Cookie", cookie)
		f.ServeHTTP(resp, req)

		assert.Equal(t, resp.Code, http.StatusUnprocessableEntity)
		assert.Equal(t, resp.Body.String(), "custom error\n")
	})
}

func TestInvalid(t *testing.T) {
	t.Run("Invalid session data type", func(t *testing.T) {
		f := flamego.NewWithLogger(&bytes.Buffer{})
		f.Use(session.Sessioner())
		f.Use(Csrfer())

		f.Get("/login", func(sess session.Session) {
			sess.Set("uid", true)
		})

		// Generate token via GET request
		f.Get("/private", func() {})

		resp := httptest.NewRecorder()
		req, err := http.NewRequest(http.MethodGet, "/login", nil)
		assert.NoError(t, err)
		f.ServeHTTP(resp, req)

		cookie := resp.Header().Get("Set-Cookie")

		resp = httptest.NewRecorder()
		req, err = http.NewRequest(http.MethodGet, "/private", nil)
		assert.NoError(t, err)

		req.Header.Set("Cookie", cookie)
		f.ServeHTTP(resp, req)
	})

	t.Run("Invalid request", func(t *testing.T) {
		f := flamego.NewWithLogger(&bytes.Buffer{})
		f.Use(session.Sessioner())
		f.Use(Csrfer())

		f.Get("/login", Validate, func() {})

		// Generate token via GET request
		f.Get("/private", func() {})

		resp := httptest.NewRecorder()
		req, err := http.NewRequest(http.MethodGet, "/login", nil)
		assert.NoError(t, err)
		f.ServeHTTP(resp, req)

		assert.Equal(t, resp.Code, http.StatusBadRequest)
	})

	t.Run("Invalid token", func(t *testing.T) {
		f := flamego.NewWithLogger(&bytes.Buffer{})
		f.Use(session.Sessioner())
		f.Use(Csrfer())

		f.Get("/login", Validate, func() {})

		resp := httptest.NewRecorder()
		req, err := http.NewRequest(http.MethodGet, "/login", nil)
		assert.NoError(t, err)
		f.ServeHTTP(resp, req)

		resp = httptest.NewRecorder()
		req, err = http.NewRequest(http.MethodGet, "/login", nil)
		assert.NoError(t, err)

		req.Header.Set("X-CSRFToken", "invalid")
		f.ServeHTTP(resp, req)

		assert.Equal(t, resp.Code, http.StatusBadRequest)
	})
}
