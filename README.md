# csrf

[![GitHub Workflow Status](https://img.shields.io/github/workflow/status/flamego/csrf/Go?logo=github&style=for-the-badge)](https://github.com/flamego/csrf/actions?query=workflow%3AGo)
[![Codecov](https://img.shields.io/codecov/c/gh/flamego/csrf?logo=codecov&style=for-the-badge)](https://app.codecov.io/gh/flamego/csrf)
[![GoDoc](https://img.shields.io/badge/GoDoc-Reference-blue?style=for-the-badge&logo=go)](https://pkg.go.dev/github.com/flamego/csrf?tab=doc)
[![Sourcegraph](https://img.shields.io/badge/view%20on-Sourcegraph-brightgreen.svg?style=for-the-badge&logo=sourcegraph)](https://sourcegraph.com/github.com/flamego/csrf)

Package csrf is a middleware that generates and validates CSRF tokens for [Flamego](https://github.com/flamego/flamego).

## Installation

The minimum requirement of Go is **1.16**.

	go get github.com/flamego/csrf


## Getting started

```html
<!-- templates/protected.tmpl -->
<form action="/protected" method="POST">
  <input type="hidden" name="_csrf" value="{{.CSRFToken}}">
  <button>Submit</button>
</form>
```

```go
package main

import (
	"net/http"

	"github.com/flamego/csrf"
	"github.com/flamego/flamego"
	"github.com/flamego/session"
	"github.com/flamego/template"
)

func main() {
	f := flamego.Classic()
	f.Use(template.Templater())
	f.Use(session.Sessioner())
	f.Use(csrf.Csrfer())

	// Simulate the authentication of a session. If the "userID" exists,
	// then redirect to a form that requires CSRF protection.
	f.Get("/", func(c flamego.Context, s session.Session) {
		if s.Get("userID") == nil {
			c.Redirect("/login")
			return
		}
		c.Redirect("/protected")
	})

	// Set uid for the session.
	f.Get("/login", func(c flamego.Context, s session.Session) {
		s.Set("userID", 123)
		c.Redirect("/")
	})

	// Render a protected form by passing a CSRF token using x.Token().
	f.Get("/protected", func(c flamego.Context, s session.Session, x csrf.CSRF, t template.Template, data template.Data) {
		if s.Get("userID") == nil {
			c.Redirect("/login", http.StatusUnauthorized)
			return
		}

		// Pass token to the protected template.
		data["CSRFToken"] = x.Token()
		t.HTML(http.StatusOK, "protected")
	})

	// Apply CSRF validation to route.
	f.Post("/protected", csrf.Validate, func(c flamego.Context, s session.Session, t template.Template) {
		if s.Get("userID") != nil {
			c.ResponseWriter().Write([]byte("You submitted with a valid CSRF token"))
			return
		}
		c.Redirect("/login", http.StatusUnauthorized)
	})

	f.Run()
}
```

## Getting help

- Read [documentation and examples](https://flamego.dev/middleware/csrf.html).
- Please [file an issue](https://github.com/flamego/flamego/issues) or [start a discussion](https://github.com/flamego/flamego/discussions) on the [flamego/flamego](https://github.com/flamego/flamego) repository.

## License

This project is under the MIT License. See the [LICENSE](LICENSE) file for the full license text.
