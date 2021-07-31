// Copyright 2021 Flamego. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

package csrf

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha1"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// timeout is the duration that XSRF tokens are valid.
const timeout = 24 * time.Hour

// clean sanitizes a string for inclusion in a token by replacing all ":"s.
func clean(s string) string {
	return strings.Replace(s, ":", "_", -1)
}

// GenerateToken returns a URL-safe secure XSRF token that expires in 24 hours.
//
// The key is a secret key for your application, userID is a unique identifier
// for the user, actionID is the action the user is taking (e.g. POSTing to a
// particular path).
func GenerateToken(key, userID, actionID string) string {
	return generateTokenAtTime(key, userID, actionID, time.Now())
}

// generateTokenAtTime returns a token that expires 24 hours from now.
func generateTokenAtTime(key, userID, actionID string, now time.Time) string {
	h := hmac.New(sha1.New, []byte(key))
	_, _ = fmt.Fprintf(h, "%s:%s:%d", clean(userID), clean(actionID), now.UnixNano())
	tok := fmt.Sprintf("%s:%d", h.Sum(nil), now.UnixNano())
	return base64.RawURLEncoding.EncodeToString([]byte(tok))
}

// ValidToken returns true if token is a valid and unexpired.
func ValidToken(token, key, userID, actionID string) bool {
	return validTokenAtTime(token, key, userID, actionID, time.Now())
}

// validTokenAtTime uses now to check if the token is expired.
func validTokenAtTime(token, key, userID, actionID string, now time.Time) bool {
	// Decode the token.
	data, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil {
		return false
	}

	// Extract the issue time of the token.
	sep := bytes.LastIndex(data, []byte{':'})
	if sep < 0 {
		return false
	}
	nanos, err := strconv.ParseInt(string(data[sep+1:]), 10, 64)
	if err != nil {
		return false
	}
	issueTime := time.Unix(0, nanos)

	// Check that the token is not expired.
	if now.Sub(issueTime) >= timeout {
		return false
	}

	// Check that the token is not from the future. Allow 1-minute grace period in
	// case the token is being verified on a machine whose clock is behind the
	// machine that issued the token.
	if issueTime.After(now.Add(1 * time.Minute)) {
		return false
	}

	expected := generateTokenAtTime(key, userID, actionID, issueTime)

	// Check that the token matches the expected value. Use constant time comparison
	// to avoid timing attacks.
	return subtle.ConstantTimeCompare([]byte(token), []byte(expected)) == 1
}
