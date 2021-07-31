// Copyright 2021 Flamego. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

package csrf

import (
	"encoding/base64"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

const (
	key      = "quay"
	userID   = "12345678"
	actionID = "POST /form"
)

var (
	now              = time.Now()
	oneMinuteFromNow = now.Add(1 * time.Minute)
)

func TestValidToken(t *testing.T) {
	tok := generateTokenAtTime(key, userID, actionID, now)
	assert.True(t, validTokenAtTime(tok, key, userID, actionID, oneMinuteFromNow))
	assert.True(t, validTokenAtTime(tok, key, userID, actionID, now.Add(timeout-1*time.Nanosecond)))
	assert.True(t, validTokenAtTime(tok, key, userID, actionID, now.Add(-1*time.Minute)))
}

// TestSeparatorReplacement tests that separators are being correctly
// substituted.
func TestSeparatorReplacement(t *testing.T) {
	assert.NotEqual(t, generateTokenAtTime("foo:bar", "baz", "wah", now), generateTokenAtTime("foo", "bar:baz", "wah", now))
}

func TestInvalidToken(t *testing.T) {
	invalidTokenTests := []struct {
		name, key, userID, actionID string
		t                           time.Time
	}{
		{"Bad key", "foobar", userID, actionID, oneMinuteFromNow},
		{"Bad userID", key, "foobar", actionID, oneMinuteFromNow},
		{"Bad actionID", key, userID, "foobar", oneMinuteFromNow},
		{"Expired", key, userID, actionID, now.Add(timeout)},
		{"More than 1 minute from the future", key, userID, actionID, now.Add(-1*time.Nanosecond - 1*time.Minute)},
	}

	tok := generateTokenAtTime(key, userID, actionID, now)
	for _, itt := range invalidTokenTests {
		assert.False(t, validTokenAtTime(tok, itt.key, itt.userID, itt.actionID, itt.t))
	}
}

// TestValidateBadData primarily tests that no unexpected panics are triggered
// during parsing.
func TestValidateBadData(t *testing.T) {
	badDataTests := []struct {
		name, tok string
	}{
		{"Invalid Base64", "ASDab24(@)$*=="},
		{"No delimiter", base64.URLEncoding.EncodeToString([]byte("foobar12345678"))},
		{"Invalid time", base64.URLEncoding.EncodeToString([]byte("foobar:foobar"))},
	}

	for _, bdt := range badDataTests {
		assert.False(t, validTokenAtTime(bdt.tok, key, userID, actionID, oneMinuteFromNow))
	}
}
