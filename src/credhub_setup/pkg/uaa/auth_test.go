package uaa

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func handleUnexpectedPath(t *testing.T) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		t.Logf("Unexpected HTTP %s on %s", r.Method, r.URL.String())
		t.Fail()
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(fmt.Sprintf("Path %s is not found\n", r.URL.Path)))
	}
}

func handleCCPing(sawPing *bool) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		*sawPing = true
		w.WriteHeader(http.StatusOK)
	}
}

type mockAuthMux struct {
	*http.ServeMux
	t            *testing.T
	clientID     string
	clientSecret string
	accessToken  string
}

func newMockAuthMux(t *testing.T) *mockAuthMux {
	m := &mockAuthMux{
		ServeMux: http.NewServeMux(),
		t:        t,
	}
	m.clientID, _ = m.randomString()
	m.clientSecret, _ = m.randomString()
	m.accessToken, _ = m.randomString()
	m.HandleFunc("/", handleUnexpectedPath(t))
	m.HandleFunc("/oauth/token", m.handleTokenRequest)
	return m
}

func (m *mockAuthMux) randomString() (string, error) {
	buf := make([]byte, 16)
	_, err := rand.Read(buf)
	if !assert.NoError(m.t, err, "could not read random") {
		return "", fmt.Errorf("could not read random: %w", err)
	}
	return fmt.Sprintf("%x", buf), nil
}

func (m *mockAuthMux) jsonResponse(w http.ResponseWriter, data interface{}) {
	w.Header().Add("Content-Type", "application/json")
	err := json.NewEncoder(w).Encode(data)
	if !assert.NoError(m.t, err, "error writing JSON response") {
		w.WriteHeader(http.StatusInternalServerError)
	}
}

func (m *mockAuthMux) handleTokenRequest(w http.ResponseWriter, r *http.Request) {
	grantType := r.FormValue("grant_type")
	if !assert.Equalf(m.t, "client_credentials", grantType, "OAuth token request %s got unexpected grant type", r.URL.Path) {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte(fmt.Sprintf("Unexpected grant type %s", grantType)))
	}
	clientID, clientSecret, ok := r.BasicAuth()
	if !ok {
		clientID = r.FormValue("client_id")
		clientSecret = r.FormValue("client_secret")
	}
	if m.clientID != clientID {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte(fmt.Sprintf("Unexpected client ID %s", clientID)))
		return
	}
	if m.clientSecret != clientSecret {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte(fmt.Sprintf("Unexpected client secret %s", clientSecret)))
		return
	}
	accessToken, err := m.randomString()
	if !assert.NoError(m.t, err, "error generating access token") {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(fmt.Sprintf("%v", err)))
		return
	}
	m.accessToken = accessToken
	m.t.Logf("Oauth token request: new access token %s", m.accessToken)
	m.jsonResponse(w, map[string]interface{}{
		"access_token": m.accessToken,
		"token_type":   "bearer",
		"expires_in":   time.Hour,
	})
}

func TestAuthenticate(t *testing.T) {
	t.Parallel()

	t.Run("with bad credentials", func(t *testing.T) {
		t.Parallel()
		sawPing := false
		ccMux := http.NewServeMux()
		ccMux.HandleFunc("/", handleUnexpectedPath(t))
		ccMux.HandleFunc("/ping", handleCCPing(&sawPing))
		ccServer := httptest.NewTLSServer(ccMux)
		defer ccServer.Close()

		uaaMux := newMockAuthMux(t)
		uaaServer := httptest.NewTLSServer(uaaMux)
		defer uaaServer.Close()

		uaaURL, err := url.Parse(uaaServer.URL)
		require.NoError(t, err, "could not parse UAA server URL")

		client, err := Authenticate(
			context.Background(),
			ccServer.Client(),
			uaaServer.Client(),
			uaaURL.ResolveReference(&url.URL{Path: "/oauth/token"}),
			"incorrect client ID",
			"incorrect client secret",
		)
		assert.NoError(t, err, "bad credentials should not fail to create auth client")
		if assert.NotNil(t, client, "did not get a client") {
			_, err := client.Get(ccServer.URL + "/ping")
			assert.Error(t, err, "ping should fail with bad credentials")
		}
	})

	t.Run("with good credentials", func(t *testing.T) {
		t.Parallel()
		sawPing := false
		ccMux := http.NewServeMux()
		ccMux.HandleFunc("/", handleUnexpectedPath(t))
		ccMux.HandleFunc("/ping", handleCCPing(&sawPing))
		ccServer := httptest.NewTLSServer(ccMux)
		defer ccServer.Close()

		uaaMux := newMockAuthMux(t)
		uaaServer := httptest.NewTLSServer(uaaMux)
		defer uaaServer.Close()

		uaaURL, err := url.Parse(uaaServer.URL)
		require.NoError(t, err, "could not parse UAA server URL")

		client, err := Authenticate(
			context.Background(),
			ccServer.Client(),
			uaaServer.Client(),
			uaaURL.ResolveReference(&url.URL{Path: "/oauth/token"}),
			uaaMux.clientID,
			uaaMux.clientSecret,
		)
		assert.NoError(t, err, "could not create authenticated client")
		if assert.NotNil(t, client, "did not get a client") {
			resp, err := client.Get(ccServer.URL + "/ping")
			assert.NoError(t, err, "could not get ping response")
			assert.GreaterOrEqualf(t, resp.StatusCode, 200, "unexpected response: %s", resp.Status)
			assert.Lessf(t, resp.StatusCode, 400, "unexpected response: %s", resp.Status)
			assert.True(t, sawPing, "did not see ping")
		}
	})
}
