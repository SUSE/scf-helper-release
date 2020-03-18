package uaa

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"credhub_setup/pkg/cc"
	cchelpers "credhub_setup/pkg/cc/testhelpers"
	quarkshelpers "credhub_setup/pkg/quarks/testhelpers"
)

type mockAuthServer struct {
	*http.ServeMux
	server       *httptest.Server
	clientID     string
	clientSecret string
	accessToken  string
}

func newMockAuthServer() *mockAuthServer {
	m := &mockAuthServer{
		ServeMux: http.NewServeMux(),
	}
	m.clientID, _ = m.randomString()
	m.clientSecret, _ = m.randomString()
	m.accessToken, _ = m.randomString()
	m.HandleFunc("/", m.handleUnexpectedPath)
	m.HandleFunc("/v2/info", m.handleInfo)
	m.HandleFunc("/ping", m.handlePing)
	m.HandleFunc("/oauth/token", m.handleTokenRequest)
	return m
}

func (m *mockAuthServer) randomString() (string, error) {
	buf := make([]byte, 16)
	_, err := rand.Read(buf)
	if err != nil {
		return "", fmt.Errorf("could not read random: %w", err)
	}
	return fmt.Sprintf("%x", buf), nil
}

func (m *mockAuthServer) jsonResponse(w http.ResponseWriter, data interface{}) {
	w.Header().Add("Content-Type", "application/json")
	err := json.NewEncoder(w).Encode(data)
	if err != nil {
		msg := fmt.Sprintf("error writing JSON response: %v", err)
		fmt.Printf("%s\n", msg)
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(msg))
	}
}

func (m *mockAuthServer) handleInfo(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	m.jsonResponse(w, map[string]interface{}{
		"authorization_endpoint": m.server.URL,
		"token_endpoint":         m.server.URL,
	})
}

func (m *mockAuthServer) handlePing(w http.ResponseWriter, r *http.Request) {
	auth := r.Header.Get("Authorization")
	if auth != fmt.Sprintf("Bearer %s", m.accessToken) {
		fmt.Printf("/ping: invalid auth %v\n", auth)
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte("Unexpected auth header"))
		return
	}
	m.jsonResponse(w, map[string]string{"hello": "world"})
}

func (m *mockAuthServer) handleTokenRequest(w http.ResponseWriter, r *http.Request) {
	grantType := r.FormValue("grant_type")
	if grantType != "client_credentials" {
		fmt.Printf("OAuth token request %s got unexpected grant type %s\n",
			r.URL.Path, grantType)
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte(fmt.Sprintf("Unexpected grant type %s", grantType)))
	}
	clientID, clientSecret, ok := r.BasicAuth()
	if !ok {
		clientID = r.FormValue("client_id")
		clientSecret = r.FormValue("client_secret")
	}
	if clientID != m.clientID {
		fmt.Printf("Oauth token request %s got unexpected client ID \"%v\"\n",
			r.URL.Path, clientID)
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte(fmt.Sprintf("Unexpected client ID %s", clientID)))
		return
	}
	if clientSecret != m.clientSecret {
		fmt.Printf("Oauth token request %s got unexpected client secret \"%v\"\n",
			r.URL.Path, clientSecret)
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte(fmt.Sprintf("Unexpected client secret %s", clientSecret)))
		return
	}
	accessToken, err := m.randomString()
	if err != nil {
		fmt.Printf("Oauth token request: %v\n", err)
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(fmt.Sprintf("%v", err)))
		return
	}
	m.accessToken = accessToken
	fmt.Printf("Oauth token request: new access token %s\n", m.accessToken)
	m.jsonResponse(w, map[string]interface{}{
		"access_token": m.accessToken,
		"token_type":   "bearer",
		"expires_in":   time.Hour,
	})
}

func (m *mockAuthServer) handleUnexpectedPath(w http.ResponseWriter, r *http.Request) {
	fmt.Printf(">> Unexpected HTTP %s on %s\n", r.Method, r.URL.String())
	w.WriteHeader(http.StatusNotFound)
	_, _ = w.Write([]byte(fmt.Sprintf("Path %s is not found\n", r.URL.Path)))
}

func TestAuthenticate(t *testing.T) {
	t.Parallel()

	ctx, fakeMount, err := quarkshelpers.GenerateFakeMount(
		context.Background(),
		"deployment",
		t)
	require.NoError(t, err, "could not set up temporary mount directory")
	defer fakeMount.CleanUp()

	m := newMockAuthServer()
	server, err := cchelpers.NewMockServer(ctx, t, fakeMount, m)
	require.NoError(t, err, "could not create mock CC server")
	defer server.Close()
	m.server = server

	certBytes := bytes.Buffer{}
	pem.Encode(&certBytes, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: server.Certificate().Raw,
	})

	err = fakeMount.WriteFile("run/uaa-ca-cert/ca.crt", certBytes.Bytes())
	require.NoError(t, err, "could not write UAA CA cert")

	ccClient, err := cc.NewHTTPClient(ctx)
	require.NoError(t, err, "could not create unauthenticated CC client")

	baseURL, err := url.Parse(server.URL)
	require.NoError(t, err, "could not parse server URL")

	tokenURL := baseURL.ResolveReference(&url.URL{Path: "/oauth/token"})
	pingURL := baseURL.ResolveReference(&url.URL{Path: "/ping"})

	client, err := Authenticate(ctx, ccClient, tokenURL, "bad client ID", "bad client secret")
	require.NoError(t, err, "bad credentials should not fail auth client")
	require.NotNil(t, client, "got no client")
	_, err = client.Get(pingURL.String())
	assert.Error(t, err, "ping should fail with bad credentials")

	client, err = Authenticate(ctx, ccClient, tokenURL, m.clientID, m.clientSecret)
	require.NoError(t, err, "could not auth")
	require.NotNil(t, client, "got no client")

	resp, err := client.Get(pingURL.String())
	require.NoError(t, err, "could not get ping response")
	require.GreaterOrEqual(t, resp.StatusCode, 200, "unexpected response: %s", resp.Status)
	require.Less(t, resp.StatusCode, 400, "unexpected response: %s", resp.Status)
}
