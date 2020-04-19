package main

import (
	"context"
	"crypto/rand"
	"encoding/pem"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"credhub_setup/pkg/config"
)

// constant values for testing
const (
	podName           = "pod-name"
	podAddress        = "192.2.25.73"
	podPort           = "6667"
	groupExistingGUID = "existing-guid"
)

// handleUnexpectedPath returns a handler func that logs the access and fails
// the test.
func handleUnexpectedPath(t *testing.T) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		t.Logf("Unexpected HTTP %s on %s", r.Method, r.URL.String())
		for k, v := range r.Header {
			t.Logf("  %s: %+v", k, v)
		}
		t.Fail()
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(fmt.Sprintf("Path %s is not found\n", r.URL.Path)))
	}
}

func randomString(t *testing.T) (string, error) {
	buf := make([]byte, 16)
	_, err := rand.Read(buf)
	if !assert.NoError(t, err, "could not read random") {
		return "", fmt.Errorf("could not read random: %w", err)
	}
	return fmt.Sprintf("%x", buf), nil
}

type mockUAAHandler struct {
	*testing.T
	*mux.Router
	*httptest.Server
	config      config.UAA
	accessToken string
}

func (h *mockUAAHandler) handleTokenRequest(w http.ResponseWriter, req *http.Request) {
	grantType := req.FormValue("grant_type")
	if !assert.Equalf(h.T, "client_credentials", grantType, "OAuth token request %s got unexpected grant type", req.URL.Path) {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	clientID, clientSecret, ok := req.BasicAuth()
	if !ok {
		clientID = req.FormValue("client_id")
		clientSecret = req.FormValue("client_secret")
	}
	if h.config.OAuthClient != clientID {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	if h.config.OAuthSecret != clientSecret {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	h.T.Logf("Oauth token request: reusing access token %s", h.accessToken)
	w.Header().Add("Content-Type", "application/json")
	io.WriteString(w, fmt.Sprintf(`{
		"access_token": "%s",
		"token_type": "bearer",
		"expires_in": %d
	}`, h.accessToken, int(time.Hour.Seconds())))
}

func (h *mockUAAHandler) Close() error {
	h.Server.Close()
	return os.Remove(h.config.UAACACert)
}

func newMockUAA(t *testing.T) (*mockUAAHandler, error) {
	m := mux.NewRouter()
	h := &mockUAAHandler{T: t, Router: m}
	m.Path("/oauth2/token").HandlerFunc(h.handleTokenRequest)
	m.PathPrefix("/").HandlerFunc(handleUnexpectedPath(t))
	h.Server = httptest.NewTLSServer(m)
	serverURL, err := url.Parse(h.Server.URL)
	if !assert.NoError(t, err, "could not parse server URL") {
		return nil, err
	}
	certFile, err := ioutil.TempFile("", "uaa-ca-certificate-*.crt")
	if !assert.NoError(t, err, "could not create temporary cert") {
		return nil, err
	}
	h.config = config.UAA{
		OAuthClient: "client_id",
		OAuthSecret: "hunter2",
		UAATokenURL: serverURL.ResolveReference(&url.URL{Path: "/oauth2/token"}).String(),
		UAACACert:   certFile.Name(),
	}
	for _, cert := range h.Server.TLS.Certificates {
		pem.Encode(certFile, &pem.Block{
			Type:  "CERTIFICATE",
			Bytes: cert.Certificate[len(cert.Certificate)-1],
		})
	}
	h.accessToken, err = randomString(t)
	if !assert.NoError(t, err, "could not generate access token") {
		return nil, err
	}
	return h, nil
}

type mockCCHandler struct {
	*testing.T
	*mux.Router
	*httptest.Server
	config            config.CC
	triggeredRequests map[string]struct{}
}

func (h *mockCCHandler) handleListExisting(w http.ResponseWriter, req *http.Request) {
	query := req.FormValue("q")
	if !assert.True(h.T, strings.HasPrefix(query, "name:"), "unexpected query: %s", query) {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	name := strings.TrimPrefix(query, "name:")
	w.WriteHeader(http.StatusOK)
	_, _ = io.WriteString(w, fmt.Sprintf(`{
		"resources": [{
			"metadata": { "guid": "%s" },
			"entity": { "name": "%s", "rules": [],
				"running_default": false, "staging_default": false }
		}]
	}`, groupExistingGUID, name))
	h.triggeredRequests["list-existing"] = struct{}{}
}

func (h *mockCCHandler) handleListMissing(w http.ResponseWriter, req *http.Request) {
	query := req.FormValue("q")
	if !assert.True(h.T, strings.HasPrefix(query, "name:"), "unexpected query: %s", query) {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	w.WriteHeader(http.StatusOK)
	_, _ = io.WriteString(w, `{"resources": []}`)
	h.triggeredRequests["list-missing"] = struct{}{}
}

func (h *mockCCHandler) handleCreate(w http.ResponseWriter, req *http.Request) {
	body, err := ioutil.ReadAll(req.Body)
	assert.NoError(h.T, err, "could not read request body")
	expected := fmt.Sprintf(`{
		"name": "credhub-internal-%[1]s",
		"rules": [
			{ "description": "%[1]s service access",
			  "destination": "%[2]s",
			  "log": false,
			  "ports": "%[3]s",
			  "protocol": "tcp" }
		]
	}`, podName, podAddress, podPort)
	assert.JSONEq(h.T, expected, string(body))
	io.WriteString(w, fmt.Sprintf(`{
		"metadata": { "guid": "%s" },
		"entity": %s
	}`, groupExistingGUID, expected))
	h.triggeredRequests["create"] = struct{}{}
}

func (h *mockCCHandler) handleUpdate(w http.ResponseWriter, req *http.Request) {
	vars := mux.Vars(req)
	if !assert.Equal(h.T, groupExistingGUID, vars["guid"], "unexpected GUID to update") {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	body, err := ioutil.ReadAll(req.Body)
	assert.NoError(h.T, err, "could not read request body")
	expected := fmt.Sprintf(`{
		"name": "credhub-internal-%[1]s",
		"rules": [
			{ "description": "%[1]s service access",
			  "destination": "%[2]s",
			  "log": false,
			  "ports": "%[3]s",
			  "protocol": "tcp" }
		]
	}`, podName, podAddress, podPort)
	assert.JSONEq(h.T, expected, string(body))
	io.WriteString(w, fmt.Sprintf(`{
		"metadata": { "guid": "%s" },
		"entity": %s
	}`, groupExistingGUID, expected))
	h.triggeredRequests["update"] = struct{}{}
}

func (h *mockCCHandler) handleDelete(w http.ResponseWriter, req *http.Request) {
	vars := mux.Vars(req)
	if !assert.Equal(h.T, groupExistingGUID, vars["guid"], "unexpected GUID to delete") {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	h.triggeredRequests["delete"] = struct{}{}
}

func (h *mockCCHandler) handleBind(w http.ResponseWriter, req *http.Request) {
	vars := mux.Vars(req)
	assert.Equal(h.T, groupExistingGUID, vars["guid"], "got unexpected GUID")
	h.triggeredRequests["bind-"+vars["lifecycle"]] = struct{}{}
}

func (h *mockCCHandler) Close() error {
	h.Server.Close()
	return os.Remove(h.config.CCCACert)
}

func newMockCC(t *testing.T, existing bool, token string) (*mockCCHandler, error) {
	m := mux.NewRouter()
	h := &mockCCHandler{
		T:                 t,
		Router:            m,
		triggeredRequests: make(map[string]struct{}),
	}
	submux := m.Headers("Authorization", "Bearer "+token).Subrouter()
	if existing {
		submux.Methods(http.MethodGet).
			Path("/v2/security_groups").
			HandlerFunc(h.handleListExisting)
	} else {
		submux.Methods(http.MethodGet).
			Path("/v2/security_groups").
			HandlerFunc(h.handleListMissing)
	}
	submux.Methods(http.MethodPost).
		Path("/v2/security_groups").
		HandlerFunc(h.handleCreate)
	submux.Methods(http.MethodPut).
		Path("/v2/security_groups/{guid}").
		HandlerFunc(h.handleUpdate)
	submux.Methods(http.MethodDelete).
		Path("/v2/security_groups/{guid}").
		HandlerFunc(h.handleDelete)
	submux.Methods(http.MethodPut).
		Path("/v2/config/{lifecycle}_security_groups/{guid}").
		HandlerFunc(h.handleBind)
	m.PathPrefix("/").HandlerFunc(handleUnexpectedPath(t))
	h.Server = httptest.NewTLSServer(m)
	certFile, err := ioutil.TempFile("", "cc-ca-certificate-*.crt")
	if !assert.NoError(t, err, "could not create temporary cert") {
		return nil, err
	}
	h.config = config.CC{
		CCURL:    h.Server.URL,
		CCCACert: certFile.Name(),
		Name:     podName,
		PodIP:    podAddress,
		Ports:    podPort,
	}
	for _, cert := range h.Server.TLS.Certificates {
		pem.Encode(certFile, &pem.Block{
			Type:  "CERTIFICATE",
			Bytes: cert.Certificate[len(cert.Certificate)-1],
		})
	}
	return h, nil
}

// TestProcess runs end-to-end tests.
func TestProcess(t *testing.T) {
	t.Run("applying security groups", func(t *testing.T) {
		t.Run("with existing groups", func(t *testing.T) {
			uaa, err := newMockUAA(t)
			require.NoError(t, err, "could not create mock UAA")
			defer func() { assert.NoError(t, uaa.Close(), "UAA cleanup failed") }()
			cc, err := newMockCC(t, true, uaa.accessToken)
			require.NoError(t, err, "could not create mock CC")
			defer func() { assert.NoError(t, cc.Close(), "CC cleanup failed") }()

			err = process(
				context.Background(),
				config.Config{UAA: uaa.config, CC: cc.config},
				t,
				processModeApply)
			assert.NoError(t, err, "failed to process")
			expected := map[string]struct{}{
				"list-existing": struct{}{},
				"update":        struct{}{},
				"bind-staging":  struct{}{},
				"bind-running":  struct{}{},
			}
			assert.Equal(t, expected, cc.triggeredRequests, "unexpected requests")
		})
		t.Run("with no existing groups", func(t *testing.T) {
			uaa, err := newMockUAA(t)
			require.NoError(t, err, "could not create mock UAA")
			defer func() { assert.NoError(t, uaa.Close(), "UAA cleanup failed") }()
			cc, err := newMockCC(t, false, uaa.accessToken)
			require.NoError(t, err, "could not create mock CC")
			defer func() { assert.NoError(t, cc.Close(), "CC cleanup failed") }()

			err = process(
				context.Background(),
				config.Config{UAA: uaa.config, CC: cc.config},
				t,
				processModeApply)
			assert.NoError(t, err, "failed to process")
			expected := map[string]struct{}{
				"list-missing": struct{}{},
				"create":       struct{}{},
				"bind-staging": struct{}{},
				"bind-running": struct{}{},
			}
			assert.Equal(t, expected, cc.triggeredRequests, "unexpected requests")
		})
	})
	t.Run("removing security groups", func(t *testing.T) {
		t.Run("with existing groups", func(t *testing.T) {
			uaa, err := newMockUAA(t)
			require.NoError(t, err, "could not create mock UAA")
			defer func() { assert.NoError(t, uaa.Close(), "UAA cleanup failed") }()
			cc, err := newMockCC(t, true, uaa.accessToken)
			require.NoError(t, err, "could not create mock CC")
			defer func() { assert.NoError(t, cc.Close(), "CC cleanup failed") }()

			err = process(
				context.Background(),
				config.Config{UAA: uaa.config, CC: cc.config},
				t,
				processModeRemove)
			assert.NoError(t, err, "failed to process")
			expected := map[string]struct{}{
				"list-existing": struct{}{},
				"delete":        struct{}{},
			}
			assert.Equal(t, expected, cc.triggeredRequests, "unexpected requests")
		})
	})
}
