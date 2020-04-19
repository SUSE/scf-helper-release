package httpclient

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"math"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMakeHTTPClientWithCA(t *testing.T) {
	t.Parallel()

	ctx := context.Background()

	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "ok")
	}))

	serverURL, err := url.Parse(server.URL)
	require.NoError(t, err, "error parsing server url")

	wg := &sync.WaitGroup{}
	wg.Add(1)
	go func() {
		// Start a goroutine which waits until all the sub-tests have completed
		// before terminating the server.  We can't do this in the main test as
		// t.Parallel() waits for the parent task before proceeding.
		defer server.Close()
		wg.Wait()
	}()

	t.Run("valid certificate", func(t *testing.T) {
		wg.Add(1)
		defer wg.Done()
		t.Parallel()

		certFile, err := ioutil.TempFile("", "credhub-setup-ca-*.crt")
		require.NoError(t, err, "failed to create temporary CA certificate")
		defer os.Remove(certFile.Name())
		err = pem.Encode(certFile, &pem.Block{
			Type:  "CERTIFICATE",
			Bytes: server.Certificate().Raw,
		})
		require.NoError(t, err, "failed to write temporary CA certificate")
		err = certFile.Close()
		require.NoError(t, err, "failed to close temporary CA certificate")

		client, err := MakeHTTPClientWithCA(
			ctx,
			serverURL.Hostname(),
			certFile.Name())
		require.NoError(t, err, "failed to make HTTP client")

		resp, err := client.Get(server.URL)
		require.NoError(t, err, "error fetching from test server")
		require.GreaterOrEqual(t, resp.StatusCode, 200, "unexpected status: %s", resp.Status)
		require.Less(t, resp.StatusCode, 300, "unexpected status: %s", resp.Status)
	})

	t.Run("missing certificate", func(t *testing.T) {
		wg.Add(1)
		defer wg.Done()
		t.Parallel()

		certFile, err := ioutil.TempFile("", "credhub-setup-ca-*.crt")
		require.NoError(t, err, "failed to create temporary CA certificate")
		err = os.Remove(certFile.Name())
		assert.NoError(t, err, "failed to remove temporary CA certificate")

		_, err = MakeHTTPClientWithCA(
			ctx,
			serverURL.Hostname(),
			certFile.Name())
		assert.Error(t, err, "got HTTP client with missing CA certificate")
	})

	t.Run("invalid certificate", func(t *testing.T) {
		wg.Add(1)
		defer wg.Done()
		t.Parallel()

		certFile, err := ioutil.TempFile("", "credhub-setup-ca-*.crt")
		require.NoError(t, err, "failed to create temporary CA certificate")
		defer os.Remove(certFile.Name())
		err = pem.Encode(certFile, &pem.Block{
			Type:  "CERTIFICATE",
			Bytes: []byte("This is an invalid certificate"),
		})
		require.NoError(t, err, "failed to write temporary CA certificate")
		err = certFile.Close()
		require.NoError(t, err, "failed to close temporary CA certificate")

		_, err = MakeHTTPClientWithCA(
			ctx,
			serverURL.Hostname(),
			certFile.Name())
		assert.Error(t, err, "got HTTP client with invalid CA certificate")
	})

	t.Run("incorrect certificate", func(t *testing.T) {
		wg.Add(1)
		defer wg.Done()
		t.Parallel()

		serial, err := rand.Int(rand.Reader, big.NewInt(math.MaxInt64))
		require.NoError(t, err, "could not generate random serial number")
		certTemplate := &x509.Certificate{
			IsCA:         true,
			SerialNumber: serial,
		}
		pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
		require.NoError(t, err, "could not generate private key")
		cert, err := x509.CreateCertificate(rand.Reader, certTemplate, certTemplate, pubKey, privKey)
		require.NoError(t, err, "could not create certificate")

		certFile, err := ioutil.TempFile("", "credhub-setup-ca-*.crt")
		require.NoError(t, err, "failed to create temporary CA certificate")
		defer os.Remove(certFile.Name())
		err = pem.Encode(certFile, &pem.Block{
			Type:  "CERTIFICATE",
			Bytes: cert,
		})
		require.NoError(t, err, "failed to write temporary CA certificate")
		err = certFile.Close()
		require.NoError(t, err, "failed to close temporary CA certificate")

		client, err := MakeHTTPClientWithCA(
			ctx,
			serverURL.Hostname(),
			certFile.Name())
		require.NoError(t, err, "could not create HTTP client with incorrect CA certificate")
		require.NotNil(t, client, "did not create HTTP client even though no errors reported")
		_, err = client.Get(server.URL)
		require.Error(t, err, "did not get error fetching from test server with incorrect CA certificate")
	})

	// Remove the initial wait after making sure the sub-tests have had a chance
	// to add their own (before their own respective calls to t.Parallel())
	wg.Done()
}
