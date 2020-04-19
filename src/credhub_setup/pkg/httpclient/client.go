package httpclient

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"net/http"
	"time"
)

// MakeHTTPClientWithCA returns a new *http.Client that only accepts the given
// CA cert (encoded in PEM format).
func MakeHTTPClientWithCA(ctx context.Context, serverName, caCertPath string) (*http.Client, error) {
	certPool := x509.NewCertPool()

	caCertBytes, err := ioutil.ReadFile(caCertPath)
	if err != nil {
		return nil, fmt.Errorf("failed to create HTTP client: could not read CA certificate: %w", err)
	}

	ok := certPool.AppendCertsFromPEM(caCertBytes)
	if !ok {
		return nil, fmt.Errorf("failed to create HTTP client: could not append CA cert")
	}

	return &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs:    certPool,
				ServerName: serverName,
			},
		},
		Timeout: 60 * time.Second,
	}, nil
}
