package uaa

import (
	"context"
	"net/http"
	"net/url"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/clientcredentials"
)

// Authenticate with UAA, returning a suitable HTTP client.
func Authenticate(ctx context.Context, ccClient, uaaClient *http.Client, tokenURL *url.URL, clientID, clientSecret string) (*http.Client, error) {
	credentialsConfig := clientcredentials.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		TokenURL:     tokenURL.String(),
		Scopes:       []string{"cloud_controller.admin"},
	}
	uaaContext := context.WithValue(ctx, oauth2.HTTPClient, uaaClient)
	ccContext := context.WithValue(ctx, oauth2.HTTPClient, ccClient)
	client := oauth2.NewClient(ccContext, credentialsConfig.TokenSource(uaaContext))
	return client, nil
}
