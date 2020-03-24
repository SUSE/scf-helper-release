package cc

// secgroup.go contains the code necessary to interact with the CF API to set
// up default running / staging security groups.

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"

	"credhub_setup/pkg/logger"
)

// securityGroupRule is a single rule in a security group definition.
type securityGroupRule struct {
	Protocol    string `json:"protocol"`
	Destination string `json:"destination"`
	Ports       string `json:"ports"`
	Log         bool   `json:"log"`
	Description string `json:"description"`
}

// securityGroupEntity is a security group definition excluding standard
// metadata.
type securityGroupEntity struct {
	Name  string              `json:"name"`
	Rules []securityGroupRule `json:"rules"`
}

// SecurityGroupDefinition is a security group definition as returned from the
// CF API.
type SecurityGroupDefinition struct {
	Metadata struct {
		GUID string `json:"guid"`
	} `json:"metadata"`
	Entity securityGroupEntity `json:"entity"`
}

// lifecycleType is the lifecycle phase of of a security group, either
// lifecycleRunning or lifecycleStaging.
type lifecycleType string

const (
	// The phases for the security group to bind to.
	lifecycleRunning = lifecycleType("running")
	lifecycleStaging = lifecycleType("staging")
)

// secGroupRequester is a type definition for
// SecurityGroupBuilder.defaultRequester that is used to make testing various
// methods easier.
type secGroupRequester func(context.Context, string, string, string, io.Reader) (string, error)

// SecurityGroupBuilder is a helper to construct and apply / remove application
// security group definitions.
type SecurityGroupBuilder struct {
	logger.Logger
	Client   *http.Client
	Endpoint *url.URL
	Name     string
	Address  string
	Ports    string

	groupIDOverride          *string
	makeSecurityGroupRequest secGroupRequester
}

// Apply the security group, ensuring that it exists and allows the configured
// address and port to be accessed by applications.
func (b *SecurityGroupBuilder) Apply(ctx context.Context) error {
	if b.makeSecurityGroupRequest == nil {
		b.makeSecurityGroupRequest = b.defaultRequester
	}
	err := func() error {
		groupID, err := b.groupID(ctx)
		if err != nil {
			return err
		}
		body, err := b.buildSecurityGroup()
		if err != nil {
			return err
		}
		if groupID == "" {
			groupID, err = b.makeSecurityGroupRequest(
				ctx, "", "", http.MethodPost, body)
		} else {
			groupID, err = b.makeSecurityGroupRequest(
				ctx, groupID, "", http.MethodPut, body)
		}
		if err != nil {
			return err
		}

		for _, lifecycle := range []lifecycleType{
			lifecycleRunning, lifecycleStaging,
		} {
			err = b.bindDefaultSecurityGroups(ctx, groupID, lifecycle)
			if err != nil {
				return err
			}
		}

		b.Logf("Successfully applied security group %s", groupID)
		return nil
	}()
	if err != nil {
		return fmt.Errorf("failed to apply security group: %w", err)
	}

	return nil
}

// Remove the configured application security group, such that (assuming no
// other security group allows it) user applications can no longer communicate
// with the configured address and port.
func (b *SecurityGroupBuilder) Remove(ctx context.Context) error {
	if b.makeSecurityGroupRequest == nil {
		b.makeSecurityGroupRequest = b.defaultRequester
	}
	err := func() error {
		groupID, err := b.groupID(ctx)
		if err != nil {
			return err
		}
		if groupID == "" {
			return nil // Nothing to remove
		}
		_, err = b.makeSecurityGroupRequest(ctx, groupID, "", http.MethodDelete, nil)
		if err != nil {
			return err
		}
		return nil
	}()
	if err != nil {
		return fmt.Errorf("failed to remove security group: %w", err)
	}
	return nil
}

// resolvePath is a helper function to build cloud controller API requests.
func (b *SecurityGroupBuilder) resolvePath(path string, params ...interface{}) *url.URL {
	relativeURL := &url.URL{
		Path: fmt.Sprintf(path, params...),
	}
	return b.Endpoint.ResolveReference(relativeURL)
}

// groupName returns the name of the security group to set or unset.
func (b *SecurityGroupBuilder) groupName() string {
	return fmt.Sprintf("credhub-internal-%s", b.Name)
}

// defaultRequester makes a HTTP request to create/update/query the application
// security groups.  It returns the security group GUID for the desired group,
// or an empty string if not found.
func (b *SecurityGroupBuilder) defaultRequester(ctx context.Context, guid, query, method string, body io.Reader) (string, error) {
	result, err := func() (string, error) {
		// The request URL; if `guid` is empty, this works out to be correct too.
		requestURL := b.resolvePath("/v2/security_groups")
		if guid != "" {
			requestURL = b.resolvePath("/v2/security_groups/%s", guid)
		}
		if query != "" {
			requestURL.RawQuery = query
		}
		b.Logf("Making %s request to %s", method, requestURL.String())
		req, err := http.NewRequestWithContext(ctx, method, requestURL.String(), body)
		if err != nil {
			return "", err
		}
		resp, err := b.Client.Do(req)
		if err != nil {
			return "", err
		}
		switch code := resp.StatusCode; {
		case code == http.StatusNotFound:
			// If the item is not found, report that instead of an error.
			return "", nil
		case code < 200 || code >= 400:
			return "", fmt.Errorf("got unexpected response: %s", resp.Status)
		}

		switch method {
		case http.MethodGet:
			// We're looking for a matching security group.
			var responseData struct {
				Resources []SecurityGroupDefinition `json:"resources"`
			}
			err = json.NewDecoder(resp.Body).Decode(&responseData)
			if err != nil {
				return "", fmt.Errorf("failed to parse JSON: %w", err)
			}

			b.Logf("Got security groups: %+v", responseData)
			for _, resource := range responseData.Resources {
				if resource.Entity.Name == b.groupName() {
					return resource.Metadata.GUID, nil
				}
			}
			return "", nil

		case http.MethodDelete:
			// There is no response body on deleting a security group,
			return "", nil

		default:
			// The response is a single security group on create / update.
			definition := SecurityGroupDefinition{}
			err = json.NewDecoder(resp.Body).Decode(&definition)
			if err != nil {
				return "", fmt.Errorf("failed to parse JSON: %w", err)
			}
			b.Logf("Got security group: %+v", definition)
			return definition.Metadata.GUID, nil
		}
	}()
	if err != nil {
		return "", fmt.Errorf("CC request failed: %w", err)
	}
	return result, nil
}

// groupGUID returns the GUID of the existing security group, if one already
// exists.
func (b *SecurityGroupBuilder) groupID(ctx context.Context) (string, error) {
	if b.groupIDOverride != nil {
		return *b.groupIDOverride, nil // for testing
	}
	if b.makeSecurityGroupRequest == nil {
		b.makeSecurityGroupRequest = b.defaultRequester
	}

	var result string
	err := (func() error {
		query := url.Values{}
		query.Set("q", fmt.Sprintf("name:%s", b.groupName()))

		var err error
		result, err = b.makeSecurityGroupRequest(ctx, "", query.Encode(), http.MethodGet, nil)
		if err != nil {
			return err
		}
		return nil
	})()
	if err != nil {
		return "", fmt.Errorf("failed to get security group: %w", err)
	}
	return result, nil
}

// buildSecurityGroup returns the JSON-serialized security group definition.
func (b *SecurityGroupBuilder) buildSecurityGroup() (io.Reader, error) {
	entity := securityGroupEntity{
		Name: b.groupName(),
		Rules: []securityGroupRule{
			securityGroupRule{
				Protocol:    "tcp",
				Destination: b.Address,
				Ports:       b.Ports,
				Description: fmt.Sprintf("%s service access", b.Name),
			},
		},
	}

	contentBytes, err := json.Marshal(entity)
	if err != nil {
		return nil, err
	}
	return bytes.NewReader(contentBytes), nil
}

// bindDefaultSecurityGroups causes the give security group to be applied to
// both staging and running applications across the CF deployment.
func (b *SecurityGroupBuilder) bindDefaultSecurityGroups(ctx context.Context, guid string, lifecycle lifecycleType) error {
	err := func() error {
		bindURL := b.resolvePath("/v2/config/%s_security_groups/%s", lifecycle, guid)
		req, err := http.NewRequestWithContext(ctx, http.MethodPut, bindURL.String(), nil)
		if err != nil {
			return err
		}
		resp, err := b.Client.Do(req)
		if err != nil {
			return err
		}
		if resp.StatusCode < 200 || resp.StatusCode >= 400 {
			return fmt.Errorf("got unexpected response: %s", resp.Status)
		}
		b.Logf("Successfully bound %s security group: %s", lifecycle, resp.Status)
		return nil
	}()
	if err != nil {
		return fmt.Errorf("failed to bind %s security group: %w", lifecycle, err)
	}
	return nil
}
