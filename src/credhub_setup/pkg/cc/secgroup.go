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

// EndpointInfo describes an endpoint we should expose in the application
// security groups, consisting of a host name, a port, and a description.  The
// host name, however, is expressed as the IP addresses it resolves to.
type EndpointInfo struct {
	Addresses   []string
	Port        string
	Description string
}

// lifecycleType is the lifecycle phase of of a security group, either
// lifecycleRunning or lifecycleStaging.
type lifecycleType string

const (
	// SecurityGroupName is the name of the security group to create / update.
	SecurityGroupName = "credhub-internal"

	// The phases for the security group to bind to.
	lifecycleRunning = lifecycleType("running")
	lifecycleStaging = lifecycleType("staging")
)

type SecurityGroupBuilder struct {
	logger.Logger
	Client   *http.Client
	Endpoint *url.URL
	Name     string
	Address  string
	Ports    string
}

func (b *SecurityGroupBuilder) Apply(ctx context.Context) error {
	err := func() error {
		groupID, err := b.groupGUID(ctx)
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

func (b *SecurityGroupBuilder) Remove(ctx context.Context) error {
	err := func() error {
		groupID, err := b.groupGUID(ctx)
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

// makeSecurityGroupRequest make a HTTP request to create/update/query the
// security groups.  It returns the security group GUID for the desired group,
// or an empty string if not found.
func (b *SecurityGroupBuilder) makeSecurityGroupRequest(ctx context.Context, guid, query, method string, body io.Reader) (string, error) {
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

	if guid != "" {
		// A GUID is given; the response is a single security group.
		definition := SecurityGroupDefinition{}
		err = json.NewDecoder(resp.Body).Decode(&definition)
		if err != nil {
			return "", err
		}
		b.Logf("Got security group: %+v", definition)
		return definition.Metadata.GUID, nil
	}

	// We're looking for a matchin security group.
	var responseData struct {
		Resources []SecurityGroupDefinition `json:"resources"`
	}
	err = json.NewDecoder(resp.Body).Decode(&responseData)
	if err != nil {
		return "", err
	}

	b.Logf("Got security groups: %+v", responseData)
	for _, resource := range responseData.Resources {
		if resource.Entity.Name == b.groupName() {
			return resource.Metadata.GUID, nil
		}
	}
	return "", nil
}

// groupGUID returns the GUID of the existing security group, if one already
// exists.
func (b *SecurityGroupBuilder) groupGUID(ctx context.Context) (string, error) {
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

// BuildSecurityGroup constructs the security group entity (as required to be
// uploaded to the CC API) for apps to be able to communicate with CredHub,
// given the addresses for CredHub and the port it's listening on.
func BuildSecurityGroup(endpoints []EndpointInfo) securityGroupEntity {
	var entries []securityGroupRule
	for _, endpoint := range endpoints {
		for _, addr := range endpoint.Addresses {
			desc := endpoint.Description
			if desc == "" {
				desc = "CredHub service access"
			}
			entries = append(entries, securityGroupRule{
				Protocol:    "tcp",
				Destination: addr,
				Ports:       endpoint.Port,
				Description: desc,
			})
		}
	}
	return securityGroupEntity{
		Name:  SecurityGroupName,
		Rules: entries,
	}
}

// GetExistingSecurityGroup returns the GUID of the existing security group, if
// there is one; otherwise, returns the empty string.
func GetExistingSecurityGroup(ctx context.Context, log logger.Logger, client *http.Client, baseURL *url.URL) (string, error) {
	existingURL := &url.URL{
		Path: "/v2/security_groups",
	}
	existingURL = baseURL.ResolveReference(existingURL)
	query := existingURL.Query()
	query.Set("q", fmt.Sprintf("name:%s", SecurityGroupName))
	existingURL.RawQuery = query.Encode()
	log.Logf("Checking for existing groups via %s\n", existingURL)
	resp, err := client.Get(existingURL.String())
	if err != nil {
		return "", fmt.Errorf("failed to get existing security groups: %w", err)
	}

	var responseData struct {
		Resources []SecurityGroupDefinition `json:"resources"`
	}
	err = json.NewDecoder(resp.Body).Decode(&responseData)
	if err != nil {
		return "", fmt.Errorf("failed to get existing security groups: %w", err)
	}

	log.Logf("Got security groups: %+v\n", responseData)
	for _, resource := range responseData.Resources {
		if resource.Entity.Name == SecurityGroupName {
			return resource.Metadata.GUID, nil
		}
	}

	return "", nil
}

// CreateOrUpdateSecurityGroup creates a new security group, or updates an
// existing security group if one already exists.  The security group definition
// is read from the io.Reader.
func CreateOrUpdateSecurityGroup(ctx context.Context, log logger.Logger, client *http.Client, baseURL *url.URL, contentReader io.Reader) (string, error) {
	groupID, err := GetExistingSecurityGroup(ctx, log, client, baseURL)
	if err != nil {
		return "", err
	}
	var updateURL *url.URL
	var method string
	if groupID == "" {
		updateURL = &url.URL{
			Path: "/v2/security_groups",
		}
		method = http.MethodPost
	} else {
		updateURL = &url.URL{
			Path: fmt.Sprintf("/v2/security_groups/%s", groupID),
		}
		method = http.MethodPut
	}
	updateURL = baseURL.ResolveReference(updateURL)
	req, err := http.NewRequestWithContext(ctx, method, updateURL.String(), contentReader)
	if err != nil {
		return "", fmt.Errorf("failed to create or update security group: could not create request: %w", err)
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to create or update security group: %w", err)
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 400 {
		err = fmt.Errorf("got unexpected response: %s", resp.Status)
		return "", fmt.Errorf("failed to create or update security group: %w", err)
	}

	var resultingSecurityGroup SecurityGroupDefinition
	err = json.NewDecoder(resp.Body).Decode(&resultingSecurityGroup)
	if err != nil {
		err = fmt.Errorf("failed to read response: %w", err)
		return "", fmt.Errorf("failed to create or update security group: %w", err)
	}
	log.Logf("Succesfully updated security group: %s / %+v\n", resp.Status, resultingSecurityGroup)

	return resultingSecurityGroup.Metadata.GUID, nil
}

// bindDefaultSecurityGroup binds the security group with the given GUID to both
// the staging and running lifecycle phases as a default security group (i.e.
// across all spaces).
func bindDefaultSecurityGroup(ctx context.Context, log logger.Logger, lifecycle lifecycleType, groupID string, client *http.Client, baseURL *url.URL) error {
	bindURL := baseURL.ResolveReference(&url.URL{
		Path: fmt.Sprintf("/v2/config/%s_security_groups/%s", lifecycle, groupID),
	})
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, bindURL.String(), nil)
	if err != nil {
		return fmt.Errorf("failed to bind %s security group: could not create request: %w", lifecycle, err)
	}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to bind %s security group: %w", lifecycle, err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 400 {
		err = fmt.Errorf("got unexpected response: %s", resp.Status)
		return fmt.Errorf("failed to bind %s security group: %w", lifecycle, err)
	}
	log.Logf("Successfully bound %s security group: %s\n", lifecycle, resp.Status)
	return nil
}

// SetupCredHubApplicationSecurityGroups does all of the work to ensure an
// appropriate security group exists and is bound to the appropriate lifecycle
// phases.  It requres the addresses and port that the target (CredHub) is
// listening on.
func SetupCredHubApplicationSecurityGroups(ctx context.Context, log logger.Logger, ccURL *url.URL, client *http.Client, endpoints []EndpointInfo) error {
	contents := BuildSecurityGroup(endpoints)
	contentBytes, err := json.Marshal(contents)
	if err != nil {
		return fmt.Errorf("failed to setup security groups: marshaling security groups: %w", err)
	}
	contentReader := bytes.NewReader(contentBytes)

	groupID, err := CreateOrUpdateSecurityGroup(ctx, log, client, ccURL, contentReader)
	if err != nil {
		return fmt.Errorf("failed to setup security groups: %w", err)
	}

	for _, lifecycle := range []lifecycleType{lifecycleRunning, lifecycleStaging} {
		err = bindDefaultSecurityGroup(ctx, log, lifecycle, groupID, client, ccURL)
		if err != nil {
			return fmt.Errorf("failed to setup security groups: %w", err)
		}
	}

	return nil
}

func RemoveCredHubApplicationSecurityGroups(ctx context.Context, log logger.Logger) error {
	return fmt.Errorf("not implemented")
}
