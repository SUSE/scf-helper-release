package cc

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"

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

/*
type mockCC struct {
	*http.ServeMux
	securityGroups []*cc.SecurityGroupDefinition
	defaultGroups  map[string]map[string]struct{}
}

func newMockCC() *mockCC {
	m := &mockCC{
		ServeMux: http.NewServeMux(),
		defaultGroups: map[string]map[string]struct{}{
			"staging": make(map[string]struct{}),
			"running": make(map[string]struct{}),
		},
	}
	m.HandleFunc("/v2/security_groups", m.handleNoID)
	m.HandleFunc("/v2/security_groups/", m.handleUpdate)
	m.HandleFunc("/v2/config/staging_security_groups/",
		func(w http.ResponseWriter, r *http.Request) {
			m.handleBind("staging", w, r)
		})
	m.HandleFunc("/v2/config/running_security_groups/",
		func(w http.ResponseWriter, r *http.Request) {
			m.handleBind("running", w, r)
		})

	return m
}

func (m *mockCC) handleNoID(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		m.handleList(w, r)
	case http.MethodPost:
		m.handleCreate(w, r)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
		_, _ = w.Write([]byte(fmt.Sprintf("method %s not allowed", r.Method)))
	}
}

func (m *mockCC) handleList(w http.ResponseWriter, r *http.Request) {
	groups := make([]*cc.SecurityGroupDefinition, 0, len(m.securityGroups))
	query := r.URL.Query().Get("q")
	if query == "" {
		copy(groups, m.securityGroups)
	} else {
		if !strings.HasPrefix(query, "name:") {
			w.WriteHeader(http.StatusBadRequest)
			_, err := w.Write([]byte(fmt.Sprintf("Invalid query %s", query)))
			if err != nil {
				fmt.Printf("Error writing invalid query response: %v", err)
			}
			return
		}
		query = strings.TrimPrefix(query, "name:")
		for _, group := range m.securityGroups {
			if group.Entity.Name == query {
				groups = append(groups, group)
			}
		}
	}

	result := map[string]interface{}{
		"resources": groups,
	}
	err := json.NewEncoder(w).Encode(result)
	if err != nil {
		fmt.Printf("Error writing query response: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(fmt.Sprintf("could not write query response: %v", err)))
		return
	}
}

func (m *mockCC) handleCreate(w http.ResponseWriter, r *http.Request) {
	newGroup := cc.SecurityGroupDefinition{}
	err := json.NewDecoder(r.Body).Decode(&newGroup.Entity)
	if err != nil {
		msg := fmt.Sprintf("could not read entity: %v", err)
		fmt.Printf("%s\n", msg)
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(msg))
		return
	}
	// nobody said the GUID actually has to be a GUID...
	newGroup.Metadata.GUID = fmt.Sprintf("%d", time.Now().UnixNano())

	m.securityGroups = append(m.securityGroups, &newGroup)
	w.WriteHeader(http.StatusCreated)
	err = json.NewEncoder(w).Encode(&newGroup)
	if err != nil {
		msg := fmt.Sprintf("could not write new group: %v", err)
		fmt.Printf("%s\n", msg)
		_, _ = w.Write([]byte(msg))
	}
}

func (m *mockCC) handleUpdate(w http.ResponseWriter, r *http.Request) {
	groupID := m.getGroupIDFromRequest(r)
	group, err := m.findGroupByID(groupID)
	if err != nil {
		msg := fmt.Sprintf("error finding group by ID: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(msg))
		fmt.Printf("%s\n", msg)
		return
	}
	if group == nil {
		msg := fmt.Sprintf("could not find group id %s", groupID)
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte(msg))
		return
	}

	err = json.NewDecoder(r.Body).Decode(&group.Entity)
	if err != nil {
		msg := fmt.Sprintf("could not read entity: %v", err)
		fmt.Printf("%s\n", msg)
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(msg))
		return
	}

	w.WriteHeader(http.StatusCreated)
	err = json.NewEncoder(w).Encode(group)
	if err != nil {
		msg := fmt.Sprintf("could not write new group: %v", err)
		fmt.Printf("%s\n", msg)
		_, _ = w.Write([]byte(msg))
	}
}

func (m *mockCC) handleBind(lifeCycle string, w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPut {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	groupID := m.getGroupIDFromRequest(r)
	group, err := m.findGroupByID(groupID)
	if err != nil {
		msg := fmt.Sprintf("could not get group by ID %s: %v", groupID, err)
		fmt.Printf("%s\n", msg)
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(msg))
		return
	}
	if group == nil {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	m.defaultGroups[lifeCycle][groupID] = struct{}{}
	w.WriteHeader(http.StatusAccepted)
}

func (m *mockCC) getGroupIDFromRequest(r *http.Request) string {
	index := strings.LastIndex(r.URL.Path, "/")
	if index >= 0 {
		return r.URL.Path[index+1:]
	}
	return r.URL.Path
}

func (m *mockCC) findGroup(fn func(*cc.SecurityGroupDefinition) bool) (*cc.SecurityGroupDefinition, error) {
	var result *cc.SecurityGroupDefinition
	for _, group := range m.securityGroups {
		if fn(group) {
			if result != nil {
				return nil, fmt.Errorf("multiple groups with same matcher")
			}
			result = group
		}
	}
	return result, nil
}

func (m *mockCC) findGroupByID(groupID string) (*cc.SecurityGroupDefinition, error) {
	group, err := m.findGroup(func(group *cc.SecurityGroupDefinition) bool {
		return group.Metadata.GUID == groupID
	})
	if err != nil {
		return nil, fmt.Errorf("error finding group %s by ID: %w", groupID, err)
	}
	return group, nil
}
*/

func TestApply(t *testing.T) {
	ctx := context.Background()
	t.Parallel()

	bindingHandler := func(t *testing.T, groupGUID string, boundLifecycles map[lifecycleType]bool) http.HandlerFunc {
		return func(w http.ResponseWriter, req *http.Request) {
			pathParts := strings.FieldsFunc(req.URL.Path,
				func(r rune) bool { return r == '/' })
			if !assert.Lenf(t, pathParts, 4, "Unexpected request path %s", req.URL.Path) {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			if !assert.Equalf(t, groupGUID, pathParts[3], "Unexpected security group %s to bind", pathParts[3]) {
				w.WriteHeader(http.StatusNotFound)
				return
			}

			var lifecycle lifecycleType
			switch pathParts[2] {
			case "staging_security_groups":
				lifecycle = lifecycleStaging
			case "running_security_groups":
				lifecycle = lifecycleRunning
			default:
				assert.Failf(t, "unknown lifecycle %s", pathParts[2])
				return
			}

			t.Logf("Got request for %s", lifecycle)
			boundLifecycles[lifecycle] = true
			w.WriteHeader(http.StatusNoContent)
		}
	}

	t.Run("creates a new security group", func(t *testing.T) {
		t.Parallel()

		builtGUID := "newly-created-security-group"

		boundLifecycles := map[lifecycleType]bool{}
		mux := http.NewServeMux()
		mux.Handle("/v2/config/", bindingHandler(t, builtGUID, boundLifecycles))
		server := httptest.NewServer(mux)
		defer server.Close()
		serverURL, err := url.Parse(server.URL)
		require.NoError(t, err, "failed to parse server URL")

		emptyGUID := ""
		builder := &SecurityGroupBuilder{
			Logger:          t,
			Client:          server.Client(),
			Endpoint:        serverURL,
			Name:            "new-security-group",
			Address:         serverURL.Hostname(),
			Ports:           serverURL.Port(),
			groupIDOverride: &emptyGUID,
		}
		builder.makeSecurityGroupRequest = func(ctx context.Context, guid, query, method string, body io.Reader) (string, error) {
			assert.Empty(t, guid, "unexpected non-empty GUID to create")
			assert.Equal(t, http.MethodPost, method, "unexpected method to create new security group")
			return builtGUID, nil
		}
		err = builder.Apply(ctx)
		assert.NoError(t, err, "unexpected error creating new security group")
		assert.Contains(t, boundLifecycles, lifecycleStaging, "staging not bound")
		assert.Contains(t, boundLifecycles, lifecycleRunning, "running not bound")
	})

	t.Run("updates an existing security group", func(t *testing.T) {
		t.Parallel()

		existingGUID := "existing-security-group"
		boundLifecycles := map[lifecycleType]bool{}
		mux := http.NewServeMux()
		mux.Handle("/v2/config/", bindingHandler(t, existingGUID, boundLifecycles))
		server := httptest.NewServer(mux)
		defer server.Close()
		serverURL, err := url.Parse(server.URL)
		require.NoError(t, err, "failed to parse server URL")

		builder := &SecurityGroupBuilder{
			Logger:          t,
			Client:          server.Client(),
			Endpoint:        serverURL,
			Name:            "existing-security-group",
			Address:         serverURL.Hostname(),
			Ports:           serverURL.Port(),
			groupIDOverride: &existingGUID,
		}
		builder.makeSecurityGroupRequest = func(ctx context.Context, guid, query, method string, body io.Reader) (string, error) {
			assert.Equal(t, existingGUID, guid, "unexpected GUID to update")
			assert.Equal(t, http.MethodPut, method, "unexpected method to update existing security group")
			return existingGUID, nil
		}
		err = builder.Apply(ctx)
		assert.NoError(t, err, "unexpected error updating existing security group")
		assert.Contains(t, boundLifecycles, lifecycleStaging, "staging not bound")
		assert.Contains(t, boundLifecycles, lifecycleRunning, "running not bound")
	})
}

func TestRemove(t *testing.T) {
	t.Parallel()

	t.Run("allows no groups to remove", func(t *testing.T) {
		t.Parallel()
		emptyGUID := ""
		builder := &SecurityGroupBuilder{
			Logger:          t,
			groupIDOverride: &emptyGUID,
		}
		builder.makeSecurityGroupRequest = func(ctx context.Context, guid, query, method string, body io.Reader) (string, error) {
			assert.Failf(t, "unexpected request", "trying to %s group %s", method, guid)
			return "", fmt.Errorf("test failed")
		}
		err := builder.Remove(context.Background())
		assert.NoError(t, err, "unexpected error removing no group")
	})

	t.Run("removes the desired group", func(t *testing.T) {
		t.Parallel()
		groupGUID := "some-group-to-be-removed"
		builder := &SecurityGroupBuilder{
			Logger:          t,
			groupIDOverride: &groupGUID,
		}
		builder.makeSecurityGroupRequest = func(ctx context.Context, guid, query, method string, body io.Reader) (string, error) {
			assert.Equal(t, http.MethodDelete, method, "unexpected method")
			assert.Equal(t, groupGUID, guid, "unexpected GUID")
			return "", nil
		}
		err := builder.Remove(context.Background())
		assert.NoError(t, err, "unexpected error removing group")
	})
}

func TestRequestor(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	makeBuilder := func(t *testing.T) (*SecurityGroupBuilder, *http.ServeMux, chan<- bool, error) {
		cleanupWaiter := make(chan bool)
		mux := http.NewServeMux()
		mux.HandleFunc("/", handleUnexpectedPath(t))
		server := httptest.NewTLSServer(mux)
		go func() {
			<-cleanupWaiter
			server.Close()
		}()
		serverURL, err := url.Parse(server.URL)
		if err != nil {
			close(cleanupWaiter)
			return nil, nil, nil, fmt.Errorf("could not parse temporary server URL: %s", err)
		}
		builder := &SecurityGroupBuilder{
			Logger:   t,
			Client:   server.Client(),
			Endpoint: serverURL,
		}
		return builder, mux, cleanupWaiter, nil
	}

	t.Run("query for a group", func(t *testing.T) {
		t.Parallel()
		const expected = "desired-guid"

		builder, mux, cleanup, err := makeBuilder(t)
		defer close(cleanup)
		require.NoError(t, err, "could not create builder")

		query := url.Values{}
		query.Set("q", fmt.Sprintf("name:%s", builder.groupName()))
		mux.HandleFunc("/v2/security_groups", func(w http.ResponseWriter, r *http.Request) {
			if !assert.Equal(t, http.MethodGet, r.Method, "bad HTTP method") {
				w.WriteHeader(http.StatusMethodNotAllowed)
				return
			}
			if !assert.Equal(t, query.Get("q"), r.FormValue("q")) {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			_, err := io.WriteString(w, fmt.Sprintf(`{
				"resources": [
					{ "metadata": { "guid": "%s" }, "entity": { "name": "%s" } },
					{ "metadata": { "guid": "%s" }, "entity": { "name": "%s" } }
				]
			}`, "incorrect", "wrong name", expected, builder.groupName()))
			assert.NoError(t, err, "could not write response")
		})

		actual, err := builder.defaultRequester(ctx, "", query.Encode(), http.MethodGet, nil)
		assert.NoError(t, err, "unexpected error running query")
		assert.Equal(t, expected, actual, "unepxected id")
	})

	t.Run("create a group", func(t *testing.T) {
		t.Parallel()
		const expected = "group-guid"
		const contents = "body contents"

		builder, mux, cleanup, err := makeBuilder(t)
		defer close(cleanup)
		require.NoError(t, err, "could not create builder")

		mux.HandleFunc("/v2/security_groups", func(w http.ResponseWriter, r *http.Request) {
			if !assert.Equal(t, http.MethodPost, r.Method, "bad HTTP method") {
				w.WriteHeader(http.StatusMethodNotAllowed)
				return
			}
			body, err := ioutil.ReadAll(r.Body)
			if !assert.NoError(t, err, "could not read request body") {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			if !assert.Equal(t, contents, string(body), "unexpected request body") {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			w.WriteHeader(http.StatusOK)
			_, err = io.WriteString(w, fmt.Sprintf(`{
				"metadata": { "guid": "%s" }, "entity": { "name": "%s" }
			}`, expected, "group-name"))
			assert.NoError(t, err, "failed to write response")
		})

		body := bytes.NewBufferString(contents)
		actual, err := builder.defaultRequester(ctx, "", "", http.MethodPost, body)
		assert.NoError(t, err, "could not make request")
		assert.Equal(t, expected, actual, "unexpected group GUID")
	})

	t.Run("update a group", func(t *testing.T) {
		t.Parallel()
		const (
			guid    = "group-guid"
			newName = "new-name"
		)
		expectedBody := fmt.Sprintf(`{ "name": "%s" }`, newName)

		builder, mux, cleanup, err := makeBuilder(t)
		defer close(cleanup)
		require.NoError(t, err, "could not create builder")

		executedUpdate := false
		mux.HandleFunc("/v2/security_groups/"+guid, func(w http.ResponseWriter, r *http.Request) {
			if !assert.Equal(t, http.MethodPut, r.Method, "unexpected method") {
				w.WriteHeader(http.StatusMethodNotAllowed)
				return
			}
			body, err := ioutil.ReadAll(r.Body)
			if !assert.NoError(t, err, "could not read request body") {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			if !assert.Equal(t, expectedBody, string(body), "unexpected request body") {
				w.WriteHeader(http.StatusBadRequest)
				return
			}

			executedUpdate = true
			w.WriteHeader(http.StatusOK)
			_, err = io.WriteString(w, fmt.Sprintf(`{
				"metadata": { "guid": "%s" }, "entity": { "name": "%s" }
			}`, guid, newName))
			assert.NoError(t, err, "failed to write response")
		})

		body := bytes.NewBufferString(expectedBody)
		actual, err := builder.defaultRequester(ctx, guid, "", http.MethodPut, body)
		assert.NoError(t, err, "error updating security group")
		assert.Equal(t, guid, actual)
		assert.True(t, executedUpdate, "did not execute update")
	})

	t.Run("delete a group", func(t *testing.T) {
		t.Parallel()
		const (
			existingGUID = "existing-guid"
			missingGUID  = "missing-guid"
		)

		deleted := map[string]bool{}
		deletedMut := sync.Mutex{}
		wg := sync.WaitGroup{}
		wg.Add(1)
		defer wg.Done()
		builder, mux, cleanup, err := makeBuilder(t)
		go func() {
			defer close(cleanup)
			wg.Wait()
			assert.Contains(t, deleted, existingGUID)
			assert.Contains(t, deleted, missingGUID)
		}()
		require.NoError(t, err, "could not create builder")

		mux.HandleFunc("/v2/security_groups/"+existingGUID, func(w http.ResponseWriter, r *http.Request) {
			if !assert.Equal(t, http.MethodDelete, r.Method, "unexpected method") {
				w.WriteHeader(http.StatusMethodNotAllowed)
				return
			}
			deletedMut.Lock()
			deleted[existingGUID] = true
			deletedMut.Unlock()
			w.WriteHeader(http.StatusNoContent)
		})
		mux.HandleFunc("/v2/security_groups/"+missingGUID, func(w http.ResponseWriter, r *http.Request) {
			if !assert.Equal(t, http.MethodDelete, r.Method, "unexpected method") {
				w.WriteHeader(http.StatusMethodNotAllowed)
				return
			}
			deletedMut.Lock()
			deleted[missingGUID] = true
			deletedMut.Unlock()
			w.WriteHeader(http.StatusNotFound)
		})

		t.Run("sucessfully", func(t *testing.T) {
			wg.Add(1)
			defer wg.Done()
			t.Parallel()
			_, err := builder.defaultRequester(ctx, existingGUID, "", http.MethodDelete, nil)
			assert.NoError(t, err, "failed to delete existing GUID")
		})
		t.Run("when the group is missing", func(t *testing.T) {
			wg.Add(1)
			defer wg.Done()
			t.Parallel()
			_, err := builder.defaultRequester(ctx, missingGUID, "", http.MethodDelete, nil)
			assert.NoError(t, err, "failed to delete missing GUID")
		})
	})
	assert.NotNil(t, makeBuilder)
}

/*
func TestGetExistingSecurityGroup(t *testing.T) {
	t.Parallel()
	mockCCInstance := newMockCC()
	server := httptest.NewServer(mockCCInstance)
	defer server.Close()

	ctx := context.Background()
	baseURL, err := url.Parse(server.URL)
	require.NoError(t, err, "could not parse server URL")
	client := server.Client()
	groupID, err := cc.GetExistingSecurityGroup(ctx, client, baseURL)
	require.NoError(t, err, "could not get group ID")
	require.Empty(t, groupID, "got unexpected group ID")

	newEntity := cc.BuildSecurityGroup(
		[]cc.EndpointInfo{cc.EndpointInfo{Addresses: []string{"1"}, Port: 80}})
	entityBytes, err := json.Marshal(newEntity)
	require.NoError(t, err, "could not marshal sample data")
	entityReader := bytes.NewReader(entityBytes)
	createdID, err := cc.CreateOrUpdateSecurityGroup(ctx, client, baseURL, entityReader)
	require.NoError(t, err, "could not create security group")
	require.NotEmpty(t, createdID, "empty group ID returned after creation")

	createdGroup, err := mockCCInstance.findGroupByID(createdID)
	require.NoError(t, err, "error finding group by ID")
	require.NotNil(t, createdGroup, "could not find created group")
	require.Equal(t, createdGroup.Entity, newEntity)

	updatedEntity := cc.BuildSecurityGroup(
		[]cc.EndpointInfo{cc.EndpointInfo{Addresses: []string{"hello"}, Port: 443}})
	entityBytes, err = json.Marshal(updatedEntity)
	require.NoError(t, err, "could not marshal sample data")
	entityReader = bytes.NewReader(entityBytes)
	updatedID, err := cc.CreateOrUpdateSecurityGroup(ctx, client, baseURL, entityReader)
	require.NoError(t, err, "could not update security group")
	require.Equal(t, createdID, updatedID, "got different ID on update")

	updatedGroup, err := mockCCInstance.findGroupByID(updatedID)
	require.NoError(t, err, "error finding group by ID")
	require.NotNil(t, updatedGroup, "could not find updated group")
	require.Equal(t, updatedGroup.Entity, updatedEntity)
}

func TestSetupCredHubApplicationSecurityGroups(t *testing.T) {
	t.Parallel()

	ctx, fakeMount, err := quarkshelpers.GenerateFakeMount(context.Background(), "deployment-name", t)
	require.NoError(t, err, "could not set up temporary mount directorry")
	defer fakeMount.CleanUp()

	mockCCInstance := newMockCC()
	server, err := cchelpers.NewMockServer(ctx, t, fakeMount, mockCCInstance)
	require.NoError(t, err, "could not create mock CC server")
	defer server.Close()

	client := server.Client()

	err = cc.SetupCredHubApplicationSecurityGroups(ctx, client,
		[]cc.EndpointInfo{cc.EndpointInfo{Addresses: []string{"1"}, Port: 22}})
	require.NoError(t, err, "could not set up credhub security groups")

	group, err := mockCCInstance.findGroup(func(group *cc.SecurityGroupDefinition) bool {
		return group.Entity.Name == cc.SecurityGroupName
	})
	require.NoError(t, err, "could not find group %s by name", cc.SecurityGroupName)
	require.NotNil(t, group, "group %s was not found", cc.SecurityGroupName)
	require.Len(t, group.Entity.Rules, 1, "unexpected rules")
	rule := group.Entity.Rules[0]
	require.Equal(t, "1", rule.Destination)
	require.Equal(t, "22", rule.Ports)

	for _, lifecycle := range []string{"running", "staging"} {
		container := mockCCInstance.defaultGroups[lifecycle]
		require.Contains(t, container, group.Metadata.GUID,
			"group not set as %s", lifecycle)
	}

	// Do it again and check for updates
	err = cc.SetupCredHubApplicationSecurityGroups(ctx, client,
		[]cc.EndpointInfo{cc.EndpointInfo{Addresses: []string{"irc"}, Port: 6667}})
	require.NoError(t, err, "could not set up credhub security groups")

	group, err = mockCCInstance.findGroup(func(group *cc.SecurityGroupDefinition) bool {
		return group.Entity.Name == cc.SecurityGroupName
	})
	require.NoError(t, err, "could not find group %s by name", cc.SecurityGroupName)
	require.NotNil(t, group, "group %s was not found", cc.SecurityGroupName)
	require.Len(t, group.Entity.Rules, 1, "unexpected rules")
	rule = group.Entity.Rules[0]
	require.Equal(t, "irc", rule.Destination)
	require.Equal(t, "6667", rule.Ports)

	for _, lifecycle := range []string{"running", "staging"} {
		container := mockCCInstance.defaultGroups[lifecycle]
		require.Contains(t, container, group.Metadata.GUID,
			"group not set as %s", lifecycle)
	}
}
*/
