// Copyright IBM Corp. 2020, 2026
// SPDX-License-Identifier: BUSL-1.1

package oidc

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/hashicorp/boundary/internal/auth/oidc/store"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockDirectoryServer creates a test HTTP server that mimics the Google Admin
// SDK Directory API Groups.list endpoint. It returns the provided groups for
// any userKey and requires no authentication (the test bypasses the OAuth2
// layer by injecting a pre-configured http.Client directly via listGoogleGroups).
func mockDirectoryServer(t *testing.T, responses []googleDirectoryGroupsResponse) *httptest.Server {
	t.Helper()
	callCount := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if callCount >= len(responses) {
			t.Errorf("unexpected extra request #%d to mock directory server", callCount+1)
			http.Error(w, "unexpected request", http.StatusInternalServerError)
			return
		}
		resp := responses[callCount]
		callCount++
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(resp); err != nil {
			t.Errorf("failed to encode mock response: %v", err)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

// rewriteGroupsURL returns an http.Client whose transport rewrites requests
// destined for googleDirectoryGroupsURL to the given mock server URL instead,
// so we can test listGoogleGroups against a local server.
func clientPointingAt(mockURL string) *http.Client {
	return &http.Client{
		Transport: &urlRewriteTransport{targetBase: mockURL},
	}
}

type urlRewriteTransport struct {
	targetBase string
}

func (t *urlRewriteTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	// Replace the scheme+host with the mock server's, preserving path+query.
	clone := req.Clone(req.Context())
	clone.URL.Scheme = "http"
	base := strings.TrimRight(t.targetBase, "/")
	// Strip the real host prefix so the path hits the mock server root.
	clone.URL.Host = strings.TrimPrefix(base, "http://")
	clone.URL.Path = "/"
	return http.DefaultTransport.RoundTrip(clone)
}

func TestListGoogleGroups_SinglePage(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	want := []string{"eng@example.com", "infra@example.com"}
	srv := mockDirectoryServer(t, []googleDirectoryGroupsResponse{
		{
			Groups: []struct {
				Email string `json:"email"`
			}{
				{Email: "eng@example.com"},
				{Email: "infra@example.com"},
			},
		},
	})

	got, err := listGoogleGroups(ctx, clientPointingAt(srv.URL), "alice@example.com")
	require.NoError(t, err)
	assert.Equal(t, want, got)
}

func TestListGoogleGroups_Pagination(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	srv := mockDirectoryServer(t, []googleDirectoryGroupsResponse{
		{
			Groups: []struct {
				Email string `json:"email"`
			}{
				{Email: "eng@example.com"},
			},
			NextPageToken: "token-page-2",
		},
		{
			Groups: []struct {
				Email string `json:"email"`
			}{
				{Email: "infra@example.com"},
				{Email: "security@example.com"},
			},
		},
	})

	got, err := listGoogleGroups(ctx, clientPointingAt(srv.URL), "alice@example.com")
	require.NoError(t, err)
	assert.Equal(t, []string{"eng@example.com", "infra@example.com", "security@example.com"}, got)
}

func TestListGoogleGroups_EmptyMembership(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	srv := mockDirectoryServer(t, []googleDirectoryGroupsResponse{
		{}, // no groups, no next page token
	})

	got, err := listGoogleGroups(ctx, clientPointingAt(srv.URL), "alice@example.com")
	require.NoError(t, err)
	assert.Empty(t, got)
}

func TestListGoogleGroups_APIError(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, `{"error": {"code": 403, "message": "Not authorized"}}`, http.StatusForbidden)
	}))
	t.Cleanup(srv.Close)

	_, err := listGoogleGroups(ctx, clientPointingAt(srv.URL), "alice@example.com")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "403")
}

func TestListGoogleGroups_SkipsEmptyEmailGroups(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	srv := mockDirectoryServer(t, []googleDirectoryGroupsResponse{
		{
			Groups: []struct {
				Email string `json:"email"`
			}{
				{Email: "eng@example.com"},
				{Email: ""},
				{Email: "infra@example.com"},
			},
		},
	})

	got, err := listGoogleGroups(ctx, clientPointingAt(srv.URL), "alice@example.com")
	require.NoError(t, err)
	assert.Equal(t, []string{"eng@example.com", "infra@example.com"}, got)
}

func TestFetchGoogleWorkspaceGroups_ValidationErrors(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	cases := []struct {
		name               string
		serviceAccountJSON string
		adminEmail         string
		userEmail          string
		wantErr            string
	}{
		{
			name:               "missing service account JSON",
			serviceAccountJSON: "",
			adminEmail:         "admin@example.com",
			userEmail:          "alice@example.com",
			wantErr:            "missing service account JSON",
		},
		{
			name:               "missing admin email",
			serviceAccountJSON: `{"type":"service_account"}`,
			adminEmail:         "",
			userEmail:          "alice@example.com",
			wantErr:            "missing admin email",
		},
		{
			name:               "missing user email",
			serviceAccountJSON: `{"type":"service_account"}`,
			adminEmail:         "admin@example.com",
			userEmail:          "",
			wantErr:            "missing user email",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, err := fetchGoogleWorkspaceGroups(ctx, tc.serviceAccountJSON, tc.adminEmail, tc.userEmail)
			require.Error(t, err)
			assert.Contains(t, err.Error(), tc.wantErr)
		})
	}
}

// TestFetchGoogleWorkspaceGroups_MockHTTPClient verifies that
// fetchGoogleWorkspaceGroups plumbs the HTTP client through to listGoogleGroups
// correctly by injecting a mock googleHTTPClientFunc.
func TestFetchGoogleWorkspaceGroups_MockHTTPClient(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	want := []string{"eng@example.com"}
	srv := mockDirectoryServer(t, []googleDirectoryGroupsResponse{
		{
			Groups: []struct {
				Email string `json:"email"`
			}{
				{Email: "eng@example.com"},
			},
		},
	})

	// Swap out the package-level HTTP client factory to return a client that
	// points at our mock server instead of calling real Google OAuth2.
	orig := googleHTTPClientFunc
	t.Cleanup(func() { googleHTTPClientFunc = orig })
	googleHTTPClientFunc = func(_ context.Context, _, _ string) (*http.Client, error) {
		return clientPointingAt(srv.URL), nil
	}

	got, err := fetchGoogleWorkspaceGroups(ctx, `{"type":"service_account"}`, "admin@example.com", "alice@example.com")
	require.NoError(t, err)
	assert.Equal(t, want, got)
}

// TestFetchGoogleWorkspaceGroups_HTTPClientError verifies that errors from the
// HTTP client factory propagate correctly.
func TestFetchGoogleWorkspaceGroups_HTTPClientError(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	orig := googleHTTPClientFunc
	t.Cleanup(func() { googleHTTPClientFunc = orig })
	googleHTTPClientFunc = func(_ context.Context, _, _ string) (*http.Client, error) {
		return nil, fmt.Errorf("credential parse error")
	}

	_, err := fetchGoogleWorkspaceGroups(ctx, `{"type":"service_account"}`, "admin@example.com", "alice@example.com")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "credential parse error")
}

func TestAuthMethod_GoogleWorkspaceValidation(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	cases := []struct {
		name           string
		serviceAccount string
		adminEmail     string
		wantErr        bool
	}{
		{
			name:           "both set is valid",
			serviceAccount: `{"type":"service_account"}`,
			adminEmail:     "admin@example.com",
			wantErr:        false,
		},
		{
			name:           "both empty is valid",
			serviceAccount: "",
			adminEmail:     "",
			wantErr:        false,
		},
		{
			name:           "only service account set is invalid",
			serviceAccount: `{"type":"service_account"}`,
			adminEmail:     "",
			wantErr:        true,
		},
		{
			name:           "only admin email set is invalid",
			serviceAccount: "",
			adminEmail:     "admin@example.com",
			wantErr:        true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			am := &AuthMethod{
				AuthMethod: &store.AuthMethod{
					ScopeId:                           "o_1234567890",
					OperationalState:                  string(InactiveState),
					GoogleWorkspaceServiceAccountJson: tc.serviceAccount,
					GoogleWorkspaceAdminEmail:         tc.adminEmail,
				},
			}
			err := am.validate(ctx, "test")
			if tc.wantErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), "google_workspace_service_account_json and google_workspace_admin_email must both be set or both be empty")
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestAuthMethod_Clone_GoogleWorkspaceFields(t *testing.T) {
	t.Parallel()

	am := &AuthMethod{
		AuthMethod: &store.AuthMethod{
			PublicId:                          "amoidc_test1234",
			ScopeId:                           "o_1234567890",
			GoogleWorkspaceServiceAccountJson: `{"type":"service_account"}`,
			GoogleWorkspaceAdminEmail:         "admin@example.com",
			CtGoogleWorkspaceServiceAccountJson: []byte("encrypted-bytes"),
		},
	}

	cloned := am.Clone()
	assert.Equal(t, am.GoogleWorkspaceServiceAccountJson, cloned.GoogleWorkspaceServiceAccountJson)
	assert.Equal(t, am.GoogleWorkspaceAdminEmail, cloned.GoogleWorkspaceAdminEmail)
	assert.Equal(t, am.CtGoogleWorkspaceServiceAccountJson, cloned.CtGoogleWorkspaceServiceAccountJson)

	// Verify the clone is a deep copy: mutating the original doesn't affect the clone.
	am.GoogleWorkspaceAdminEmail = "other@example.com"
	am.CtGoogleWorkspaceServiceAccountJson[0] = 'X'
	assert.Equal(t, "admin@example.com", cloned.GoogleWorkspaceAdminEmail)
	assert.Equal(t, byte('e'), cloned.CtGoogleWorkspaceServiceAccountJson[0])
}
