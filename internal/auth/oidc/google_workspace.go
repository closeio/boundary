// Copyright IBM Corp. 2020, 2026
// SPDX-License-Identifier: BUSL-1.1

package oidc

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"

	"github.com/hashicorp/boundary/internal/errors"
	"golang.org/x/oauth2/google"
)

const (
	// googleDirectoryGroupsURL is the Admin SDK endpoint for listing a user's groups.
	googleDirectoryGroupsURL = "https://admin.googleapis.com/admin/directory/v1/groups"

	// googleDirectoryScope is the read-only OAuth2 scope for the Admin SDK
	// Directory API groups resource.
	googleDirectoryScope = "https://www.googleapis.com/auth/admin.directory.group.readonly"
)

// googleDirectoryGroupsResponse models the relevant fields from the Admin SDK
// Groups.list response.
type googleDirectoryGroupsResponse struct {
	Groups []struct {
		Email string `json:"email"`
	} `json:"groups"`
	NextPageToken string `json:"nextPageToken"`
}

// googleHTTPClientFunc creates an *http.Client authenticated to call the Google
// Admin SDK. It is a package-level variable so tests can substitute a mock
// without making real OAuth2 token requests.
var googleHTTPClientFunc = defaultGoogleHTTPClient

// defaultGoogleHTTPClient parses a service account JSON key and returns an
// HTTP client that impersonates adminEmail via domain-wide delegation.
func defaultGoogleHTTPClient(ctx context.Context, serviceAccountJSON, adminEmail string) (*http.Client, error) {
	const op = "oidc.defaultGoogleHTTPClient"
	conf, err := google.JWTConfigFromJSON([]byte(serviceAccountJSON), googleDirectoryScope)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op, errors.WithMsg("failed to parse Google service account JSON"))
	}
	// Domain-wide delegation: impersonate the Workspace admin to call the
	// Directory API on behalf of any user in the domain.
	conf.Subject = adminEmail
	return conf.Client(ctx), nil
}

// fetchGoogleWorkspaceGroups calls the Google Admin SDK Directory API to
// return the email addresses of all Google Workspace groups that userEmail
// belongs to.
//
// serviceAccountJSON is the plaintext content of a Google service account JSON
// key file whose associated service account has been granted domain-wide
// delegation with the scope https://www.googleapis.com/auth/admin.directory.group.readonly.
//
// adminEmail is a Google Workspace admin email address that Boundary
// impersonates when calling the API.
//
// On error the function returns a non-nil error; callers should log the error
// and continue authentication without group claims rather than blocking login.
func fetchGoogleWorkspaceGroups(ctx context.Context, serviceAccountJSON, adminEmail, userEmail string) ([]string, error) {
	const op = "oidc.fetchGoogleWorkspaceGroups"
	if serviceAccountJSON == "" {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing service account JSON")
	}
	if adminEmail == "" {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing admin email")
	}
	if userEmail == "" {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing user email")
	}

	httpClient, err := googleHTTPClientFunc(ctx, serviceAccountJSON, adminEmail)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}

	return listGoogleGroups(ctx, httpClient, userEmail)
}

// listGoogleGroups pages through the Admin SDK Groups.list endpoint and
// returns all group email addresses the user belongs to. It is separated from
// fetchGoogleWorkspaceGroups so tests can inject a pre-authenticated client
// directly without going through googleHTTPClientFunc.
func listGoogleGroups(ctx context.Context, httpClient *http.Client, userEmail string) ([]string, error) {
	const op = "oidc.listGoogleGroups"
	var allGroups []string
	pageToken := ""

	for {
		reqURL := fmt.Sprintf("%s?userKey=%s&maxResults=200",
			googleDirectoryGroupsURL, url.QueryEscape(userEmail))
		if pageToken != "" {
			reqURL += "&pageToken=" + url.QueryEscape(pageToken)
		}

		req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
		if err != nil {
			return nil, errors.Wrap(ctx, err, op, errors.WithMsg("failed to build Directory API request"))
		}

		resp, err := httpClient.Do(req)
		if err != nil {
			return nil, errors.Wrap(ctx, err, op, errors.WithMsg("Directory API request failed"))
		}
		body, readErr := io.ReadAll(resp.Body)
		resp.Body.Close()
		if readErr != nil {
			return nil, errors.Wrap(ctx, readErr, op, errors.WithMsg("failed to read Directory API response body"))
		}

		if resp.StatusCode != http.StatusOK {
			return nil, errors.New(ctx, errors.Unknown, op,
				fmt.Sprintf("Directory API returned HTTP %d: %s", resp.StatusCode, body))
		}

		var result googleDirectoryGroupsResponse
		if err := json.Unmarshal(body, &result); err != nil {
			return nil, errors.Wrap(ctx, err, op, errors.WithMsg("failed to decode Directory API response"))
		}

		for _, g := range result.Groups {
			if g.Email != "" {
				allGroups = append(allGroups, g.Email)
			}
		}

		if result.NextPageToken == "" {
			break
		}
		pageToken = result.NextPageToken
	}

	return allGroups, nil
}
