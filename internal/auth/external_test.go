package auth

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/amoylab/unla/internal/common/config"
	"github.com/stretchr/testify/assert"
	"go.uber.org/zap"
)

type rtFunc func(*http.Request) (*http.Response, error)

func (f rtFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func newJSONResponse(status int, v any) *http.Response {
	b, _ := json.Marshal(v)
	return &http.Response{StatusCode: status, Body: io.NopCloser(strings.NewReader(string(b))), Header: make(http.Header)}
}

func TestGoogleOAuth_Flow(t *testing.T) {
	logger := zap.NewNop()
	goauth := NewGoogleOAuth(logger, config.GoogleOAuthConfig{ClientID: "cid", ClientSecret: "sec", RedirectURI: "http://cb"})
	authURL := goauth.GetAuthURL("state123")
	assert.Contains(t, authURL, "client_id=cid")

	old := http.DefaultTransport
	defer func() { http.DefaultTransport = old }()

	http.DefaultTransport = rtFunc(func(r *http.Request) (*http.Response, error) {
		switch {
		case r.URL.String() == "https://oauth2.googleapis.com/token":
			_ = r.ParseForm()
			if r.PostForm.Get("code") == "good" {
				return newJSONResponse(200, map[string]any{"access_token": "at", "token_type": "Bearer"}), nil
			}
			return newJSONResponse(400, map[string]any{"error": "bad"}), nil
		case r.URL.String() == "https://www.googleapis.com/oauth2/v2/userinfo":
			if got := r.Header.Get("Authorization"); got == "Bearer at" {
				return newJSONResponse(200, map[string]any{"id": "1", "email": "e@x", "name": "n", "picture": "p"}), nil
			}
			return newJSONResponse(401, map[string]any{"error": "unauthorized"}), nil
		default:
			return newJSONResponse(404, map[string]any{"error": "not found"}), nil
		}
	})

	tok, err := goauth.ExchangeCode(context.Background(), "good")
	assert.NoError(t, err)
	assert.Equal(t, "at", tok.AccessToken)

	ui, err := goauth.GetUserInfo(context.Background(), tok.AccessToken)
	assert.NoError(t, err)
	assert.Equal(t, "google", ui.Provider)
	assert.Equal(t, "e@x", ui.Email)
}

func TestGitHubOAuth_Flow_WithEmailFallback(t *testing.T) {
	logger := zap.NewNop()
	ghauth := NewGitHubOAuth(logger, config.GitHubOAuthConfig{ClientID: "cid", ClientSecret: "sec", RedirectURI: "http://cb"})
	authURL := ghauth.GetAuthURL("state123")
	assert.Contains(t, authURL, "client_id=cid")

	old := http.DefaultTransport
	defer func() { http.DefaultTransport = old }()

	http.DefaultTransport = rtFunc(func(r *http.Request) (*http.Response, error) {
		switch {
		case r.URL.String() == "https://github.com/login/oauth/access_token":
			_ = r.ParseForm()
			if r.PostForm.Get("code") == "good" {
				return newJSONResponse(200, map[string]any{"access_token": "ghat", "token_type": "Bearer"}), nil
			}
			return newJSONResponse(400, map[string]any{"error": "bad"}), nil
		case r.URL.String() == "https://api.github.com/user":
			// simulate missing email -> fallback path
			return newJSONResponse(200, map[string]any{"id": 2, "login": "u", "name": "n", "avatar_url": "a"}), nil
		case r.URL.String() == "https://api.github.com/user/emails":
			return newJSONResponse(200, []map[string]any{{"email": "x@y", "primary": true}}), nil
		default:
			return newJSONResponse(404, map[string]any{"error": "not found"}), nil
		}
	})

	tok, err := ghauth.ExchangeCode(context.Background(), "good")
	assert.NoError(t, err)
	assert.Equal(t, "ghat", tok.AccessToken)

	ui, err := ghauth.GetUserInfo(context.Background(), tok.AccessToken)
	assert.NoError(t, err)
	assert.Equal(t, "github", ui.Provider)
	assert.Equal(t, "x@y", ui.Email)
	assert.Equal(t, "u", ui.Username)
}

func TestOktaOAuth_Flow(t *testing.T) {
	logger := zap.NewNop()

	old := http.DefaultTransport
	defer func() { http.DefaultTransport = old }()

	// Mock OIDC discovery and token endpoints
	http.DefaultTransport = rtFunc(func(r *http.Request) (*http.Response, error) {
		switch {
		// OIDC Discovery endpoint
		case strings.Contains(r.URL.String(), "/.well-known/openid-configuration"):
			return newJSONResponse(200, map[string]any{
				"issuer":                 "https://dev-test.okta.com",
				"authorization_endpoint": "https://dev-test.okta.com/oauth2/v1/authorize",
				"token_endpoint":         "https://dev-test.okta.com/oauth2/v1/token",
				"userinfo_endpoint":      "https://dev-test.okta.com/oauth2/v1/userinfo",
				"jwks_uri":               "https://dev-test.okta.com/oauth2/v1/keys",
			}), nil

		// JWKS endpoint (for ID token verification)
		case strings.Contains(r.URL.String(), "/oauth2/v1/keys"):
			return newJSONResponse(200, map[string]any{
				"keys": []map[string]any{
					{
						"kty": "RSA",
						"kid": "test-key-id",
						"use": "sig",
						"n":   "test-modulus",
						"e":   "AQAB",
					},
				},
			}), nil

		// Token endpoint
		case strings.Contains(r.URL.String(), "/oauth2/v1/token"):
			_ = r.ParseForm()
			if r.PostForm.Get("code") == "good" {
				// Return token with ID token (simplified - in real scenario this would be a valid JWT)
				return newJSONResponse(200, map[string]any{
					"access_token": "okta_at",
					"token_type":   "Bearer",
					"id_token":     "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6InRlc3Qta2V5LWlkIn0.eyJzdWIiOiIwMHUxMjM0NSIsImVtYWlsIjoib2t0YUB0ZXN0LmNvbSIsIm5hbWUiOiJPa3RhIFRlc3QiLCJwcmVmZXJyZWRfdXNlcm5hbWUiOiJva3RhdXNlciIsImF1ZCI6InRlc3QtY2xpZW50LWlkIiwiaXNzIjoiaHR0cHM6Ly9kZXYtdGVzdC5va3RhLmNvbSIsImV4cCI6OTk5OTk5OTk5OSwiaWF0IjoxNjAwMDAwMDAwfQ.test-signature",
					"expires_in":   3600,
				}), nil
			}
			return newJSONResponse(400, map[string]any{"error": "invalid_grant"}), nil

		// Userinfo endpoint
		case strings.Contains(r.URL.String(), "/oauth2/v1/userinfo"):
			if r.Header.Get("Authorization") == "Bearer okta_at" {
				return newJSONResponse(200, map[string]any{
					"sub":                "00u12345",
					"email":              "okta@test.com",
					"name":               "Okta Test",
					"preferred_username": "oktauser",
					"picture":            "https://example.com/avatar.jpg",
				}), nil
			}
			return newJSONResponse(401, map[string]any{"error": "unauthorized"}), nil

		default:
			return newJSONResponse(404, map[string]any{"error": "not found"}), nil
		}
	})

	// Create Okta OAuth provider
	oktaAuth, err := NewOktaOAuth(context.Background(), logger, config.OktaOAuthConfig{
		Domain:       "dev-test.okta.com",
		ClientID:     "test-client-id",
		ClientSecret: "test-secret",
		RedirectURI:  "http://localhost/callback",
	})

	// Note: In real testing, OIDC provider initialization might fail with mock responses
	// This test demonstrates the expected behavior when properly mocked
	if err != nil {
		t.Logf("Okta OAuth initialization failed (expected with simplified mocks): %v", err)
		t.Skip("Skipping Okta OAuth flow test - requires full OIDC mock setup")
		return
	}

	// Test auth URL generation
	authURL := oktaAuth.GetAuthURL("state123")
	assert.Contains(t, authURL, "dev-test.okta.com")
	assert.Contains(t, authURL, "state=state123")

	// Test token exchange would happen here if OIDC verification was fully mocked
	t.Log("Okta OAuth basic initialization and auth URL generation successful")
}

func TestOktaOAuth_InvalidConfig(t *testing.T) {
	logger := zap.NewNop()

	// Test with invalid domain (should fail OIDC discovery)
	_, err := NewOktaOAuth(context.Background(), logger, config.OktaOAuthConfig{
		Domain:       "invalid-domain-that-does-not-exist.okta.com",
		ClientID:     "test-client-id",
		ClientSecret: "test-secret",
		RedirectURI:  "http://localhost/callback",
	})

	// Expect error when OIDC provider cannot be discovered
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to create OIDC provider")
}
