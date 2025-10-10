package auth

import (
	"context"
	"net/http"

	"go.uber.org/zap"

	"github.com/amoylab/unla/internal/common/config"
	"github.com/amoylab/unla/internal/common/errorx"
)

// Auth defines the authentication oauth interface
type Auth interface {
	OAuth2
	IsOAuth2Enabled() bool
	GetOAuth2CORS() *config.CORSConfig
	GetGoogleOAuth() ExternalOAuth
	GetGitHubOAuth() ExternalOAuth
	GetOktaOAuth() ExternalOAuth
	IsGoogleOAuthEnabled() bool
	IsGitHubOAuthEnabled() bool
	IsOktaOAuthEnabled() bool
}

type OAuth2 interface {
	// ServerMetadata returns the server metadata
	ServerMetadata(r *http.Request) map[string]interface{}

	// Authorize handles the authorization request
	Authorize(ctx context.Context, r *http.Request) (*AuthorizationResponse, error)

	// Token handles the token request
	Token(ctx context.Context, r *http.Request) (*TokenResponse, error)

	// Register handles client registration
	Register(ctx context.Context, r *http.Request) (*ClientRegistrationResponse, error)

	// Revoke handles token revocation
	Revoke(ctx context.Context, r *http.Request) error

	// ValidateToken validates an access token
	ValidateToken(ctx context.Context, token string) error
}

// AuthorizationResponse represents the response from the authorization endpoint
type AuthorizationResponse struct {
	Code  string
	State string
}

// TokenResponse represents the response from the token endpoint
type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int64  `json:"expires_in,omitempty"`
	RefreshToken string `json:"refresh_token,omitempty"`
	Scope        string `json:"scope,omitempty"`
}

// ClientRegistrationResponse represents the response from the client registration endpoint
type ClientRegistrationResponse struct {
	ClientID                string   `json:"client_id"`
	ClientSecret            string   `json:"client_secret,omitempty"`
	RedirectURIs            []string `json:"redirect_uris"`
	GrantTypes              []string `json:"grant_types"`
	ResponseTypes           []string `json:"response_types"`
	TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method"`
	Scope                   string   `json:"scope"`
}

type auth struct {
	OAuth2
	cfg         config.AuthConfig
	googleOAuth *GoogleOAuth
	githubOAuth *GitHubOAuth
	oktaOAuth   *OktaOAuth
}

// NewAuth creates a new auth oauth based on the configuration
func NewAuth(logger *zap.Logger, cfg config.AuthConfig) (Auth, error) {
	ctx := context.Background()

	a := &auth{
		cfg: cfg,
	}
	if cfg.OAuth2 != nil {
		oauth2, err := newOAuth(logger, *cfg.OAuth2)
		if err != nil {
			return nil, err
		}
		a.OAuth2 = oauth2
	}
	if cfg.Google != nil {
		a.googleOAuth = NewGoogleOAuth(logger, *cfg.Google)
	}
	if cfg.GitHub != nil {
		a.githubOAuth = NewGitHubOAuth(logger, *cfg.GitHub)
	}
	if cfg.Okta != nil {
		oktaOAuth, err := NewOktaOAuth(ctx, logger, *cfg.Okta)
		if err != nil {
			logger.Warn("Failed to initialize Okta OAuth", zap.Error(err))
		} else {
			a.oktaOAuth = oktaOAuth
		}
	}
	return a, nil
}

// IsOAuth2Enabled returns true if OAuth2 is enabled
func (a *auth) IsOAuth2Enabled() bool {
	return a.cfg.OAuth2 != nil
}

// GetOAuth2CORS returns the OAuth2 CORS configuration
func (a *auth) GetOAuth2CORS() *config.CORSConfig {
	return a.cfg.CORS
}

// ValidateToken validates an access token
func (a *auth) ValidateToken(ctx context.Context, token string) error {
	if a.OAuth2 == nil {
		return errorx.ErrOAuth2NotEnabled
	}

	return a.OAuth2.ValidateToken(ctx, token)
}

// GetGoogleOAuth returns the Google OAuth provider
func (a *auth) GetGoogleOAuth() ExternalOAuth {
	return a.googleOAuth
}

// GetGitHubOAuth returns the GitHub OAuth provider
func (a *auth) GetGitHubOAuth() ExternalOAuth {
	return a.githubOAuth
}

// IsGoogleOAuthEnabled returns true if Google OAuth is enabled
func (a *auth) IsGoogleOAuthEnabled() bool {
	return a.cfg.Google != nil && a.googleOAuth != nil &&
		a.cfg.Google.ClientID != "" && a.cfg.Google.ClientSecret != ""
}

// IsGitHubOAuthEnabled returns true if GitHub OAuth is enabled
func (a *auth) IsGitHubOAuthEnabled() bool {
	return a.cfg.GitHub != nil && a.githubOAuth != nil &&
		a.cfg.GitHub.ClientID != "" && a.cfg.GitHub.ClientSecret != ""
}

// GetOktaOAuth returns the Okta OAuth provider
func (a *auth) GetOktaOAuth() ExternalOAuth {
	return a.oktaOAuth
}

// IsOktaOAuthEnabled returns true if Okta OAuth is enabled
func (a *auth) IsOktaOAuthEnabled() bool {
	return a.cfg.Okta != nil && a.oktaOAuth != nil &&
		a.cfg.Okta.ClientID != "" && a.cfg.Okta.ClientSecret != ""
}
