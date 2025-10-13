package handler

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/amoylab/unla/internal/apiserver/database"
	"github.com/amoylab/unla/internal/auth"
	"github.com/amoylab/unla/internal/auth/jwt"
	"github.com/amoylab/unla/internal/i18n"
	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
	"golang.org/x/crypto/bcrypt"
)

// OAuthHandler handles external OAuth authentication
type OAuthHandler struct {
	db         database.Database
	jwtService *jwt.Service
	auth       auth.Auth
	logger     *zap.Logger
	states     map[string]time.Time // In-memory state storage for demo
}

// NewOAuthHandler creates a new OAuth handler
func NewOAuthHandler(db database.Database, jwtService *jwt.Service, authService auth.Auth, logger *zap.Logger) *OAuthHandler {
	return &OAuthHandler{
		db:         db,
		jwtService: jwtService,
		auth:       authService,
		logger:     logger.Named("apiserver.handler.oauth"),
		states:     make(map[string]time.Time),
	}
}

// getFrontendURL extracts the frontend URL from the request
func (h *OAuthHandler) getFrontendURL(c *gin.Context) string {
	// Try to get origin from request headers (most reliable for OAuth callbacks)
	if origin := c.GetHeader("Origin"); origin != "" {
		return origin
	}

	// Try referer as fallback
	if referer := c.GetHeader("Referer"); referer != "" {
		// Parse referer to extract base URL
		if idx := strings.Index(referer, "/login"); idx > 0 {
			return referer[:idx]
		}
		// Extract scheme://host from referer
		if strings.HasPrefix(referer, "http://") || strings.HasPrefix(referer, "https://") {
			parts := strings.SplitN(referer, "/", 4)
			if len(parts) >= 3 {
				return strings.Join(parts[:3], "/")
			}
		}
	}

	// Construct from request host
	scheme := "http"
	if c.Request.TLS != nil || c.GetHeader("X-Forwarded-Proto") == "https" {
		scheme = "https"
	}
	host := c.Request.Host
	if host != "" {
		// Check if it's a backend port, likely need to map to frontend
		if strings.Contains(host, ":5234") {
			host = strings.Replace(host, ":5234", ":5173", 1)
		}
		return fmt.Sprintf("%s://%s", scheme, host)
	}

	// Last resort fallback
	return "http://localhost:5173"
}

// GoogleLogin initiates Google OAuth login
func (h *OAuthHandler) GoogleLogin(c *gin.Context) {
	if !h.auth.IsGoogleOAuthEnabled() {
		h.logger.Warn("Google OAuth not enabled")
		i18n.RespondWithError(c, i18n.ErrBadRequest.WithParam("Reason", "Google OAuth not enabled"))
		return
	}

	state := h.generateState()
	h.states[state] = time.Now().Add(10 * time.Minute) // 10 minutes expiry

	googleOAuth := h.auth.GetGoogleOAuth()
	authURL := googleOAuth.GetAuthURL(state)

	h.logger.Info("initiating Google OAuth login",
		zap.String("state", state),
		zap.String("remote_addr", c.ClientIP()))

	c.JSON(http.StatusOK, gin.H{
		"auth_url": authURL,
		"state":    state,
	})
}

// GoogleCallback handles Google OAuth callback
func (h *OAuthHandler) GoogleCallback(c *gin.Context) {
	frontendBase := h.getFrontendURL(c)

	if !h.auth.IsGoogleOAuthEnabled() {
		h.logger.Warn("Google OAuth not enabled")
		c.Redirect(http.StatusTemporaryRedirect, fmt.Sprintf("%s/login?oauth=error&message=oauth_not_enabled", frontendBase))
		return
	}

	code := c.Query("code")
	state := c.Query("state")

	if code == "" || state == "" {
		h.logger.Warn("missing code or state in Google callback",
			zap.String("remote_addr", c.ClientIP()))
		c.Redirect(http.StatusTemporaryRedirect, fmt.Sprintf("%s/login?oauth=error&message=missing_parameters", frontendBase))
		return
	}

	// Validate state
	if !h.validateState(state) {
		h.logger.Warn("invalid state in Google callback",
			zap.String("state", state),
			zap.String("remote_addr", c.ClientIP()))
		c.Redirect(http.StatusTemporaryRedirect, fmt.Sprintf("%s/login?oauth=error&message=invalid_state", frontendBase))
		return
	}

	h.logger.Info("processing Google OAuth callback",
		zap.String("state", state),
		zap.String("remote_addr", c.ClientIP()))

	googleOAuth := h.auth.GetGoogleOAuth()

	// Exchange code for token
	tokenResp, err := googleOAuth.ExchangeCode(c.Request.Context(), code)
	if err != nil {
		h.logger.Error("failed to exchange Google code for token",
			zap.Error(err),
			zap.String("remote_addr", c.ClientIP()))
		c.Redirect(http.StatusTemporaryRedirect, fmt.Sprintf("%s/login?oauth=error&message=token_exchange_failed", frontendBase))
		return
	}

	// Get user info
	userInfo, err := googleOAuth.GetUserInfo(c.Request.Context(), tokenResp.AccessToken)
	if err != nil {
		h.logger.Error("failed to get Google user info",
			zap.Error(err),
			zap.String("remote_addr", c.ClientIP()))
		c.Redirect(http.StatusTemporaryRedirect, fmt.Sprintf("%s/login?oauth=error&message=user_info_failed", frontendBase))
		return
	}

	// Handle user authentication
	token, user, err := h.handleOAuthUser(c, userInfo)
	if err != nil {
		h.logger.Error("failed to handle Google OAuth user",
			zap.Error(err),
			zap.String("email", userInfo.Email),
			zap.String("remote_addr", c.ClientIP()))
		c.Redirect(http.StatusTemporaryRedirect, fmt.Sprintf("%s/login?oauth=error&message=user_creation_failed", frontendBase))
		return
	}

	h.logger.Info("Google OAuth login successful",
		zap.String("email", userInfo.Email),
		zap.String("username", user.Username),
		zap.String("remote_addr", c.ClientIP()))

	// Redirect to frontend with token in URL fragment (for security)
	frontendURL := fmt.Sprintf("%s/login?oauth=success#token=%s&user_id=%d&username=%s&role=%s",
		frontendBase, token, user.ID, user.Username, user.Role)
	c.Redirect(http.StatusTemporaryRedirect, frontendURL)
}

// GitHubLogin initiates GitHub OAuth login
func (h *OAuthHandler) GitHubLogin(c *gin.Context) {
	if !h.auth.IsGitHubOAuthEnabled() {
		h.logger.Warn("GitHub OAuth not enabled")
		i18n.RespondWithError(c, i18n.ErrBadRequest.WithParam("Reason", "GitHub OAuth not enabled"))
		return
	}

	state := h.generateState()
	h.states[state] = time.Now().Add(10 * time.Minute) // 10 minutes expiry

	githubOAuth := h.auth.GetGitHubOAuth()
	authURL := githubOAuth.GetAuthURL(state)

	h.logger.Info("initiating GitHub OAuth login",
		zap.String("state", state),
		zap.String("remote_addr", c.ClientIP()))

	c.JSON(http.StatusOK, gin.H{
		"auth_url": authURL,
		"state":    state,
	})
}

// GitHubCallback handles GitHub OAuth callback
func (h *OAuthHandler) GitHubCallback(c *gin.Context) {
	frontendBase := h.getFrontendURL(c)

	if !h.auth.IsGitHubOAuthEnabled() {
		h.logger.Warn("GitHub OAuth not enabled")
		c.Redirect(http.StatusTemporaryRedirect, fmt.Sprintf("%s/login?oauth=error&message=oauth_not_enabled", frontendBase))
		return
	}

	code := c.Query("code")
	state := c.Query("state")

	if code == "" || state == "" {
		h.logger.Warn("missing code or state in GitHub callback",
			zap.String("remote_addr", c.ClientIP()))
		c.Redirect(http.StatusTemporaryRedirect, fmt.Sprintf("%s/login?oauth=error&message=missing_parameters", frontendBase))
		return
	}

	// Validate state
	if !h.validateState(state) {
		h.logger.Warn("invalid state in GitHub callback",
			zap.String("state", state),
			zap.String("remote_addr", c.ClientIP()))
		c.Redirect(http.StatusTemporaryRedirect, fmt.Sprintf("%s/login?oauth=error&message=invalid_state", frontendBase))
		return
	}

	h.logger.Info("processing GitHub OAuth callback",
		zap.String("state", state),
		zap.String("remote_addr", c.ClientIP()))

	githubOAuth := h.auth.GetGitHubOAuth()

	// Exchange code for token
	tokenResp, err := githubOAuth.ExchangeCode(c.Request.Context(), code)
	if err != nil {
		h.logger.Error("failed to exchange GitHub code for token",
			zap.Error(err),
			zap.String("remote_addr", c.ClientIP()))
		c.Redirect(http.StatusTemporaryRedirect, fmt.Sprintf("%s/login?oauth=error&message=token_exchange_failed", frontendBase))
		return
	}

	// Get user info
	userInfo, err := githubOAuth.GetUserInfo(c.Request.Context(), tokenResp.AccessToken)
	if err != nil {
		h.logger.Error("failed to get GitHub user info",
			zap.Error(err),
			zap.String("remote_addr", c.ClientIP()))
		c.Redirect(http.StatusTemporaryRedirect, fmt.Sprintf("%s/login?oauth=error&message=user_info_failed", frontendBase))
		return
	}

	// Handle user authentication
	token, user, err := h.handleOAuthUser(c, userInfo)
	if err != nil {
		h.logger.Error("failed to handle GitHub OAuth user",
			zap.Error(err),
			zap.String("email", userInfo.Email),
			zap.String("remote_addr", c.ClientIP()))
		c.Redirect(http.StatusTemporaryRedirect, fmt.Sprintf("%s/login?oauth=error&message=user_creation_failed", frontendBase))
		return
	}

	h.logger.Info("GitHub OAuth login successful",
		zap.String("email", userInfo.Email),
		zap.String("username", user.Username),
		zap.String("remote_addr", c.ClientIP()))

	// Redirect to frontend with token in URL fragment (for security)
	frontendURL := fmt.Sprintf("%s/login?oauth=success#token=%s&user_id=%d&username=%s&role=%s",
		frontendBase, token, user.ID, user.Username, user.Role)
	c.Redirect(http.StatusTemporaryRedirect, frontendURL)
}

// OktaLogin initiates Okta OIDC login
func (h *OAuthHandler) OktaLogin(c *gin.Context) {
	if !h.auth.IsOktaOAuthEnabled() {
		h.logger.Warn("Okta OAuth not enabled")
		i18n.RespondWithError(c, i18n.ErrBadRequest.WithParam("Reason", "Okta OAuth not enabled"))
		return
	}

	state := h.generateState()
	h.states[state] = time.Now().Add(10 * time.Minute) // 10 minutes expiry

	oktaOAuth := h.auth.GetOktaOAuth()
	authURL := oktaOAuth.GetAuthURL(state)

	h.logger.Info("initiating Okta OIDC login",
		zap.String("state", state),
		zap.String("remote_addr", c.ClientIP()))

	c.JSON(http.StatusOK, gin.H{
		"auth_url": authURL,
		"state":    state,
	})
}

// OktaCallback handles Okta OIDC callback
func (h *OAuthHandler) OktaCallback(c *gin.Context) {
	frontendBase := h.getFrontendURL(c)

	if !h.auth.IsOktaOAuthEnabled() {
		h.logger.Warn("Okta OAuth not enabled")
		c.Redirect(http.StatusTemporaryRedirect, fmt.Sprintf("%s/login?oauth=error&message=oauth_not_enabled", frontendBase))
		return
	}

	code := c.Query("code")
	state := c.Query("state")

	if code == "" || state == "" {
		h.logger.Warn("missing code or state in Okta callback",
			zap.String("remote_addr", c.ClientIP()))
		c.Redirect(http.StatusTemporaryRedirect, fmt.Sprintf("%s/login?oauth=error&message=missing_parameters", frontendBase))
		return
	}

	// Validate state
	if !h.validateState(state) {
		h.logger.Warn("invalid state in Okta callback",
			zap.String("state", state),
			zap.String("remote_addr", c.ClientIP()))
		c.Redirect(http.StatusTemporaryRedirect, fmt.Sprintf("%s/login?oauth=error&message=invalid_state", frontendBase))
		return
	}

	h.logger.Info("processing Okta OIDC callback",
		zap.String("state", state),
		zap.String("remote_addr", c.ClientIP()))

	oktaOAuth := h.auth.GetOktaOAuth()

	// Exchange code for token
	tokenResp, err := oktaOAuth.ExchangeCode(c.Request.Context(), code)
	if err != nil {
		h.logger.Error("failed to exchange Okta code for token",
			zap.Error(err),
			zap.String("remote_addr", c.ClientIP()))
		c.Redirect(http.StatusTemporaryRedirect, fmt.Sprintf("%s/login?oauth=error&message=token_exchange_failed", frontendBase))
		return
	}

	// Get user info
	userInfo, err := oktaOAuth.GetUserInfo(c.Request.Context(), tokenResp.AccessToken)
	if err != nil {
		h.logger.Error("failed to get Okta user info",
			zap.Error(err),
			zap.String("remote_addr", c.ClientIP()))
		c.Redirect(http.StatusTemporaryRedirect, fmt.Sprintf("%s/login?oauth=error&message=user_info_failed", frontendBase))
		return
	}

	// Handle user authentication
	token, user, err := h.handleOAuthUser(c, userInfo)
	if err != nil {
		h.logger.Error("failed to handle Okta OAuth user",
			zap.Error(err),
			zap.String("email", userInfo.Email),
			zap.String("remote_addr", c.ClientIP()))
		c.Redirect(http.StatusTemporaryRedirect, fmt.Sprintf("%s/login?oauth=error&message=user_creation_failed", frontendBase))
		return
	}

	h.logger.Info("Okta OIDC login successful",
		zap.String("email", userInfo.Email),
		zap.String("username", user.Username),
		zap.String("remote_addr", c.ClientIP()))

	// Redirect to frontend with token in URL fragment (for security)
	frontendURL := fmt.Sprintf("%s/login?oauth=success#token=%s&user_id=%d&username=%s&role=%s",
		frontendBase, token, user.ID, user.Username, user.Role)
	c.Redirect(http.StatusTemporaryRedirect, frontendURL)
}

// GetOAuthProviders returns available OAuth providers
func (h *OAuthHandler) GetOAuthProviders(c *gin.Context) {
	providers := gin.H{}

	if h.auth.IsGoogleOAuthEnabled() {
		providers["google"] = gin.H{
			"enabled": true,
			"name":    "Google",
		}
	}

	if h.auth.IsGitHubOAuthEnabled() {
		providers["github"] = gin.H{
			"enabled": true,
			"name":    "GitHub",
		}
	}

	if h.auth.IsOktaOAuthEnabled() {
		providers["okta"] = gin.H{
			"enabled": true,
			"name":    "Okta",
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"providers": providers,
	})
}

// Helper methods

func (h *OAuthHandler) generateState() string {
	b := make([]byte, 32)
	rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

func (h *OAuthHandler) generateTenantName(email string) (string, error) {
	// Extract username part from email
	parts := strings.Split(email, "@")
	if len(parts) != 2 {
		return "", fmt.Errorf("invalid email format")
	}
	username := parts[0]

	// Generate 4 random characters
	b := make([]byte, 3) // 3 bytes = 4 base64 characters
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("failed to generate random suffix: %w", err)
	}
	suffix := base64.RawURLEncoding.EncodeToString(b)[:4]

	return fmt.Sprintf("%s_%s", username, suffix), nil
}

func (h *OAuthHandler) validateState(state string) bool {
	expiry, exists := h.states[state]
	if !exists {
		return false
	}

	if time.Now().After(expiry) {
		delete(h.states, state)
		return false
	}

	delete(h.states, state)
	return true
}

func (h *OAuthHandler) handleOAuthUser(c *gin.Context, userInfo *auth.ExternalUserInfo) (string, *database.User, error) {
	// Try to find existing user by email
	existingUser, err := h.db.GetUserByUsername(c.Request.Context(), userInfo.Email)
	if err == nil && existingUser != nil {
		// User exists, check if active
		if !existingUser.IsActive {
			return "", nil, fmt.Errorf("user account is disabled")
		}

		// Generate token for existing user
		token, err := h.jwtService.GenerateToken(existingUser.ID, existingUser.Username, string(existingUser.Role))
		if err != nil {
			return "", nil, fmt.Errorf("failed to generate token: %w", err)
		}

		return token, existingUser, nil
	}

	// User doesn't exist, create new user
	username := userInfo.Email
	if userInfo.Username != "" {
		username = userInfo.Username
	}

	// Generate a random password for OAuth users (they won't use it)
	randomPassword := h.generateState()
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(randomPassword), bcrypt.DefaultCost)
	if err != nil {
		return "", nil, fmt.Errorf("failed to hash password: %w", err)
	}

	newUser := &database.User{
		Username:  username,
		Password:  string(hashedPassword),
		Role:      database.RoleNormal, // OAuth users are normal users by default
		IsActive:  true,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	// Use database transaction to ensure atomicity
	err = h.db.Transaction(c.Request.Context(), func(ctx context.Context) error {
		// Create user
		if err := h.db.CreateUser(ctx, newUser); err != nil {
			return fmt.Errorf("failed to create user: %w", err)
		}

		// Generate tenant name
		tenantName, err := h.generateTenantName(userInfo.Email)
		if err != nil {
			return fmt.Errorf("failed to generate tenant name: %w", err)
		}

		// Create default tenant for the user
		newTenant := &database.Tenant{
			Name:        tenantName,
			Prefix:      "/" + tenantName,
			Description: fmt.Sprintf("Default tenant for %s", userInfo.Email),
			IsActive:    true,
			CreatedAt:   time.Now(),
			UpdatedAt:   time.Now(),
		}

		if err := h.db.CreateTenant(ctx, newTenant); err != nil {
			return fmt.Errorf("failed to create tenant: %w", err)
		}

		// Associate user with tenant
		if err := h.db.AddUserToTenant(ctx, newUser.ID, newTenant.ID); err != nil {
			return fmt.Errorf("failed to associate user with tenant: %w", err)
		}

		h.logger.Info("created default tenant for OAuth user",
			zap.String("tenant_name", tenantName),
			zap.String("user_email", userInfo.Email),
			zap.Uint("user_id", newUser.ID),
			zap.Uint("tenant_id", newTenant.ID))

		return nil
	})

	if err != nil {
		return "", nil, err
	}

	// Generate token for new user
	token, err := h.jwtService.GenerateToken(newUser.ID, newUser.Username, string(newUser.Role))
	if err != nil {
		return "", nil, fmt.Errorf("failed to generate token: %w", err)
	}

	h.logger.Info("created new OAuth user",
		zap.String("username", username),
		zap.String("email", userInfo.Email),
		zap.String("provider", userInfo.Provider),
		zap.Uint("user_id", newUser.ID))

	return token, newUser, nil
}
