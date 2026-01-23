package gitsync

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/clientcredentials"
)

// Credential types that external users can return from Secret.Typed() for git authentication.

// SecretBasicAuth represents HTTP basic authentication credentials.
type SecretBasicAuth struct {
	Username string   // Username for basic auth
	Password string   // Password for basic auth
	Headers  []string // Optional additional HTTP headers (format: "Header-Name: value")
}

// SecretGitHubApp represents GitHub App authentication credentials.
// GitHub Apps use short-lived installation tokens for enhanced security.
type SecretGitHubApp struct {
	IntegrationID  int64  // GitHub App integration ID
	InstallationID int64  // GitHub App installation ID
	PrivateKey     string // Path to private key file (PEM format)
}

// SecretSSHKey represents SSH key authentication credentials.
type SecretSSHKey struct {
	Key          string   // SSH private key (PEM format)
	Passphrase   string   // Optional passphrase for encrypted keys
	Fingerprints []string // Required SSH key fingerprints for host validation (SHA256 format)
}

// TokenSecret is the shared interface for secrets that can provide a bearer token.
// This is used for token-based authentication in git operations.
type TokenSecret interface {
	Token(context.Context) (string, error)
}

// SecretOIDCClientCredentials represents OIDC Client Credentials flow authentication.
// Supports both explicit token endpoint and automatic discovery via issuer.
type SecretOIDCClientCredentials struct {
	Issuer       string   // OIDC issuer URL for automatic discovery (required if TokenURL not provided)
	TokenURL     string   // Explicit token endpoint URL (optional if Issuer provided)
	ClientID     string   // OAuth2 client ID (required)
	ClientSecret string   // OAuth2 client secret (required)
	Scopes       []string // Optional OAuth2 scopes to request
}

// validate performs upfront validation of the OIDC credentials configuration.
func (s *SecretOIDCClientCredentials) validate() error {
	if s.ClientID == "" {
		return errors.New("client_id is required")
	}
	if s.ClientSecret == "" {
		return errors.New("client_secret is required")
	}
	if s.Issuer == "" && s.TokenURL == "" {
		return errors.New("either issuer or token_endpoint must be provided")
	}
	return nil
}

// getClientCredentialsConfig creates and returns a properly configured clientcredentials.Config.
func (s *SecretOIDCClientCredentials) getClientCredentialsConfig(ctx context.Context) (*clientcredentials.Config, error) {
	if err := s.validate(); err != nil {
		return nil, fmt.Errorf("invalid configuration: %w", err)
	}

	tokenURL := s.TokenURL
	if tokenURL == "" && s.Issuer != "" {
		// Discover token endpoint from issuer's well-known configuration
		wellKnown := s.Issuer + "/.well-known/openid-configuration"
		req, err := oauth2.NewClient(ctx, nil).Get(wellKnown)
		if err != nil {
			return nil, fmt.Errorf("failed to fetch OIDC discovery document from %s: %w", wellKnown, err)
		}
		defer req.Body.Close()

		var discovery struct {
			TokenEndpoint string `json:"token_endpoint"`
		}
		if err := json.NewDecoder(req.Body).Decode(&discovery); err != nil {
			return nil, fmt.Errorf("failed to decode OIDC discovery document: %w", err)
		}
		tokenURL = discovery.TokenEndpoint
	}

	return &clientcredentials.Config{
		ClientID:     s.ClientID,
		ClientSecret: s.ClientSecret,
		TokenURL:     tokenURL,
		Scopes:       s.Scopes,
	}, nil
}

// Token obtains and returns an access token using OIDC Client Credentials flow.
func (s *SecretOIDCClientCredentials) Token(ctx context.Context) (string, error) {
	config, err := s.getClientCredentialsConfig(ctx)
	if err != nil {
		return "", fmt.Errorf("failed to configure client: %w", err)
	}

	token, err := config.Token(ctx)
	if err != nil {
		return "", fmt.Errorf("failed to obtain token: %w", err)
	}

	if token.AccessToken == "" {
		return "", errors.New("received empty access token")
	}

	return token.AccessToken, nil
}

var _ TokenSecret = (*SecretOIDCClientCredentials)(nil)

// SecretTokenAuth represents static bearer token authentication.
type SecretTokenAuth struct {
	BearerToken string // Bearer token for HTTP authentication
}

// Token returns the static bearer token.
func (s *SecretTokenAuth) Token(context.Context) (string, error) {
	return s.BearerToken, nil
}

var _ TokenSecret = (*SecretTokenAuth)(nil)
