package gitsync

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	gohttp "net/http"
	"os"
	"strings"
	"sync"

	"github.com/bradleyfalzon/ghinstallation/v2"
	"github.com/go-git/go-git/v5/plumbing/transport"
	"github.com/go-git/go-git/v5/plumbing/transport/http"
	gitssh "github.com/go-git/go-git/v5/plumbing/transport/ssh"
	"golang.org/x/crypto/ssh"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/clientcredentials"
)

// auth returns the appropriate authentication method for the configured credentials.
func (s *Synchronizer) auth(ctx context.Context) (transport.AuthMethod, error) {
	if s.config.Credentials == nil {
		return nil, nil
	}

	var credMap map[string]any
	var err error

	// Use SecretProvider if available, otherwise fall back to config-based resolution
	if s.secretProvider != nil {
		credMap, err = s.secretProvider.GetSecret(ctx, s.config.Credentials.Name)
		if err != nil {
			return nil, err
		}
	} else {
		// Backward compatibility: use config-based resolution
		value, err := s.config.Credentials.Resolve(ctx)
		if err != nil {
			return nil, err
		}
		// Convert internal config types to map format
		credMap, err = convertConfigToMap(value)
		if err != nil {
			return nil, err
		}
	}

	// Extract the type field
	credType, ok := credMap["type"].(string)
	if !ok {
		return nil, errors.New("credential map must include a 'type' field")
	}

	// Dispatch based on credential type
	switch credType {
	case "basic_auth":
		return authBasicFromMap(credMap)
	case "github_app":
		return authGitHubAppFromMap(ctx, &s.gh, credMap)
	case "ssh_key":
		return authSSHFromMap(credMap)
	case "bearer_token":
		return authBearerTokenFromMap(credMap)
	case "oidc_client_credentials":
		return authOIDCFromMap(credMap)
	default:
		return nil, fmt.Errorf("unsupported credential type: %s", credType)
	}
}

// authBasicFromMap creates basic auth from a map
func authBasicFromMap(m map[string]any) (transport.AuthMethod, error) {
	username, _ := m["username"].(string)
	password, ok := m["password"].(string)
	if !ok {
		return nil, errors.New("basic_auth requires 'password' field")
	}

	var headers []string
	if h, ok := m["headers"].([]any); ok {
		for _, v := range h {
			if str, ok := v.(string); ok {
				headers = append(headers, str)
			}
		}
	}

	return &basicAuth{
		Username: username,
		Password: password,
		Headers:  headers,
	}, nil
}

// authGitHubAppFromMap creates GitHub App auth from a map
func authGitHubAppFromMap(ctx context.Context, gh *github, m map[string]any) (transport.AuthMethod, error) {
	integrationID, err := getInt64FromMap(m, "integration_id")
	if err != nil {
		return nil, err
	}

	installationID, err := getInt64FromMap(m, "installation_id")
	if err != nil {
		return nil, err
	}

	privateKey, ok := m["private_key"].(string)
	if !ok {
		return nil, errors.New("github_app requires 'private_key' field")
	}

	token, err := gh.Token(ctx, integrationID, installationID, privateKey)
	if err != nil {
		return nil, err
	}

	return &http.BasicAuth{Username: "x-access-token", Password: token}, nil
}

// authSSHFromMap creates SSH auth from a map
func authSSHFromMap(m map[string]any) (transport.AuthMethod, error) {
	key, ok := m["key"].(string)
	if !ok {
		return nil, errors.New("ssh_key requires 'key' field")
	}

	passphrase, _ := m["passphrase"].(string)

	var fingerprints []string
	if fps, ok := m["fingerprints"].([]any); ok {
		for _, fp := range fps {
			if str, ok := fp.(string); ok {
				fingerprints = append(fingerprints, str)
			}
		}
	}

	if len(fingerprints) == 0 {
		return nil, errors.New("ssh_key requires at least one fingerprint")
	}

	return newSSHAuth(key, passphrase, fingerprints)
}

// authBearerTokenFromMap creates bearer token auth from a map
func authBearerTokenFromMap(m map[string]any) (transport.AuthMethod, error) {
	token, ok := m["token"].(string)
	if !ok {
		return nil, errors.New("bearer_token requires 'token' field")
	}

	return &tokenAuth{
		tokenSecret: &staticToken{token: token},
		name:        "bearer-token",
	}, nil
}

// authOIDCFromMap creates OIDC client credentials auth from a map
func authOIDCFromMap(m map[string]any) (transport.AuthMethod, error) {
	clientID, ok := m["client_id"].(string)
	if !ok {
		return nil, errors.New("oidc_client_credentials requires 'client_id' field")
	}

	clientSecret, ok := m["client_secret"].(string)
	if !ok {
		return nil, errors.New("oidc_client_credentials requires 'client_secret' field")
	}

	// Either issuer or token_url must be provided
	issuer, _ := m["issuer"].(string)
	tokenURL, _ := m["token_url"].(string)

	if issuer == "" && tokenURL == "" {
		return nil, errors.New("oidc_client_credentials requires either 'issuer' or 'token_url' field")
	}

	var scopes []string
	if scopesAny, ok := m["scopes"].([]any); ok {
		for _, s := range scopesAny {
			if str, ok := s.(string); ok {
				scopes = append(scopes, str)
			}
		}
	}

	return &tokenAuth{
		tokenSecret: &oidcClientCredentials{
			issuer:       issuer,
			tokenURL:     tokenURL,
			clientID:     clientID,
			clientSecret: clientSecret,
			scopes:       scopes,
		},
		name: "oidc-client-credentials",
	}, nil
}

// getInt64FromMap extracts an int64 from a map, handling various numeric types
func getInt64FromMap(m map[string]any, key string) (int64, error) {
	val, ok := m[key]
	if !ok {
		return 0, fmt.Errorf("missing required field '%s'", key)
	}

	switch v := val.(type) {
	case int64:
		return v, nil
	case int:
		return int64(v), nil
	case float64:
		return int64(v), nil
	default:
		return 0, fmt.Errorf("field '%s' must be a number, got %T", key, val)
	}
}

// convertConfigToMap converts internal config types to map format for backward compatibility
func convertConfigToMap(value any) (map[string]any, error) {
	// This would convert config.SecretBasicAuth, config.SecretGitHubApp, etc. to maps
	// For now, return an error since we expect all external users to provide maps
	return nil, fmt.Errorf("config-based secrets not yet supported in map format")
}

// github handles GitHub App authentication by managing installation tokens.
type github struct {
	integrationID  int64
	installationID int64
	privateKey     []byte
	tr             *ghinstallation.Transport
	mu             sync.Mutex
}

// Token retrieves a GitHub App installation token for authentication.
func (gh *github) Token(ctx context.Context, integrationID, installationID int64, privateKeyFile string) (string, error) {
	privateKey, err := os.ReadFile(privateKeyFile)
	if err != nil {
		return "", err
	}

	tr, err := gh.transport(integrationID, installationID, privateKey)
	if err != nil {
		return "", err
	}

	token, err := tr.Token(ctx)
	if err != nil {
		return "", err
	}

	return token, nil
}

// transport returns a cached GitHub App transport or creates a new one if the configuration has changed.
func (gh *github) transport(integrationID, installationID int64, privateKey []byte) (*ghinstallation.Transport, error) {
	gh.mu.Lock()
	defer gh.mu.Unlock()

	if gh.tr == nil || gh.integrationID != integrationID || gh.installationID != installationID || !bytes.Equal(gh.privateKey, privateKey) {
		tr, err := ghinstallation.New(gohttp.DefaultTransport, integrationID, installationID, privateKey)
		if err != nil {
			return nil, err
		}

		gh.integrationID = integrationID
		gh.installationID = installationID
		gh.privateKey = privateKey
		gh.tr = tr
	}

	return gh.tr, nil
}

// newSSHAuth creates an SSH authentication method with fingerprint validation.
func newSSHAuth(key string, passphrase string, fingerprints []string) (gitssh.AuthMethod, error) {
	var signer ssh.Signer
	var err error
	if passphrase != "" {
		signer, err = ssh.ParsePrivateKeyWithPassphrase([]byte(key), []byte(passphrase))
		if err != nil {
			return nil, err
		}
	} else {
		signer, err = ssh.ParsePrivateKey([]byte(key))
		if err != nil {
			return nil, err
		}
	}

	if len(fingerprints) == 0 {
		return nil, errors.New("ssh: at least one fingerprint is required when using ssh_key authentication")
	}

	return &gitssh.PublicKeys{
		User:   "git",
		Signer: signer,
		HostKeyCallbackHelper: gitssh.HostKeyCallbackHelper{
			HostKeyCallback: newCheckFingerprints(fingerprints),
		},
	}, nil
}

// newCheckFingerprints creates an SSH host key callback that validates against known fingerprints.
func newCheckFingerprints(fingerprints []string) ssh.HostKeyCallback {
	m := make(map[string]bool, len(fingerprints))
	for _, fp := range fingerprints {
		m[fp] = true
	}

	return func(hostname string, _ net.Addr, key ssh.PublicKey) error {
		fingerprint := ssh.FingerprintSHA256(key)
		if _, ok := m[fingerprint]; !ok {
			return fmt.Errorf("ssh: unknown fingerprint (%s) for %s", fingerprint, hostname)
		}
		return nil
	}
}

// basicAuth provides HTTP basic authentication but in addition can set
// extra headers required for authentication.
type basicAuth struct {
	Username string
	Password string
	Headers  []string
}

func (a *basicAuth) String() string {
	masked := "*******"
	if a.Password == "" {
		masked = "<empty>"
	}
	return fmt.Sprintf("%s - %s:%s [%s]", a.Name(), a.Username, masked, strings.Join(a.Headers, ", "))
}

func (*basicAuth) Name() string {
	return "http-basic-auth-extra"
}

func (a *basicAuth) SetAuth(r *gohttp.Request) {
	r.SetBasicAuth(a.Username, a.Password)
	for _, header := range a.Headers {
		name, value, found := strings.Cut(header, ":")
		if found {
			r.Header.Set(strings.TrimSpace(name), strings.TrimSpace(value))
		}
	}
}

// tokenSecret is a private interface for credentials that can provide bearer tokens.
// Both static tokens and dynamic tokens (like OIDC) implement this interface.
type tokenSecret interface {
	Token(ctx context.Context) (string, error)
}

// staticToken implements tokenSecret for static bearer tokens.
type staticToken struct {
	token string
}

func (t *staticToken) Token(context.Context) (string, error) {
	return t.token, nil
}

// oidcClientCredentials implements tokenSecret for OIDC client credentials flow.
type oidcClientCredentials struct {
	issuer       string
	tokenURL     string
	clientID     string
	clientSecret string
	scopes       []string
	ts           oauth2.TokenSource
	mu           sync.Mutex
}

func (o *oidcClientCredentials) Token(ctx context.Context) (string, error) {
	o.mu.Lock()
	defer o.mu.Unlock()

	if o.ts == nil {
		cfg := clientcredentials.Config{
			ClientID:     o.clientID,
			ClientSecret: o.clientSecret,
			Scopes:       o.scopes,
		}

		if o.tokenURL != "" {
			cfg.TokenURL = o.tokenURL
		} else if o.issuer != "" {
			cfg.TokenURL = o.issuer + "/oauth/token"
		}

		o.ts = cfg.TokenSource(ctx)
	}

	token, err := o.ts.Token()
	if err != nil {
		return "", err
	}

	return token.AccessToken, nil
}

// tokenAuth provides HTTP bearer token authentication using any tokenSecret.
// It works with both static tokens and dynamic tokens (like OIDC client credentials).
type tokenAuth struct {
	tokenSecret tokenSecret
	name        string
}

func (a *tokenAuth) String() string {
	return a.Name() + " - token-based"
}

func (a *tokenAuth) Name() string {
	return "http-" + a.name
}

func (a *tokenAuth) SetAuth(r *gohttp.Request) {
	// Get a token using the tokenSecret interface
	token, err := a.tokenSecret.Token(r.Context())
	if err != nil {
		// If we can't get a token, we can't set auth
		// This will likely result in an authentication error downstream
		return
	}

	r.Header.Set("Authorization", "Bearer "+token)
}
