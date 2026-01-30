package gitsync

import "context"

// SecretProvider abstracts the source of secrets, allowing external projects
// to integrate with their own secret management backends (Vault, AWS Secrets Manager,
// HashiCorp Vault, etc.).
//
// The GetSecret method returns a map containing the secret data. The map MUST include
// a "type" field to indicate the credential type, and additional fields based on the type.
//
// Supported credential types and their required fields:
//
// Type: "basic_auth"
//   - username (string, optional)
//   - password (string, required)
//   - headers ([]string, optional) - format: "Header-Name: value"
//
// Type: "github_app"
//   - integration_id (int64, required)
//   - installation_id (int64, required)
//   - private_key (string, required) - path to PEM file
//
// Type: "ssh_key"
//   - key (string, required) - SSH private key in PEM format
//   - passphrase (string, optional)
//   - fingerprints ([]string, required) - SHA256 fingerprints
//
// Type: "bearer_token"
//   - token (string, required)
//
// Type: "oidc_client_credentials"
//   - issuer (string, required if token_url not provided)
//   - token_url (string, required if issuer not provided)
//   - client_id (string, required)
//   - client_secret (string, required)
//   - scopes ([]string, optional)
//
// Example:
//
//	// GitHub App credentials
//	return map[string]any{
//	    "type":            "github_app",
//	    "integration_id":  int64(12345),
//	    "installation_id": int64(67890),
//	    "private_key":     "/path/to/key.pem",
//	}, nil
//
// This interface enables:
//   - Centralize secret management
//   - Enforce security policies
//   - Rotate credentials without config changes
//   - Audit secret access
//   - Integrate with enterprise secret management systems
type SecretProvider interface {
	// GetSecret retrieves a secret by name and returns a map with credential data.
	// The map must include a "type" field and other fields as required by the credential type.
	GetSecret(ctx context.Context, name string) (map[string]any, error)
}
