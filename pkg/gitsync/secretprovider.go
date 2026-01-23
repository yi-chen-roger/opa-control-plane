package gitsync

import "context"

// SecretProvider abstracts the source of secrets, allowing external projects
// to integrate with their own secret management backends (Vault, AWS Secrets Manager,
// HashiCorp Vault, etc.).
//
// This interface enables:
//   - Centralize secret management
//   - Enforce security policies
//   - Rotate credentials without config changes
//   - Audit secret access
//   - Integrate with enterprise secret management systems
type SecretProvider interface {
	// GetSecret retrieves a secret by name and returns a Secret interface.
	// The returned Secret will be passed to Secret.Typed() to get the typed
	// credential value for authentication.
	GetSecret(ctx context.Context, name string) (Secret, error)
}
