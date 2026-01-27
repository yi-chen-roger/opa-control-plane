package gitsync

import "context"

// Secret represents a typed secret that can be used for authentication.
// External projects implementing SecretProvider should return implementations
// of this interface from GetSecret().
//
// The secret value will be type-asserted to one of the credential types
// (SecretBasicAuth, SecretGitHubApp, SecretSSHKey, etc.) for authentication.
type Secret interface {
	// Typed returns the typed secret value that can be used for authentication.
	// The returned value should be one of the gitsync credential types.
	Typed(ctx context.Context) (any, error)
}
