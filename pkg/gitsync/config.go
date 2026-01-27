package gitsync

// GitConfig represents the minimal git configuration for external users.
// This is the public API for configuring git synchronization.
type GitConfig struct {
	// Repo is the git repository URL (required)
	Repo string

	// Reference is the git branch or tag to checkout (optional, mutually exclusive with Commit)
	Reference *string

	// Commit is the specific commit SHA to checkout (optional, mutually exclusive with Reference)
	Commit *string

	// CredentialName is the name of the secret to use for authentication (optional)
	// The actual secret is resolved through the SecretProvider.
	CredentialName *string
}
