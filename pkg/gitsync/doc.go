// Package gitsync provides git repository synchronization for OPA bundle building.
//
// This package implements secure git clone, fetch, and checkout operations with
// support for multiple authentication methods:
//   - GitHub App (short-lived installation tokens)
//   - Personal Access Tokens (PAT)
//   - SSH keys with fingerprint validation
//   - Basic HTTP authentication
//   - OIDC Client Credentials
//
// The primary type is Synchronizer, which manages the lifecycle of a git repository
// clone and keeps it synchronized with the remote repository.
//
// # Basic Usage
//
// For external users, use GitConfig with an optional SecretProvider:
//
//	import "github.com/open-policy-agent/opa-control-plane/pkg/gitsync"
//
//	ref := "main"
//	credName := "github-token"
//	gitConfig := &gitsync.GitConfig{
//	    Repo:           "https://github.com/myorg/policies.git",
//	    Reference:      &ref,
//	    CredentialName: &credName,
//	}
//
//	// provider implements gitsync.SecretProvider for fetching credentials
//	syncer := gitsync.NewFromGitConfig("/path/to/clone", gitConfig, "my-source", provider)
//	err := syncer.Execute(ctx)
//	if err != nil {
//	    log.Fatal(err)
//	}
//	defer syncer.Close(ctx)
//
// For simple cases without credentials (public repos), pass nil as the provider:
//
//	gitConfig := &gitsync.GitConfig{
//	    Repo:      "https://github.com/myorg/public-policies.git",
//	    Reference: &ref,
//	}
//	syncer := gitsync.NewFromGitConfig("/path/to/clone", gitConfig, "my-source", nil)
//
// # External Secret Management
//
// External projects can integrate with their own secret management systems
// (HashiCorp Vault, AWS Secrets Manager, etc.) by implementing the SecretProvider interface:
//
//	type MySecretProvider struct {
//	    client *vault.Client
//	}
//
//	func (p *MySecretProvider) GetSecret(ctx context.Context, name string) (gitsync.Secret, error) {
//	    // Fetch secret from Vault
//	    vaultSecret, err := p.client.Logical().Read("secret/data/" + name)
//	    if err != nil {
//	        return nil, err
//	    }
//
//	    // Return a gitsync.Secret implementation that provides the credential
//	    return &myVaultSecret{data: vaultSecret.Data}, nil
//	}
//
//	type myVaultSecret struct {
//	    data map[string]interface{}
//	}
//
//	func (s *myVaultSecret) Typed(ctx context.Context) (any, error) {
//	    // Convert Vault data to gitsync credential types
//	    return &gitsync.SecretGitHubApp{
//	        IntegrationID:  s.data["integration_id"].(int64),
//	        InstallationID: s.data["installation_id"].(int64),
//	        PrivateKey:     s.data["private_key"].(string),
//	    }, nil
//	}
//
//	// Use custom provider with NewFromGitConfig
//	provider := &MySecretProvider{client: vaultClient}
//	syncer := gitsync.NewFromGitConfig(path, gitConfig, sourceName, provider)
//	err := syncer.Execute(ctx)
//
// This allows:
//   - Centralize secret management across all services
//   - Enforce security policies and access controls
//   - Rotate credentials without modifying configuration files
//   - Audit all secret access through their secret management system
//   - Integrate with existing enterprise infrastructure
//
// Thread Safety: Synchronizer instances are NOT thread-safe. Each instance should
// be used by a single goroutine. Create separate instances for concurrent operations.
package gitsync
