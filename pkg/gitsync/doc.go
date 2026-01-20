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
// Example usage with config-based secrets:
//
//	import "github.com/open-policy-agent/opa-control-plane/pkg/gitsync"
//	import "github.com/open-policy-agent/opa-control-plane/pkg/config"
//
//	gitConfig := config.Git{
//	    Repo:      "https://github.com/myorg/policies.git",
//	    Reference: ptr("main"),
//	    Credentials: &config.SecretRef{
//	        Name: "github-token",
//	        // ... credential configuration
//	    },
//	}
//
//	syncer := gitsync.New("/path/to/clone", gitConfig, "my-source")
//	err := syncer.Execute(ctx)
//	if err != nil {
//	    log.Fatal(err)
//	}
//	defer syncer.Close(ctx)
//
// # External Secret Management
//
// By default, gitsync reads secrets from the configuration file. External projects
// can integrate with their own secret management systems (HashiCorp Vault, AWS Secrets
// Manager, etc.) by implementing the SecretProvider interface:
//
//	type MySecretProvider struct {
//	    client *vault.Client
//	}
//
//	func (p *MySecretProvider) GetSecret(ctx context.Context, name string) (*config.Secret, error) {
//	    // Fetch secret from Vault
//	    vaultSecret, err := p.client.Logical().Read("secret/data/" + name)
//	    if err != nil {
//	        return nil, err
//	    }
//
//	    // Convert to OCP Secret format
//	    secret := &config.Secret{
//	        Type: "github_app_auth",
//	        Value: map[string]any{
//	            "type": "github_app_auth",
//	            "integration_id": vaultSecret.Data["integration_id"],
//	            "installation_id": vaultSecret.Data["installation_id"],
//	            "private_key": vaultSecret.Data["private_key"],
//	        },
//	    }
//	    return secret, nil
//	}
//
//	// Use custom provider
//	provider := &MySecretProvider{client: vaultClient}
//	syncer := gitsync.NewWithSecretProvider(path, gitConfig, sourceName, provider)
//	err := syncer.Execute(ctx)
//
// This allows organizations to:
//   - Centralize secret management across all services
//   - Enforce security policies and access controls
//   - Rotate credentials without modifying configuration files
//   - Audit all secret access through their secret management system
//   - Integrate with existing enterprise infrastructure
//
// Thread Safety: Synchronizer instances are NOT thread-safe. Each instance should
// be used by a single goroutine. Create separate instances for concurrent operations.
package gitsync
