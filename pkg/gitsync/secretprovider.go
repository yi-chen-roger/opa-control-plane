package gitsync

import (
	"context"
	"fmt"

	"github.com/open-policy-agent/opa-control-plane/internal/config"
)

// SecretProvider abstracts the source of secrets, allowing external projects
// to integrate with their own secret management backends (Vault, AWS Secrets Manager,
// HashiCorp Vault, etc.).
//
// This interface enables organizations to:
//   - Centralize secret management
//   - Enforce security policies
//   - Rotate credentials without config changes
//   - Audit secret access
//   - Integrate with enterprise secret management systems
type SecretProvider interface {
	// GetSecret retrieves a secret by name and returns a typed Secret.
	// The returned Secret should be compatible with OCP's secret type system
	// and will be passed to Secret.Typed() for type-specific handling.
	GetSecret(ctx context.Context, name string) (*config.Secret, error)
}

// ConfigSecretProvider implements SecretProvider using OCP's config-file based secrets.
// This is the default implementation that maintains backward compatibility with
// existing OCP deployments where secrets are defined in YAML configuration files.
type ConfigSecretProvider struct {
	secrets map[string]*config.Secret
}

// NewConfigSecretProvider creates a new ConfigSecretProvider with the given secret map.
func NewConfigSecretProvider(secrets map[string]*config.Secret) *ConfigSecretProvider {
	return &ConfigSecretProvider{secrets: secrets}
}

// GetSecret retrieves a secret from the in-memory map populated from config files.
func (p *ConfigSecretProvider) GetSecret(ctx context.Context, name string) (*config.Secret, error) {
	if p.secrets == nil {
		return nil, fmt.Errorf("secret %q not found: provider not initialized", name)
	}

	secret, ok := p.secrets[name]
	if !ok {
		return nil, fmt.Errorf("secret %q not found", name)
	}

	return secret, nil
}
