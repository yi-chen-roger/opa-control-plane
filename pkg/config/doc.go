// Package config provides configuration types for OPA Control Plane components.
//
// This package contains externalized configuration types that can be used by
// external projects integrating with OCP components like gitsync.
//
// # Core Types
//
// Git: Configuration for Git repository synchronization
//
//	cfg := config.Git{
//	    Repo: "https://github.com/example/repo",
//	    Reference: ptr("main"),
//	}
//
// Secret: Generic secret container with type resolution
//
//	secret := config.Secret{
//	    Name: "my-secret",
//	    Value: map[string]any{
//	        "type": "basic_auth",
//	        "username": "user",
//	        "password": "${PASSWORD}",
//	    },
//	}
//
// # Secret Types
//
// The package supports multiple secret types for different authentication scenarios:
//
//   - SecretBasicAuth: HTTP basic authentication
//   - SecretTokenAuth: Bearer token authentication
//   - SecretOIDCClientCredentials: OIDC Client Credentials flow
//   - SecretSSHKey: SSH key authentication
//   - SecretGitHubApp: GitHub App authentication
//   - SecretAWS: AWS credentials
//   - SecretGCP: Google Cloud credentials
//   - SecretAzure: Azure credentials
//   - SecretPassword: Simple password
//   - SecretTLSCert: TLS certificate bundle
//
// # Interfaces
//
// ClientSecret: Secrets that can provide an HTTP client:
//
//	var secret config.ClientSecret = &config.SecretBasicAuth{
//	    Username: "user",
//	    Password: "pass",
//	}
//	client, err := secret.Client(ctx)
//
// TokenSecret: Secrets that can provide a bearer token:
//
//	var secret config.TokenSecret = &config.SecretTokenAuth{
//	    BearerToken: "token123",
//	}
//	token, err := secret.Token(ctx)
package config
