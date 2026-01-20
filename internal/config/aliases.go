package config

import pkgconfig "github.com/open-policy-agent/opa-control-plane/pkg/config"

// Type aliases for backward compatibility with pkg/config.
// All types that have been moved to pkg/config are re-exported here
// so that existing internal code continues to work without modification.

// Core types
type Git = pkgconfig.Git
type Secret = pkgconfig.Secret
type SecretRef = pkgconfig.SecretRef
type StringSet = pkgconfig.StringSet

// Secret type structs
type SecretAWS = pkgconfig.SecretAWS
type SecretGCP = pkgconfig.SecretGCP
type SecretAzure = pkgconfig.SecretAzure
type SecretGitHubApp = pkgconfig.SecretGitHubApp
type SecretSSHKey = pkgconfig.SecretSSHKey
type SecretBasicAuth = pkgconfig.SecretBasicAuth
type SecretTokenAuth = pkgconfig.SecretTokenAuth
type SecretOIDCClientCredentials = pkgconfig.SecretOIDCClientCredentials
type SecretPassword = pkgconfig.SecretPassword
type SecretTLSCert = pkgconfig.SecretTLSCert

// Interfaces
type ClientSecret = pkgconfig.ClientSecret
type TokenSecret = pkgconfig.TokenSecret
