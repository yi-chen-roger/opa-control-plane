package gitsync

import internalgitsync "github.com/open-policy-agent/opa-control-plane/internal/gitsync"

// SecretProvider is re-exported from internal/gitsync for external use.
// See the internal/gitsync.SecretProvider interface documentation for details on supported credential types.
type SecretProvider = internalgitsync.SecretProvider
