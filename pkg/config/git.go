package config

import (
	"context"
	"encoding/json"
	"fmt"
	"maps"
	"slices"
	"sort"

	"github.com/goccy/go-yaml"
)

// StringSet is an ordered set of unique strings.
type StringSet []string

// Equal returns true if two StringSets contain the same elements.
func (a StringSet) Equal(b StringSet) bool {
	return setEqual(a, b, func(s string) string { return s }, func(a, b string) bool { return a == b })
}

// Add adds a value to the StringSet in sorted order, maintaining uniqueness.
func (a StringSet) Add(value string) StringSet {
	i := sort.Search(len(a), func(i int) bool { return a[i] >= value })
	if i < len(a) && a[i] == value {
		return a
	}

	return slices.Insert(a, i, value)
}

// Git defines the Git synchronization configuration used by OPA Control Plane Sources.
type Git struct {
	Repo          string     `json:"repo"`
	Reference     *string    `json:"reference,omitempty"`
	Commit        *string    `json:"commit,omitempty"`
	Path          *string    `json:"path,omitempty"`
	IncludedFiles StringSet  `json:"included_files,omitempty"`
	ExcludedFiles StringSet  `json:"excluded_files,omitempty"`
	Credentials   *SecretRef `json:"credentials,omitempty"` // If nil, use the default SSH authentication mechanisms available
	// or no authentication for public repos. Note, JSON schema validation overrides this to string type.

	_ struct{} `additionalProperties:"false"`
}

// Equal returns true if two Git configurations are equal.
func (g *Git) Equal(other *Git) bool {
	return fastEqual(g, other, func(g, other *Git) bool {
		return ptrEqual(g.Reference, other.Reference) &&
			ptrEqual(g.Commit, other.Commit) &&
			ptrEqual(g.Path, other.Path) &&
			g.Credentials.Equal(other.Credentials) &&
			g.IncludedFiles.Equal(other.IncludedFiles) &&
			g.ExcludedFiles.Equal(other.ExcludedFiles)
	})
}

// SecretRef is a reference to a named secret. It holds the secret name and
// optionally a resolved secret value. External projects should use SecretProvider
// to resolve secrets rather than calling Resolve() directly.
type SecretRef struct {
	Name  string `json:"-"`
	value *Secret
}

// Resolve retrieves the secret value from the secret store. If the secret is not found, an error is returned.
// If the secret is found, it returns the value as an interface{} which can be further typed as needed.
//
// Note: This method is primarily for internal OCP use. External projects should use
// SecretProvider.GetSecret() instead.
func (s *SecretRef) Resolve(ctx context.Context) (any, error) {
	if s.value == nil {
		return nil, fmt.Errorf("secret %q not found", s.Name)
	}

	return s.value.Typed(ctx)
}

// MarshalYAML implements yaml.Marshaler for SecretRef.
func (s *SecretRef) MarshalYAML() (any, error) {
	if s.Name == "" {
		return nil, nil
	}
	return s.Name, nil
}

// MarshalJSON implements json.Marshaler for SecretRef.
func (s *SecretRef) MarshalJSON() ([]byte, error) {
	v, err := s.MarshalYAML()
	if err != nil {
		return nil, err
	}

	return json.Marshal(v)
}

// UnmarshalYAML implements yaml.Unmarshaler for SecretRef.
func (s *SecretRef) UnmarshalYAML(bs []byte) error {
	if err := yaml.Unmarshal(bs, &s.Name); err != nil {
		return fmt.Errorf("expected scalar node: %w", err)
	}
	return nil
}

// UnmarshalJSON implements json.Unmarshaler for SecretRef.
func (s *SecretRef) UnmarshalJSON(bs []byte) error {
	if err := json.Unmarshal(bs, &s.Name); err != nil {
		return fmt.Errorf("failed to unmarshal SecretRef: %w", err)
	}

	return nil
}

// Equal returns true if two SecretRefs are equal.
func (s *SecretRef) Equal(other *SecretRef) bool {
	return fastEqual(s, other, func(s, other *SecretRef) bool {
		return s.Name == other.Name && s.value.Equal(other.value)
	})
}

// Helper functions for equality comparison

func setEqual[K comparable, V comparable](a, b []V, key func(V) K, eq func(a, b V) bool) bool {
	if len(a) == 1 && len(b) == 1 {
		return eq(a[0], b[0])
	}

	// NB(sr): There's a risk of false positives here, e.g. []struct{n, v string}{ {"foo", "bar"}, {"foo", "baz"} }
	// is setEqual to []struct{n, v string}{ {"foo", "baz"} }
	m := make(map[K]V, len(a))
	for _, v := range a {
		m[key(v)] = v
	}

	n := make(map[K]V, len(b))
	for _, v := range b {
		n[key(v)] = v
	}

	return maps.Equal(m, n)
}

func ptrEqual[T comparable](a, b *T) bool {
	return fastEqual(a, b, func(a, b *T) bool { return *a == *b })
}

func fastEqual[V any](a, b *V, slowEqual func(a, b *V) bool) bool {
	if a == b {
		return true
	}

	if a == nil || b == nil {
		return false
	}

	return slowEqual(a, b)
}
