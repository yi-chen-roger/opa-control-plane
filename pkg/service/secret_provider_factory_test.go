package service_test

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	pkgsync "github.com/open-policy-agent/opa-control-plane/pkg/sync"

	"github.com/open-policy-agent/opa-control-plane/pkg/service"
)

// mockSecretProviderFactory returns a mock secret provider per tenant.
type mockSecretProviderFactory struct {
	calls []string // records tenant names passed to SecretProviderForTenant
}

func (f *mockSecretProviderFactory) SecretProviderForTenant(_ context.Context, tenant string) (pkgsync.SecretProvider, error) {
	f.calls = append(f.calls, tenant)
	return &mockSecretProvider{tenant: tenant}, nil
}

type mockSecretProvider struct {
	tenant string
}

func (p *mockSecretProvider) GetSecret(_ context.Context, name string) (map[string]any, error) {
	return map[string]any{
		"type":   "token_auth",
		"token":  fmt.Sprintf("token-for-%s-%s", p.tenant, name),
		"tenant": p.tenant,
	}, nil
}

func TestSecretProviderFactory_UsedPerTenant(t *testing.T) {
	tempDir := t.TempDir()

	// Config with a git source that has credentials — this will trigger
	// the secret provider lookup during sync.
	bs := fmt.Appendf(nil, `{
		bundles: {
			test_bundle: {
				object_storage: {
					filesystem: {
						path: %q
					}
				},
				requirements: [
					{source: test_src}
				]
			}
		},
		sources: {
			test_src: {
				git: {
					repo: https://example.com/repo.git,
					credentials: my_creds,
					reference: refs/heads/main,
				}
			}
		}
	}`, filepath.Join(tempDir, "bundles"))

	factory := &mockSecretProviderFactory{}

	svc := service.New().
		WithRawConfig(bs).
		WithPersistenceDir(filepath.Join(tempDir, "data")).
		WithSingleShot(true).
		WithMigrateDB(true).
		WithSecretProviderFactory(factory)

	// Run will fail at git sync (fake repo), but the factory should have
	// been called with the "default" tenant before that.
	_ = svc.Run(context.Background())

	if len(factory.calls) == 0 {
		t.Fatal("expected SecretProviderFactory to be called, but it was not")
	}
	if factory.calls[0] != "default" {
		t.Fatalf("expected factory to be called with tenant 'default', got %q", factory.calls[0])
	}
}

func TestSecretProviderFactory_FallbackToNil(t *testing.T) {
	tempDir := t.TempDir()

	bs := fmt.Appendf(nil, `{
		bundles: {
			test_bundle: {
				object_storage: {
					filesystem: {
						path: %q
					}
				},
				requirements: [
					{source: test_src}
				]
			}
		},
		sources: {
			test_src: {
				git: {
					repo: https://example.com/repo.git,
					credentials: my_creds,
					reference: refs/heads/main,
				}
			}
		}
	}`, filepath.Join(tempDir, "bundles"))

	// Factory that returns nil (no provider for this tenant)
	nilFactory := &nilSecretProviderFactory{}

	svc := service.New().
		WithRawConfig(bs).
		WithPersistenceDir(filepath.Join(tempDir, "data")).
		WithSingleShot(true).
		WithMigrateDB(true).
		WithSecretProviderFactory(nilFactory)

	// The factory returns nil, so credentials won't resolve.
	// The run will fail at git sync.
	_ = svc.Run(context.Background())

	if len(nilFactory.calls) == 0 {
		t.Fatal("expected factory to be consulted even when returning nil")
	}
}

type nilSecretProviderFactory struct {
	calls []string
}

func (f *nilSecretProviderFactory) SecretProviderForTenant(_ context.Context, tenant string) (pkgsync.SecretProvider, error) {
	f.calls = append(f.calls, tenant)
	return nil, nil // fall back to static provider
}

func TestSecretProviderFactory_GitSyncWithCredentials(t *testing.T) {
	tempDir := t.TempDir()

	// Create a local bare git repo so the sync actually works
	repoDir := filepath.Join(tempDir, "remotegit")
	h := writeGitRepo(t, repoDir, map[string]string{
		"foo.rego": "package foo\np := 1",
	}, nil)

	tmpl := `{
		bundles: {
			test_bundle: {
				object_storage: {
					filesystem: {
						path: %q
					}
				},
				requirements: [
					{source: test_src, git: {commit: %q}}
				]
			}
		},
		sources: {
			test_src: {
				git: {
					repo: %q,
					reference: refs/heads/master,
				}
			}
		}
	}`

	bs := fmt.Appendf(nil, tmpl,
		filepath.Join(tempDir, "bundles"),
		h.String(),
		repoDir,
	)

	factory := &mockSecretProviderFactory{}

	svc := service.New().
		WithRawConfig(bs).
		WithPersistenceDir(filepath.Join(tempDir, "data")).
		WithSingleShot(true).
		WithMigrateDB(true).
		WithSecretProviderFactory(factory)

	err := svc.Run(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	report := svc.Report()
	if report.Bundles["test_bundle"].State != service.BuildStateSuccess {
		t.Fatalf("expected success, got %v: %s", report.Bundles["test_bundle"].State, report.Bundles["test_bundle"].Message)
	}

	// Factory should have been called for the default tenant
	if len(factory.calls) == 0 {
		t.Fatal("expected factory to be called")
	}

	// Verify the built bundle exists
	glob := filepath.Join(tempDir, "data", "*", "sources", "test_src", "repo", "foo.rego")
	matches, err := filepath.Glob(glob)
	if err != nil || len(matches) == 0 {
		t.Fatalf("expected foo.rego to be synced, glob: %s, err: %v", glob, err)
	}

	content, err := os.ReadFile(matches[0])
	if err != nil {
		t.Fatal(err)
	}
	if string(content) != "package foo\np := 1" {
		t.Fatalf("unexpected content: %s", content)
	}
}
