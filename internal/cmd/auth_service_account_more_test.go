package cmd

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/steipete/gogcli/internal/config"
	"github.com/steipete/gogcli/internal/secrets"
)

func TestAuthServiceAccountSet_AndList_Text(t *testing.T) {
	origOpen := openSecretsStore
	t.Cleanup(func() { openSecretsStore = origOpen })

	store := newMemSecretsStore()
	openSecretsStore = func() (secrets.Store, error) { return store, nil }

	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(home, "xdg-config"))

	keyPath := filepath.Join(t.TempDir(), "sa.json")
	if err := os.WriteFile(keyPath, []byte(`{"type":"service_account","client_email":"svc@example.com"}`), 0o600); err != nil {
		t.Fatalf("write key: %v", err)
	}

	out := captureStdout(t, func() {
		_ = captureStderr(t, func() {
			if err := Execute([]string{"auth", "service-account", "set", "user@example.com", "--key", keyPath}); err != nil {
				t.Fatalf("Execute: %v", err)
			}
		})
	})
	if !strings.Contains(out, "Service account configured") {
		t.Fatalf("unexpected output: %q", out)
	}

	storedPath, err := config.ServiceAccountPath("user@example.com")
	if err != nil {
		t.Fatalf("ServiceAccountPath: %v", err)
	}
	if _, err := os.Stat(storedPath); err != nil {
		t.Fatalf("expected stored key at %q: %v", storedPath, err)
	}

	listOut := captureStdout(t, func() {
		_ = captureStderr(t, func() {
			if err := Execute([]string{"auth", "list"}); err != nil {
				t.Fatalf("list: %v", err)
			}
		})
	})
	if !strings.Contains(listOut, "user@example.com") || !strings.Contains(listOut, "service_account") {
		t.Fatalf("unexpected list output: %q", listOut)
	}
}

func TestAuthStatus_ShowsServiceAccountPreferred(t *testing.T) {
	origOpen := openSecretsStore
	t.Cleanup(func() { openSecretsStore = origOpen })

	store := newMemSecretsStore()
	openSecretsStore = func() (secrets.Store, error) { return store, nil }

	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(home, "xdg-config"))

	keyPath := filepath.Join(t.TempDir(), "sa.json")
	if err := os.WriteFile(keyPath, []byte(`{"type":"service_account","client_email":"svc@example.com"}`), 0o600); err != nil {
		t.Fatalf("write key: %v", err)
	}

	_ = captureStdout(t, func() {
		_ = captureStderr(t, func() {
			if err := Execute([]string{"auth", "service-account", "set", "user@example.com", "--key", keyPath}); err != nil {
				t.Fatalf("Execute: %v", err)
			}
		})
	})

	out := captureStdout(t, func() {
		_ = captureStderr(t, func() {
			if err := Execute([]string{"--account", "user@example.com", "auth", "status"}); err != nil {
				t.Fatalf("status: %v", err)
			}
		})
	})
	if !strings.Contains(out, "auth_preferred\tservice_account") {
		t.Fatalf("unexpected status output: %q", out)
	}
}

func TestAuthServiceAccountSet_Direct_AndList_Text(t *testing.T) {
	origOpen := openSecretsStore
	t.Cleanup(func() { openSecretsStore = origOpen })

	store := newMemSecretsStore()
	openSecretsStore = func() (secrets.Store, error) { return store, nil }

	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(home, "xdg-config"))

	keyPath := filepath.Join(t.TempDir(), "sa.json")
	if err := os.WriteFile(keyPath, []byte(`{"type":"service_account","client_email":"svc@project.iam.gserviceaccount.com"}`), 0o600); err != nil {
		t.Fatalf("write key: %v", err)
	}

	out := captureStdout(t, func() {
		_ = captureStderr(t, func() {
			if err := Execute([]string{"auth", "service-account", "set", "svc@project.iam.gserviceaccount.com", "--key", keyPath, "--direct"}); err != nil {
				t.Fatalf("Execute: %v", err)
			}
		})
	})
	if !strings.Contains(out, "Service account configured") {
		t.Fatalf("unexpected output: %q", out)
	}
	if !strings.Contains(out, "mode\tdirect") {
		t.Fatalf("expected mode=direct in output: %q", out)
	}

	storedPath, err := config.DirectServiceAccountPath("svc@project.iam.gserviceaccount.com")
	if err != nil {
		t.Fatalf("DirectServiceAccountPath: %v", err)
	}
	if _, err := os.Stat(storedPath); err != nil {
		t.Fatalf("expected stored key at %q: %v", storedPath, err)
	}

	// The delegation path should NOT exist.
	delegationPath, _ := config.ServiceAccountPath("svc@project.iam.gserviceaccount.com")
	if _, err := os.Stat(delegationPath); err == nil {
		t.Fatalf("delegation path should not exist: %q", delegationPath)
	}

	listOut := captureStdout(t, func() {
		_ = captureStderr(t, func() {
			if err := Execute([]string{"auth", "list"}); err != nil {
				t.Fatalf("list: %v", err)
			}
		})
	})
	if !strings.Contains(listOut, "svc@project.iam.gserviceaccount.com") {
		t.Fatalf("expected email in list output: %q", listOut)
	}
	if !strings.Contains(listOut, "direct_service_account") {
		t.Fatalf("expected direct_service_account auth type in list output: %q", listOut)
	}
}

func TestAuthStatus_ShowsDirectServiceAccountPreferred(t *testing.T) {
	origOpen := openSecretsStore
	t.Cleanup(func() { openSecretsStore = origOpen })

	store := newMemSecretsStore()
	openSecretsStore = func() (secrets.Store, error) { return store, nil }

	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(home, "xdg-config"))

	keyPath := filepath.Join(t.TempDir(), "sa.json")
	if err := os.WriteFile(keyPath, []byte(`{"type":"service_account","client_email":"svc@project.iam.gserviceaccount.com"}`), 0o600); err != nil {
		t.Fatalf("write key: %v", err)
	}

	_ = captureStdout(t, func() {
		_ = captureStderr(t, func() {
			if err := Execute([]string{"auth", "service-account", "set", "svc@project.iam.gserviceaccount.com", "--key", keyPath, "--direct"}); err != nil {
				t.Fatalf("Execute: %v", err)
			}
		})
	})

	out := captureStdout(t, func() {
		_ = captureStderr(t, func() {
			if err := Execute([]string{"--account", "svc@project.iam.gserviceaccount.com", "auth", "status"}); err != nil {
				t.Fatalf("status: %v", err)
			}
		})
	})
	if !strings.Contains(out, "auth_preferred\tdirect_service_account") {
		t.Fatalf("unexpected status output: %q", out)
	}
}
