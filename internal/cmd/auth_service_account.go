package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/steipete/gogcli/internal/config"
	"github.com/steipete/gogcli/internal/outfmt"
	"github.com/steipete/gogcli/internal/ui"
)

type AuthServiceAccountCmd struct {
	Set    AuthServiceAccountSetCmd    `cmd:"" name:"set" help:"Store a service account key for impersonation or direct access"`
	Unset  AuthServiceAccountUnsetCmd  `cmd:"" name:"unset" help:"Remove stored service account key"`
	Status AuthServiceAccountStatusCmd `cmd:"" name:"status" help:"Show stored service account key status"`
}

type serviceAccountJSONInfo struct {
	ClientEmail string
	ClientID    string
}

func parseServiceAccountJSON(data []byte) (serviceAccountJSONInfo, error) {
	var saJSON map[string]any
	if err := json.Unmarshal(data, &saJSON); err != nil {
		return serviceAccountJSONInfo{}, fmt.Errorf("invalid service account JSON: %w", err)
	}
	if saJSON["type"] != "service_account" {
		return serviceAccountJSONInfo{}, fmt.Errorf("invalid service account JSON: expected type=service_account")
	}

	info := serviceAccountJSONInfo{}
	if v, ok := saJSON["client_email"].(string); ok {
		info.ClientEmail = strings.TrimSpace(v)
	}
	if v, ok := saJSON["client_id"].(string); ok {
		info.ClientID = strings.TrimSpace(v)
	}
	return info, nil
}

func storeServiceAccountKey(email string, keyPath string, direct bool) (string, serviceAccountJSONInfo, error) {
	keyPath = strings.TrimSpace(keyPath)
	if keyPath == "" {
		return "", serviceAccountJSONInfo{}, usage("empty key path")
	}
	keyPath, err := config.ExpandPath(keyPath)
	if err != nil {
		return "", serviceAccountJSONInfo{}, err
	}

	data, err := os.ReadFile(keyPath) //nolint:gosec // user-provided path
	if err != nil {
		return "", serviceAccountJSONInfo{}, fmt.Errorf("read service account key: %w", err)
	}

	info, err := parseServiceAccountJSON(data)
	if err != nil {
		return "", serviceAccountJSONInfo{}, err
	}

	var destPath string
	if direct {
		destPath, err = config.DirectServiceAccountPath(email)
	} else {
		destPath, err = config.ServiceAccountPath(email)
	}
	if err != nil {
		return "", serviceAccountJSONInfo{}, err
	}

	if _, err := config.EnsureDir(); err != nil {
		return "", serviceAccountJSONInfo{}, err
	}

	if err := os.WriteFile(destPath, data, 0o600); err != nil {
		return "", serviceAccountJSONInfo{}, fmt.Errorf("write service account: %w", err)
	}

	return destPath, info, nil
}

type AuthServiceAccountSetCmd struct {
	Email  string `arg:"" name:"email" help:"Email to impersonate (Workspace user), or service account client_email with --direct" required:""`
	Key    string `name:"key" required:"" help:"Path to service account JSON key file"`
	Direct bool   `name:"direct" help:"Use service account directly without impersonation (no domain-wide delegation)"`
}

func (c *AuthServiceAccountSetCmd) Run(ctx context.Context) error {
	u := ui.FromContext(ctx)

	email := strings.TrimSpace(c.Email)
	if email == "" {
		return usage("empty email")
	}

	destPath, info, err := storeServiceAccountKey(email, c.Key, c.Direct)
	if err != nil {
		return err
	}

	mode := "delegation"
	if c.Direct {
		mode = "direct"
	}

	if outfmt.IsJSON(ctx) {
		return outfmt.WriteJSON(os.Stdout, map[string]any{
			"stored":       true,
			"email":        email,
			"path":         destPath,
			"client_email": info.ClientEmail,
			"client_id":    info.ClientID,
			"mode":         mode,
		})
	}
	u.Out().Printf("email\t%s", email)
	u.Out().Printf("path\t%s", destPath)
	u.Out().Printf("mode\t%s", mode)
	if info.ClientEmail != "" {
		u.Out().Printf("client_email\t%s", info.ClientEmail)
	}
	if info.ClientID != "" {
		u.Out().Printf("client_id\t%s", info.ClientID)
	}
	u.Out().Println("Service account configured. Use: gog <cmd> --account " + email)
	return nil
}

type AuthServiceAccountUnsetCmd struct {
	Email  string `arg:"" name:"email" help:"Email (impersonated user, or service account client_email with --direct)" required:""`
	Direct bool   `name:"direct" help:"Remove direct service account key (no impersonation)"`
}

func (c *AuthServiceAccountUnsetCmd) Run(ctx context.Context, flags *RootFlags) error {
	u := ui.FromContext(ctx)

	email := strings.TrimSpace(c.Email)
	if email == "" {
		return usage("empty email")
	}

	modeLabel := "delegation"
	if c.Direct {
		modeLabel = "direct"
	}

	if err := confirmDestructive(ctx, flags, fmt.Sprintf("remove stored %s service account for %s", modeLabel, email)); err != nil {
		return err
	}

	var path string
	var err error
	if c.Direct {
		path, err = config.DirectServiceAccountPath(email)
	} else {
		path, err = config.ServiceAccountPath(email)
	}
	if err != nil {
		return err
	}

	if err := os.Remove(path); err != nil {
		if os.IsNotExist(err) {
			if outfmt.IsJSON(ctx) {
				return outfmt.WriteJSON(os.Stdout, map[string]any{
					"deleted": false,
					"email":   email,
					"path":    path,
				})
			}
			u.Out().Printf("deleted\tfalse")
			u.Out().Printf("email\t%s", email)
			u.Out().Printf("path\t%s", path)
			return nil
		}
		return fmt.Errorf("remove service account: %w", err)
	}

	if outfmt.IsJSON(ctx) {
		return outfmt.WriteJSON(os.Stdout, map[string]any{
			"deleted": true,
			"email":   email,
			"path":    path,
		})
	}
	u.Out().Printf("deleted\ttrue")
	u.Out().Printf("email\t%s", email)
	u.Out().Printf("path\t%s", path)
	return nil
}

type AuthServiceAccountStatusCmd struct {
	Email  string `arg:"" name:"email" help:"Email (impersonated user, or service account client_email with --direct)" required:""`
	Direct bool   `name:"direct" help:"Check direct service account key status"`
}

func (c *AuthServiceAccountStatusCmd) Run(ctx context.Context) error {
	u := ui.FromContext(ctx)

	email := strings.TrimSpace(c.Email)
	if email == "" {
		return usage("empty email")
	}

	var path string
	var err error
	if c.Direct {
		path, err = config.DirectServiceAccountPath(email)
	} else {
		path, err = config.ServiceAccountPath(email)
	}
	if err != nil {
		return err
	}

	mode := "delegation"
	if c.Direct {
		mode = "direct"
	}

	data, err := os.ReadFile(path) //nolint:gosec // stored in user config dir
	if err != nil {
		if os.IsNotExist(err) {
			if outfmt.IsJSON(ctx) {
				return outfmt.WriteJSON(os.Stdout, map[string]any{
					"email":   email,
					"path":    path,
					"exists":  false,
					"stored":  false,
					"mode":    mode,
					"message": "no service account configured",
				})
			}
			u.Out().Printf("email\t%s", email)
			u.Out().Printf("path\t%s", path)
			u.Out().Printf("mode\t%s", mode)
			u.Out().Printf("exists\tfalse")
			return nil
		}
		return fmt.Errorf("read service account: %w", err)
	}

	info, parseErr := parseServiceAccountJSON(data)
	if parseErr != nil {
		return parseErr
	}

	if outfmt.IsJSON(ctx) {
		return outfmt.WriteJSON(os.Stdout, map[string]any{
			"email":        email,
			"path":         path,
			"exists":       true,
			"stored":       true,
			"mode":         mode,
			"client_email": info.ClientEmail,
			"client_id":    info.ClientID,
		})
	}
	u.Out().Printf("email\t%s", email)
	u.Out().Printf("path\t%s", path)
	u.Out().Printf("mode\t%s", mode)
	u.Out().Printf("exists\ttrue")
	if info.ClientEmail != "" {
		u.Out().Printf("client_email\t%s", info.ClientEmail)
	}
	if info.ClientID != "" {
		u.Out().Printf("client_id\t%s", info.ClientID)
	}
	return nil
}
