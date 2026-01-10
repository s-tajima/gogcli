package cmd

import (
	"os"
	"strings"

	"github.com/steipete/gogcli/internal/secrets"
)

var openSecretsStoreForAccount = secrets.OpenDefault

func requireAccount(flags *RootFlags) (string, error) {
	if v := strings.TrimSpace(flags.Account); v != "" {
		return v, nil
	}
	if v := strings.TrimSpace(os.Getenv("GOG_ACCOUNT")); v != "" {
		return v, nil
	}

	if store, err := openSecretsStoreForAccount(); err == nil {
		if v, err := store.GetDefaultAccount(); err == nil {
			if v := strings.TrimSpace(v); v != "" {
				return v, nil
			}
		}
		if toks, err := store.ListTokens(); err == nil {
			if len(toks) == 1 {
				if v := strings.TrimSpace(toks[0].Email); v != "" {
					return v, nil
				}
			}
		}
	}

	return "", usage("missing --account (or set GOG_ACCOUNT, set default via `gog auth manage`, or store exactly one token)")
}
