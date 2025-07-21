package main

import (
	"context"
	"fmt"
	"os"
	"strings"

	vault "github.com/hashicorp/vault/api"
)

// VaultCredentials holds the information needed to connect to a device.
type VaultCredentials struct {
	Host         string
	Username     string
	Password     string
	EnableSecret string
}

// NewVaultClient creates and configures a new Vault client from environment variables.
func NewVaultClient() (*vault.Client, error) {
	// We require that VAULT_ADDR and VAULT_TOKEN are set in the environment.
	// This avoids hardcoding secrets and connection details.
	if os.Getenv("VAULT_TOKEN") == "" {
		return nil, fmt.Errorf("VAULT_TOKEN environment variable not set. Please source the vault_environment_variables.sh script")
	}
	if os.Getenv("VAULT_ADDR") == "" {
		return nil, fmt.Errorf("VAULT_ADDR environment variable not set. Please source the vault_environment_variables.sh script")
	}

	config := vault.DefaultConfig() // Reads VAULT_ADDR, etc. from environment variables
	if os.Getenv("VAULT_SKIP_VERIFY") == "true" {
		tlsConfig := &vault.TLSConfig{Insecure: true}
		if err := config.ConfigureTLS(tlsConfig); err != nil {
			return nil, fmt.Errorf("failed to configure TLS for vault: %w", err)
		}
	}
	client, err := vault.NewClient(config)
	if err != nil {
		return nil, fmt.Errorf("failed to create vault client: %w", err)
	}
	// The token is read from the environment by DefaultConfig, but this ensures it is set.
	client.SetToken(os.Getenv("VAULT_TOKEN"))
	return client, nil
}

// GetVaultCredentials fetches a secret from Vault and returns the credentials.
// It assumes the secret contains 'host', 'username', and 'password' keys.
func GetVaultCredentials(client *vault.Client, path string) (*VaultCredentials, error) {
	// The KVv2 engine's Get method expects the path without the "kv/data/" prefix.
	secretPath := strings.TrimPrefix(path, "kv/data/")

	secret, err := client.KVv2("kv").Get(context.Background(), secretPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read secret from vault at path %s: %w", path, err)
	}

	if secret == nil {
		return nil, fmt.Errorf("secret not found (or is empty) at path: %s", path)
	}

	creds := &VaultCredentials{
		Host:         fmt.Sprintf("%v", secret.Data["host"]),
		Username:     fmt.Sprintf("%v", secret.Data["username"]),
		Password:     fmt.Sprintf("%v", secret.Data["password"]),
		EnableSecret: fmt.Sprintf("%v", secret.Data["enable_secret"]),
	}

	return creds, nil
}