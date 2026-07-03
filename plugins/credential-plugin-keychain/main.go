package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"

	"github.com/CliffJumper/secure-backup/pkg/credentials"
	"github.com/hashicorp/go-plugin"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type KeychainProvider struct{}

func (k *KeychainProvider) GetCredentials(target string) (map[string]string, error) {
	cmd := exec.Command("security", "find-generic-password", "-s", target, "-w")
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok && exitErr.ExitCode() == 44 {
			return nil, status.Error(codes.NotFound, "keychain item not found")
		}
		if strings.Contains(stderr.String(), "could not be found") {
			return nil, status.Error(codes.NotFound, "keychain item not found")
		}
		return nil, fmt.Errorf("failed to retrieve keychain item '%s': %v\nError output: %s\n(Did you create the generic password in macOS Keychain explicitly?)", target, err, stderr.String())
	}


	out := stdout.Bytes()
	if len(bytes.TrimSpace(out)) == 0 {
		return nil, fmt.Errorf("keychain returned empty output for item '%s'", target)
	}

	var creds map[string]interface{}
	if err := json.Unmarshal(out, &creds); err != nil {
		// Never echo secret material (the keychain password / credential JSON) in error messages.
		return nil, fmt.Errorf("failed to decode credentials JSON from keychain item %q: %v (refusing to print credential payload; ensure the Keychain item password is valid JSON)", target, err)
	}

	result := make(map[string]string)
	for key, v := range creds {
		if str, ok := v.(string); ok {
			result[key] = str
		}
	}

	return result, nil
}

func (k *KeychainProvider) SetCredentials(target string, creds map[string]string) error {
	data, err := json.Marshal(creds)
	if err != nil {
		return fmt.Errorf("failed to serialize credentials: %w", err)
	}

	// -U updates the item if it already exists, -s is service, -a is account, -w is the password data (JSON string)
	cmd := exec.Command("security", "add-generic-password", "-s", target, "-a", target, "-w", string(data), "-U")
	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to update keychain item '%s': %v\nError output: %s", target, err, stderr.String())
	}
	return nil
}

func main() {
	plugin.Serve(&plugin.ServeConfig{
		HandshakeConfig: credentials.HandshakeConfig,
		Plugins: map[string]plugin.Plugin{
			"provider": &credentials.ProviderGRPCPlugin{
				Impl: &KeychainProvider{},
			},
		},
		GRPCServer: plugin.DefaultGRPCServer,
	})
}
