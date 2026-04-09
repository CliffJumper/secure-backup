package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os/exec"

	"github.com/CliffJumper/secure-backup/pkg/credentials"
	"github.com/hashicorp/go-plugin"
)

type KeychainProvider struct{}

func (k *KeychainProvider) GetCredentials(target string) (map[string]string, error) {
	cmd := exec.Command("security", "find-generic-password", "-s", target, "-w")
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
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
