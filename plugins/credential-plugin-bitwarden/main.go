package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"

	"github.com/CliffJumper/secure-backup/pkg/credentials"
	"github.com/hashicorp/go-plugin"
)

type BWProvider struct{}

func (b *BWProvider) GetCredentials(target string) (map[string]string, error) {
	cmd := exec.Command("bw", "get", "item", target, "--nointeraction")
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("failed to retrieve bitwarden item '%s': %v\nError output: %s\n(Did you forget to 'export BW_SESSION=...' or unlock your vault?)", target, err, stderr.String())
	}

	out := stdout.Bytes()
	if len(bytes.TrimSpace(out)) == 0 {
		return nil, fmt.Errorf("bitwarden returned empty output for item '%s'.\nError/Warning output: %s\n(Did you forget to 'export BW_SESSION=...' or unlock your vault?)", target, stderr.String())
	}

	var item struct {
		Notes  string `json:"notes"`
		Fields []struct {
			Name  string `json:"name"`
			Value string `json:"value"`
		} `json:"fields"`
	}

	if err := json.Unmarshal(out, &item); err != nil {
		return nil, fmt.Errorf("failed to parse bitwarden item JSON: %v", err)
	}

	var jsonString string
	for _, f := range item.Fields {
		if strings.EqualFold(f.Name, "Additional options") || strings.Contains(f.Value, "keyID") {
			jsonString = f.Value
			break
		}
	}

	if jsonString == "" && item.Notes != "" {
		jsonString = item.Notes
	}

	if jsonString == "" {
		return nil, fmt.Errorf("no credentials JSON found in item '%s'", target)
	}

	var creds map[string]interface{}
	if err := json.Unmarshal([]byte(jsonString), &creds); err != nil {
		// Never echo secret material (the credentials JSON) in error messages.
		return nil, fmt.Errorf("failed to decode credentials JSON from bitwarden item %q: %v (refusing to print credential payload; ensure the item contains valid JSON in Notes or an \"Additional options\" field)", target, err)
	}

	result := make(map[string]string)
	for k, v := range creds {
		if str, ok := v.(string); ok {
			result[k] = str
		}
	}

	return result, nil
}

func main() {
	plugin.Serve(&plugin.ServeConfig{
		HandshakeConfig: credentials.HandshakeConfig,
		Plugins: map[string]plugin.Plugin{
			"provider": &credentials.ProviderGRPCPlugin{
				Impl: &BWProvider{},
			},
		},
		GRPCServer: plugin.DefaultGRPCServer,
	})
}
