package plugins

import (
	"context"

	"github.com/freew/secure-backup/pkg/plugins/proto"
	"github.com/hashicorp/go-plugin"
	"google.golang.org/grpc"
)

// HandshakeConfig is a common handshake that is shared by plugin and host.
var HandshakeConfig = plugin.HandshakeConfig{
	ProtocolVersion:  1,
	MagicCookieKey:   "BACKUP_PLUGIN",
	MagicCookieValue: "hello",
}

// Provider is the interface that we're exposing as a plugin.
type Provider interface {
	Init(config map[string]string) error
	UploadFile(localPath, remotePath string) error
	DownloadFile(remotePath, localPath string) error
	ListFiles(prefix string) ([]string, error)
	DeleteFile(remotePath string) error
}

// PluginMap is the map of plugins we can dispense.
var PluginMap = map[string]plugin.Plugin{
	"provider": &ProviderGRPCPlugin{},
}

// ProviderGRPCPlugin implements the plugin.GRPCPlugin interface.
type ProviderGRPCPlugin struct {
	plugin.Plugin
	Impl Provider
}

// GRPCServer registers the gRPC server implementation for the provider.
func (p *ProviderGRPCPlugin) GRPCServer(broker *plugin.GRPCBroker, s *grpc.Server) error {
	proto.RegisterProviderServer(s, &GRPCServer{Impl: p.Impl})
	return nil
}

// GRPCClient returns the grpc-backed provider implementation.
func (p *ProviderGRPCPlugin) GRPCClient(ctx context.Context, broker *plugin.GRPCBroker, c *grpc.ClientConn) (interface{}, error) {
	return &GRPCClient{client: proto.NewProviderClient(c)}, nil
}
