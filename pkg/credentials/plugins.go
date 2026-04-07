package credentials

import (
	"context"

	"github.com/freew/secure-backup/pkg/credentials/proto"
	"github.com/hashicorp/go-plugin"
	"google.golang.org/grpc"
)

var HandshakeConfig = plugin.HandshakeConfig{
	ProtocolVersion:  1,
	MagicCookieKey:   "CREDENTIAL_PLUGIN",
	MagicCookieValue: "hello",
}

type Provider interface {
	GetCredentials(target string) (map[string]string, error)
}

var PluginMap = map[string]plugin.Plugin{
	"provider": &ProviderGRPCPlugin{},
}

type ProviderGRPCPlugin struct {
	plugin.Plugin
	Impl Provider
}

func (p *ProviderGRPCPlugin) GRPCServer(broker *plugin.GRPCBroker, s *grpc.Server) error {
	proto.RegisterCredentialProviderServer(s, &GRPCServer{Impl: p.Impl})
	return nil
}

func (p *ProviderGRPCPlugin) GRPCClient(ctx context.Context, broker *plugin.GRPCBroker, c *grpc.ClientConn) (interface{}, error) {
	return &GRPCClient{client: proto.NewCredentialProviderClient(c)}, nil
}
