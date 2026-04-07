package credentials

import (
	"context"
	"os"
	"strconv"
	"time"

	"github.com/freew/secure-backup/pkg/credentials/proto"
)

func envDurationSeconds(key string, def time.Duration) time.Duration {
	v := os.Getenv(key)
	if v == "" {
		return def
	}
	secs, err := strconv.Atoi(v)
	if err != nil || secs <= 0 {
		return def
	}
	return time.Duration(secs) * time.Second
}

var credTimeout = envDurationSeconds("SECURE_BACKUP_CRED_PLUGIN_TIMEOUT_SECONDS", 30*time.Second)

type GRPCClient struct {
	client proto.CredentialProviderClient
}

func (m *GRPCClient) GetCredentials(target string) (map[string]string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), credTimeout)
	defer cancel()
	resp, err := m.client.GetCredentials(ctx, &proto.GetRequest{
		Target: target,
	})
	if err != nil {
		return nil, err
	}
	return resp.Credentials, nil
}

type GRPCServer struct {
	proto.UnimplementedCredentialProviderServer
	Impl Provider
}

func (m *GRPCServer) GetCredentials(ctx context.Context, req *proto.GetRequest) (*proto.GetResponse, error) {
	creds, err := m.Impl.GetCredentials(req.Target)
	if err != nil {
		return nil, err
	}
	return &proto.GetResponse{Credentials: creds}, nil
}
