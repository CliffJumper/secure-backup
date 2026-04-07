package plugins

import (
	"context"
	"os"
	"strconv"
	"time"

	"github.com/freew/secure-backup/pkg/plugins/proto"
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

var (
	initTimeout    = envDurationSeconds("SECURE_BACKUP_PLUGIN_INIT_TIMEOUT_SECONDS", 30*time.Second)
	listTimeout    = envDurationSeconds("SECURE_BACKUP_PLUGIN_LIST_TIMEOUT_SECONDS", 30*time.Second)
	deleteTimeout  = envDurationSeconds("SECURE_BACKUP_PLUGIN_DELETE_TIMEOUT_SECONDS", 2*time.Minute)
	uploadTimeout  = envDurationSeconds("SECURE_BACKUP_PLUGIN_UPLOAD_TIMEOUT_SECONDS", 30*time.Minute)
	downloadTimeout = envDurationSeconds("SECURE_BACKUP_PLUGIN_DOWNLOAD_TIMEOUT_SECONDS", 30*time.Minute)
)

// GRPCClient is an implementation of Provider that talks over RPC.
type GRPCClient struct {
	client proto.ProviderClient
}

func (m *GRPCClient) Init(config map[string]string) error {
	ctx, cancel := context.WithTimeout(context.Background(), initTimeout)
	defer cancel()
	_, err := m.client.Init(ctx, &proto.InitRequest{
		Config: config,
	})
	return err
}

func (m *GRPCClient) UploadFile(localPath, remotePath string) error {
	ctx, cancel := context.WithTimeout(context.Background(), uploadTimeout)
	defer cancel()
	_, err := m.client.UploadFile(ctx, &proto.UploadRequest{
		LocalPath:  localPath,
		RemotePath: remotePath,
	})
	return err
}

func (m *GRPCClient) DownloadFile(remotePath, localPath string) error {
	ctx, cancel := context.WithTimeout(context.Background(), downloadTimeout)
	defer cancel()
	_, err := m.client.DownloadFile(ctx, &proto.DownloadRequest{
		RemotePath: remotePath,
		LocalPath:  localPath,
	})
	return err
}

func (m *GRPCClient) ListFiles(prefix string) ([]string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), listTimeout)
	defer cancel()
	resp, err := m.client.ListFiles(ctx, &proto.ListRequest{
		Prefix: prefix,
	})
	if err != nil {
		return nil, err
	}
	return resp.Files, nil
}

func (m *GRPCClient) DeleteFile(remotePath string) error {
	ctx, cancel := context.WithTimeout(context.Background(), deleteTimeout)
	defer cancel()
	_, err := m.client.DeleteFile(ctx, &proto.DeleteRequest{
		RemotePath: remotePath,
	})
	return err
}

// GRPCServer is the gRPC server that GRPCClient talks to.
type GRPCServer struct {
	proto.UnimplementedProviderServer
	Impl Provider
}

func (m *GRPCServer) Init(ctx context.Context, req *proto.InitRequest) (*proto.Empty, error) {
	err := m.Impl.Init(req.Config)
	return &proto.Empty{}, err
}

func (m *GRPCServer) UploadFile(ctx context.Context, req *proto.UploadRequest) (*proto.Empty, error) {
	err := m.Impl.UploadFile(req.LocalPath, req.RemotePath)
	return &proto.Empty{}, err
}

func (m *GRPCServer) DownloadFile(ctx context.Context, req *proto.DownloadRequest) (*proto.Empty, error) {
	err := m.Impl.DownloadFile(req.RemotePath, req.LocalPath)
	return &proto.Empty{}, err
}

func (m *GRPCServer) ListFiles(ctx context.Context, req *proto.ListRequest) (*proto.ListResponse, error) {
	files, err := m.Impl.ListFiles(req.Prefix)
	if err != nil {
		return nil, err
	}
	return &proto.ListResponse{Files: files}, nil
}

func (m *GRPCServer) DeleteFile(ctx context.Context, req *proto.DeleteRequest) (*proto.Empty, error) {
	err := m.Impl.DeleteFile(req.RemotePath)
	return &proto.Empty{}, err
}
