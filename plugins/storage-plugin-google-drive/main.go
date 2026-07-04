package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/CliffJumper/secure-backup/pkg/plugins"
	"github.com/hashicorp/go-plugin"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	"google.golang.org/api/drive/v3"
	"google.golang.org/api/option"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type GDProvider struct {
	client           *drive.Service
	folderID         string
	tokenPath        string
	dirCache         map[string]string
	cacheMutex       sync.RWMutex
	latestToken      *oauth2.Token
	latestTokenMutex sync.RWMutex
	clientID         string
	clientSecret     string
}

type savingTokenSource struct {
	src       oauth2.TokenSource
	tokenPath string
	provider  *GDProvider
	mu        sync.Mutex
	lastToken *oauth2.Token
}

func (s *savingTokenSource) Token() (*oauth2.Token, error) {
	tok, err := s.src.Token()
	if err != nil {
		return nil, err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if s.lastToken == nil || s.lastToken.AccessToken != tok.AccessToken {
		s.lastToken = tok
		s.provider.updateLatestToken(tok)
		if s.tokenPath != "" {
			_ = s.provider.saveToken(s.tokenPath, tok)
		}
	}

	return tok, nil
}

func (g *GDProvider) updateLatestToken(token *oauth2.Token) {
	g.latestTokenMutex.Lock()
	defer g.latestTokenMutex.Unlock()
	g.latestToken = token
}

func (g *GDProvider) GetUpdatedConfig() (map[string]string, error) {
	g.latestTokenMutex.RLock()
	defer g.latestTokenMutex.RUnlock()

	if g.latestToken == nil {
		return nil, nil
	}

	data, err := json.Marshal(g.latestToken)
	if err != nil {
		return nil, err
	}

	return map[string]string{
		"client_id":          g.clientID,
		"client_secret":      g.clientSecret,
		"google_drive_token": string(data),
	}, nil
}


func (g *GDProvider) Init(config map[string]string) error {
	clientID := config["client_id"]
	if clientID == "" {
		clientID = os.Getenv("GOOGLE_DRIVE_CLIENT_ID")
	}
	clientSecret := config["client_secret"]
	if clientSecret == "" {
		clientSecret = os.Getenv("GOOGLE_DRIVE_CLIENT_SECRET")
	}

	if clientID == "" || clientSecret == "" {
		var out io.Writer = os.Stderr
		var in io.Reader = os.Stdin
		tty, ttyErr := os.OpenFile("/dev/tty", os.O_RDWR, 0)
		if ttyErr == nil {
			defer tty.Close()
			out = tty
			in = tty
		}

		if clientID == "" {
			fmt.Fprint(out, "Google Client ID is missing. Please enter your Google OAuth2 Client ID: ")
			var input string
			_, _ = fmt.Fscan(in, &input)
			clientID = strings.TrimSpace(input)
		}
		if clientSecret == "" {
			fmt.Fprint(out, "Google Client Secret is missing. Please enter your Google OAuth2 Client Secret: ")
			var input string
			_, _ = fmt.Fscan(in, &input)
			clientSecret = strings.TrimSpace(input)
		}
	}

	if clientID == "" || clientSecret == "" {
		return fmt.Errorf("client_id and client_secret are required for Google Drive storage plugin")
	}

	g.clientID = clientID
	g.clientSecret = clientSecret


	tokenPath := config["token_path"]
	if tokenPath == "" && config["google_drive_token"] == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return fmt.Errorf("failed to get user home directory: %w", err)
		}
		tokenPath = filepath.Join(home, ".config", "secure-backup", "google-drive-token.json")
	}
	g.tokenPath = tokenPath

	folderName := config["folder_name"]
	if folderName == "" {
		folderName = "secure-backup"
	}

	ctx := context.Background()
	oauthCfg := &oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		Endpoint:     google.Endpoint,
		Scopes:       []string{drive.DriveScope},
		RedirectURL:  "http://localhost:8085/oauth/callback",
	}

	if customPort := config["auth_port"]; customPort != "" {
		oauthCfg.RedirectURL = fmt.Sprintf("http://localhost:%s/oauth/callback", customPort)
	}

	token, err := g.loadToken(tokenPath, config)
	if err != nil {
		token, err = g.getInteractiveToken(ctx, oauthCfg)
		if err != nil {
			return fmt.Errorf("failed to authenticate via OAuth2: %w", err)
		}
		if tokenPath != "" {
			if err := g.saveToken(tokenPath, token); err != nil {
				log.Printf("Warning: failed to save token locally: %v", err)
			}
		}
	}

	g.updateLatestToken(token)

	tokenSrc := oauthCfg.TokenSource(ctx, token)
	autoSavingTokenSrc := &savingTokenSource{
		src:       tokenSrc,
		tokenPath: tokenPath,
		provider:  g,
	}

	driveService, err := drive.NewService(ctx, option.WithTokenSource(autoSavingTokenSrc))
	if err != nil {
		return fmt.Errorf("failed to create Google Drive service: %w", err)
	}

	g.client = driveService
	g.dirCache = make(map[string]string)

	folderID, err := g.resolveFolderID(ctx, folderName)
	if err != nil {
		return fmt.Errorf("failed to resolve/create backup folder %q: %w", folderName, err)
	}
	g.folderID = folderID

	return nil
}

func (g *GDProvider) loadToken(path string, config map[string]string) (*oauth2.Token, error) {
	if tokenJSON := config["google_drive_token"]; tokenJSON != "" {
		var tok oauth2.Token
		if err := json.Unmarshal([]byte(tokenJSON), &tok); err == nil {
			return &tok, nil
		}
	}

	if path == "" {
		return nil, errors.New("no token provided and no token path configured")
	}

	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var tok oauth2.Token
	err = json.NewDecoder(f).Decode(&tok)
	return &tok, err
}

func (g *GDProvider) saveToken(path string, token *oauth2.Token) error {
	if path == "" {
		return nil
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}
	defer f.Close()
	return json.NewEncoder(f).Encode(token)
}


func (g *GDProvider) getInteractiveToken(ctx context.Context, config *oauth2.Config) (*oauth2.Token, error) {
	port := "8085"
	if u := config.RedirectURL; u != "" {
		if idx := strings.LastIndex(u, ":"); idx != -1 {
			port = u[idx+1:]
			if slashIdx := strings.Index(port, "/"); slashIdx != -1 {
				port = port[:slashIdx]
			}
		}
	}

	codeChan := make(chan string)
	errChan := make(chan error)

	server := &http.Server{
		Addr:              "localhost:" + port,
		ReadHeaderTimeout: 3 * time.Second,
	}

	http.HandleFunc("/oauth/callback", func(w http.ResponseWriter, r *http.Request) {
		code := r.URL.Query().Get("code")
		if code == "" {
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprintln(w, "Error: Missing authorization code in callback.")
			errChan <- errors.New("missing code in callback")
			return
		}
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprintln(w, `<html><body style="font-family: sans-serif; text-align: center; padding-top: 50px; background-color: #121212; color: #ffffff;">
			<h1 style="color: #4CAF50;">Authorization Successful!</h1>
			<p>You can now close this tab and return to the terminal.</p>
		</body></html>`)
		codeChan <- code
	})

	go func() {
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			errChan <- fmt.Errorf("failed to start local callback server: %w", err)
		}
	}()

	authURL := config.AuthCodeURL("state-token", oauth2.AccessTypeOffline, oauth2.ApprovalForce)

	var out io.Writer = os.Stderr
	tty, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
	if err == nil {
		defer tty.Close()
		out = tty
	}

	fmt.Fprintln(out, "========================================================================")
	fmt.Fprintln(out, "GOOGLE DRIVE STORAGE PLUGIN: AUTHORIZATION REQUIRED")
	fmt.Fprintln(out, "========================================================================")
	fmt.Fprintln(out, "Please open the following link in your web browser to log in and authorize access:")
	fmt.Fprintln(out, authURL)
	fmt.Fprintln(out, "------------------------------------------------------------------------")

	openBrowser(authURL)

	fallbackChan := make(chan string)
	go func() {
		fmt.Fprint(out, "Or, if you are in a headless environment, paste the authorization code here: ")
		var code string
		if tty != nil {
			_, _ = fmt.Fscan(tty, &code)
		} else {
			_, _ = fmt.Fscan(os.Stdin, &code)
		}
		fallbackChan <- strings.TrimSpace(code)
	}()

	var code string
	select {
	case code = <-codeChan:
	case code = <-fallbackChan:
	case err := <-errChan:
		_ = server.Shutdown(ctx)
		return nil, err
	case <-time.After(5 * time.Minute):
		_ = server.Shutdown(ctx)
		return nil, errors.New("authorization timed out after 5 minutes")
	}

	_ = server.Shutdown(ctx)

	token, err := config.Exchange(ctx, code)
	if err != nil {
		return nil, fmt.Errorf("failed to exchange authorization code for token: %w", err)
	}

	fmt.Fprintln(out, "\nAuthorization complete!")
	fmt.Fprintln(out, "========================================================================")

	return token, nil
}

func openBrowser(url string) {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "darwin":
		cmd = exec.Command("open", url)
	case "linux":
		cmd = exec.Command("xdg-open", url)
	case "windows":
		cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", url)
	default:
		return
	}
	_ = cmd.Start()
}

func (g *GDProvider) resolveFolderID(ctx context.Context, folderName string) (string, error) {
	q := fmt.Sprintf("'root' in parents and name = '%s' and mimeType = 'application/vnd.google-apps.folder' and trashed = false", strings.ReplaceAll(folderName, "'", "\\'"))
	listCall := g.client.Files.List().Q(q).Spaces("drive").Fields("files(id, name)")
	res, err := listCall.Do()
	if err != nil {
		return "", err
	}

	if len(res.Files) > 0 {
		return res.Files[0].Id, nil
	}

	folder := &drive.File{
		Name:     folderName,
		MimeType: "application/vnd.google-apps.folder",
		Parents:  []string{"root"},
	}
	newFolder, err := g.client.Files.Create(folder).Fields("id").Do()
	if err != nil {
		return "", err
	}
	return newFolder.Id, nil
}

func (g *GDProvider) getOrCreateFolder(ctx context.Context, dirPath string) (string, error) {
	if dirPath == "" || dirPath == "." || dirPath == "/" {
		return g.folderID, nil
	}

	dirPath = filepath.Clean(dirPath)
	if strings.HasPrefix(dirPath, "/") {
		dirPath = dirPath[1:]
	}

	g.cacheMutex.RLock()
	id, ok := g.dirCache[dirPath]
	g.cacheMutex.RUnlock()
	if ok {
		return id, nil
	}

	parts := strings.Split(dirPath, "/")
	currentParentID := g.folderID

	g.cacheMutex.Lock()
	defer g.cacheMutex.Unlock()

	var currentPath string
	for _, part := range parts {
		if part == "" {
			continue
		}
		if currentPath == "" {
			currentPath = part
		} else {
			currentPath = currentPath + "/" + part
		}

		if cachedID, ok := g.dirCache[currentPath]; ok {
			currentParentID = cachedID
			continue
		}

		q := fmt.Sprintf("'%s' in parents and name = '%s' and mimeType = 'application/vnd.google-apps.folder' and trashed = false", currentParentID, strings.ReplaceAll(part, "'", "\\'"))
		res, err := g.client.Files.List().Q(q).Spaces("drive").Fields("files(id)").Do()
		if err != nil {
			return "", err
		}

		var folderID string
		if len(res.Files) > 0 {
			folderID = res.Files[0].Id
		} else {
			folder := &drive.File{
				Name:     part,
				MimeType: "application/vnd.google-apps.folder",
				Parents:  []string{currentParentID},
			}
			newFolder, err := g.client.Files.Create(folder).Fields("id").Do()
			if err != nil {
				return "", err
			}
			folderID = newFolder.Id
		}

		g.dirCache[currentPath] = folderID
		currentParentID = folderID
	}

	return currentParentID, nil
}

func (g *GDProvider) resolvePath(ctx context.Context, remotePath string) (string, string, error) {
	cleaned := filepath.Clean(remotePath)
	if strings.HasPrefix(cleaned, "..") || strings.Contains(cleaned, "/../") {
		return "", "", fmt.Errorf("path traversal detected in remote path: %s", remotePath)
	}

	dir := filepath.Dir(cleaned)
	if dir == "." || dir == "/" {
		dir = ""
	}
	base := filepath.Base(cleaned)
	if base == "." || base == "/" {
		return "", "", fmt.Errorf("invalid file path: %s", remotePath)
	}

	parentID, err := g.getOrCreateFolder(ctx, dir)
	if err != nil {
		return "", "", err
	}
	return parentID, base, nil
}

func (g *GDProvider) findFileID(ctx context.Context, parentID, name string) (string, error) {
	q := fmt.Sprintf("'%s' in parents and name = '%s' and mimeType != 'application/vnd.google-apps.folder' and trashed = false", parentID, strings.ReplaceAll(name, "'", "\\'"))
	res, err := g.client.Files.List().Q(q).Spaces("drive").Fields("files(id)").Do()
	if err != nil {
		return "", err
	}
	if len(res.Files) == 0 {
		return "", status.Error(codes.NotFound, "object not found")
	}
	return res.Files[0].Id, nil
}

func (g *GDProvider) UploadFile(localPath, remotePath string) error {
	ctx := context.Background()
	var lastErr error

	for i := 0; i < 3; i++ {
		err := g.doUpload(ctx, localPath, remotePath)
		if err == nil {
			return nil
		}
		lastErr = err
		log.Printf("Upload failed, retrying (%d/3)... err: %v", i+1, err)
		time.Sleep(2 * time.Second)
	}
	return fmt.Errorf("failed to upload after 3 retries: %w", lastErr)
}

func (g *GDProvider) doUpload(ctx context.Context, localPath, remotePath string) error {
	parentID, filename, err := g.resolvePath(ctx, remotePath)
	if err != nil {
		return err
	}

	f, err := os.Open(localPath)
	if err != nil {
		return fmt.Errorf("failed to open local file: %w", err)
	}
	defer f.Close()

	q := fmt.Sprintf("'%s' in parents and name = '%s' and mimeType != 'application/vnd.google-apps.folder' and trashed = false", parentID, strings.ReplaceAll(filename, "'", "\\'"))
	res, err := g.client.Files.List().Q(q).Spaces("drive").Fields("files(id)").Do()
	if err != nil {
		return fmt.Errorf("failed to check existing file: %w", err)
	}

	if len(res.Files) > 0 {
		fileID := res.Files[0].Id
		_, err = g.client.Files.Update(fileID, nil).Media(f).Do()
		if err != nil {
			return fmt.Errorf("failed to update existing file: %w", err)
		}
	} else {
		fileMetadata := &drive.File{
			Name:    filename,
			Parents: []string{parentID},
		}
		_, err = g.client.Files.Create(fileMetadata).Media(f).Do()
		if err != nil {
			return fmt.Errorf("failed to create new file: %w", err)
		}
	}

	return nil
}

func (g *GDProvider) DownloadFile(remotePath, localPath string) error {
	ctx := context.Background()
	var lastErr error

	for i := 0; i < 3; i++ {
		err := g.doDownload(ctx, remotePath, localPath)
		if err == nil {
			return nil
		}
		if st, ok := status.FromError(err); ok && st.Code() == codes.NotFound {
			return err
		}
		lastErr = err
		log.Printf("Download failed, retrying (%d/3)... err: %v", i+1, err)
		time.Sleep(2 * time.Second)
	}
	return fmt.Errorf("failed to download after 3 retries: %w", lastErr)
}

func (g *GDProvider) doDownload(ctx context.Context, remotePath, localPath string) error {
	parentID, filename, err := g.resolvePath(ctx, remotePath)
	if err != nil {
		return err
	}

	fileID, err := g.findFileID(ctx, parentID, filename)
	if err != nil {
		return err
	}

	resp, err := g.client.Files.Get(fileID).Download()
	if err != nil {
		return fmt.Errorf("failed to initiate download: %w", err)
	}
	defer resp.Body.Close()

	f, err := os.OpenFile(localPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return fmt.Errorf("failed to create local file: %w", err)
	}
	defer f.Close()

	if _, err := io.Copy(f, resp.Body); err != nil {
		return fmt.Errorf("failed to write file content: %w", err)
	}

	return nil
}

func (g *GDProvider) ListFiles(prefix string) ([]string, error) {
	ctx := context.Background()
	var files []string

	err := g.walkFolder(ctx, g.folderID, "", prefix, &files)
	if err != nil {
		return nil, fmt.Errorf("failed to list files: %w", err)
	}

	return files, nil
}

func (g *GDProvider) walkFolder(ctx context.Context, folderID string, currentPath string, prefix string, files *[]string) error {
	q := fmt.Sprintf("'%s' in parents and trashed = false", folderID)
	nextPageToken := ""
	for {
		listCall := g.client.Files.List().Q(q).Spaces("drive").Fields("nextPageToken, files(id, name, mimeType)")
		if nextPageToken != "" {
			listCall = listCall.PageToken(nextPageToken)
		}
		res, err := listCall.Do()
		if err != nil {
			return err
		}

		for _, file := range res.Files {
			var relPath string
			if currentPath == "" {
				relPath = file.Name
			} else {
				relPath = currentPath + "/" + file.Name
			}

			if file.MimeType == "application/vnd.google-apps.folder" {
				if strings.HasPrefix(prefix, relPath+"/") || strings.HasPrefix(relPath+"/", prefix) || prefix == "" {
					err := g.walkFolder(ctx, file.Id, relPath, prefix, files)
					if err != nil {
						return err
					}
				}
			} else {
				if strings.HasPrefix(relPath, prefix) {
					*files = append(*files, relPath)
				}
			}
		}

		nextPageToken = res.NextPageToken
		if nextPageToken == "" {
			break
		}
	}

	return nil
}

func (g *GDProvider) DeleteFile(remotePath string) error {
	ctx := context.Background()
	parentID, filename, err := g.resolvePath(ctx, remotePath)
	if err != nil {
		return err
	}

	fileID, err := g.findFileID(ctx, parentID, filename)
	if err != nil {
		if st, ok := status.FromError(err); ok && st.Code() == codes.NotFound {
			return nil
		}
		return err
	}

	err = g.client.Files.Delete(fileID).Do()
	if err != nil {
		return fmt.Errorf("failed to delete file: %w", err)
	}

	return nil
}

func main() {
	gdProvider := &GDProvider{}

	plugin.Serve(&plugin.ServeConfig{
		HandshakeConfig: plugins.HandshakeConfig,
		Plugins: map[string]plugin.Plugin{
			"provider": &plugins.ProviderGRPCPlugin{Impl: gdProvider},
		},
		GRPCServer: plugin.DefaultGRPCServer,
	})
}
