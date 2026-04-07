package main

import (
	"bufio"
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"

	"github.com/freew/secure-backup/pkg/archive"
	"github.com/freew/secure-backup/pkg/credentials"
	"github.com/freew/secure-backup/pkg/encrypt"
	"github.com/freew/secure-backup/pkg/manifest"
	"github.com/freew/secure-backup/pkg/plugins"
	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/go-plugin"
	"github.com/spf13/cobra"
	"golang.org/x/term"
	"google.golang.org/grpc/status"
)

var (
	password          []byte
	passwordFlag      string
	fileListFile      string
	remotePrefix      string
	restoreAll        bool
	deleteAll         bool
	force             bool
	verbose           bool
	stripPrefix       string
	destDir           string
	credPlugin        string
	credItem          string
	pluginOpts        map[string]string

	// New flags for plugins
	pluginFlag string
	pluginDir  string

	// Embedded public key for plugin verification
	trustedPublicKeyB64 = "5XNxNN0zGdS4KOZvhrHcSv6LuUfvjMnqXbSr+CrIYTU="
)

func main() {
	var rootCmd = &cobra.Command{
		Use:   "secure-backup",
		Short: "Backup tool with encryption and plugin support",
	}

	rootCmd.PersistentFlags().StringVarP(&pluginFlag, "plugin", "", "backblaze", "Plugin to use for backup destination (e.g., backblaze, local)")
	rootCmd.PersistentFlags().StringVarP(&credPlugin, "cred-plugin", "", "", "Plugin to use for credentials (e.g., bitwarden, keychain)")
	rootCmd.PersistentFlags().StringVarP(&credItem, "cred-item", "", "", "Target item name or ID to pass to the credential plugin")
	rootCmd.PersistentFlags().StringToStringVarP(&pluginOpts, "plugin-opt", "O", nil, "Plugin specific options (key=value)")
	rootCmd.PersistentFlags().StringVarP(&passwordFlag, "password", "p", os.Getenv("BACKUP_PASSWORD"), "Password for symmetric encryption")
	rootCmd.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "Enable verbose plugin logging")
	rootCmd.PersistentFlags().StringVar(&pluginDir, "plugin-dir", os.Getenv("SECURE_BACKUP_PLUGIN_DIR"), "Explicit directory containing plugin binaries (e.g. ./plugins during development)")

	var backupCmd = &cobra.Command{
		Use:   "backup [file1] [dir1] ...",
		Short: "Backup files and folders via plugin",
		Run:   runBackup,
	}
	backupCmd.Flags().StringVar(&fileListFile, "filelist", "", "Path to a filelist file containing list of files/folders to backup")
	backupCmd.Flags().StringVarP(&remotePrefix, "prefix", "x", "", "Prefix for the remote path")

	var restoreCmd = &cobra.Command{
		Use:   "restore [remoteFile1] ...",
		Short: "Restore and decrypt files via plugin",
		Run:   runRestore,
	}
	restoreCmd.Flags().StringVarP(&remotePrefix, "prefix", "x", "", "Prefix for the remote chunk paths in the destination bucket")
	restoreCmd.Flags().StringVarP(&stripPrefix, "strip-prefix", "s", "", "Prefix to strip from the archive paths when extracting files locally")
	restoreCmd.Flags().StringVarP(&destDir, "dest", "d", ".", "Destination directory to extract files to")
	restoreCmd.Flags().BoolVarP(&restoreAll, "all", "a", false, "Restore everything in the bucket")

	var deleteCmd = &cobra.Command{
		Use:   "delete [remoteFile1] ...",
		Short: "Delete objects via plugin",
		Long: `Delete objects from the destination.

Objects to delete can be specified as positional arguments (exact remote paths),
via --prefix to match all objects under a prefix, via --manifest to read remote
paths from a file, or via --all to empty the entire bucket.

Multiple sources can be combined (e.g. --prefix and positional args together).`,
		Run: runDelete,
	}
	deleteCmd.Flags().BoolVarP(&deleteAll, "all", "a", false, "Delete every object in the bucket")
	deleteCmd.Flags().StringVarP(&remotePrefix, "prefix", "x", "", "Delete all objects whose remote path starts with this prefix")
	deleteCmd.Flags().StringVar(&fileListFile, "filelist", "", "Path to a filelist file listing remote object paths to delete")
	deleteCmd.Flags().BoolVarP(&force, "force", "f", false, "Skip confirmation prompt")

	var listCmd = &cobra.Command{
		Use:   "list",
		Short: "List files tracked in the backup manifest",
		Run:   runList,
	}

	rootCmd.AddCommand(backupCmd, restoreCmd, deleteCmd, listCmd)

	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func ensureAuth() {
	if len(password) == 0 {
		if passwordFlag != "" {
			password = []byte(passwordFlag)
		} else {
			fmt.Print("Enter encryption password: ")
			bytePassword, err := term.ReadPassword(int(syscall.Stdin))
			if err != nil {
				log.Fatalf("Failed to read password: %v", err)
			}
			password = bytePassword
			fmt.Println()
		}

		if len(password) == 0 {
			log.Fatal("Password is required")
		}
	}
}

func findPlugin(prefix, name string) (string, error) {
	binaryName := prefix + "-" + name

	var searchPaths []string

	// 0. Explicit override for development/testing.
	// This is intentionally opt-in (vs searching CWD) to avoid plugin binary hijacking.
	if pluginDir != "" {
		if abs, err := filepath.Abs(pluginDir); err == nil {
			searchPaths = append(searchPaths, filepath.Join(abs, binaryName))
		} else {
			searchPaths = append(searchPaths, filepath.Join(pluginDir, binaryName))
		}
	}

	// 1. Executable directory ./plugins
	if execPath, err := os.Executable(); err == nil {
		searchPaths = append(searchPaths, filepath.Join(filepath.Dir(execPath), "build", "plugins", binaryName))
	}

	// 2. User config directory ~/.config/secure-backup/plugins (or equivalent per OS)
	if configDir, err := os.UserConfigDir(); err == nil {
		searchPaths = append(searchPaths, filepath.Join(configDir, "secure-backup", "plugins", binaryName))
	}

	// 3. System-wide directory /usr/local/lib/secure-backup/plugins
	searchPaths = append(searchPaths, filepath.Join("/usr", "local", "lib", "secure-backup", "plugins", binaryName))

	for _, p := range searchPaths {
		// Refuse any symlinked path components to prevent path redirection.
		if runtime.GOOS != "windows" {
			cur := string(filepath.Separator)
			for _, part := range strings.Split(filepath.Clean(p), string(filepath.Separator)) {
				if part == "" {
					continue
				}
				cur = filepath.Join(cur, part)
				fi, err := os.Lstat(cur)
				if err != nil {
					break // we'll fail later on the file itself
				}
				if fi.Mode()&os.ModeSymlink != 0 {
					cur = "" // mark as invalid
					break
				}
				// Refuse group/world-writable directories in the path.
				if fi.IsDir() && fi.Mode().Perm()&0o022 != 0 {
					cur = ""
					break
				}
			}
			if cur == "" {
				continue
			}
		}

		fi, err := os.Lstat(p)
		if err != nil || fi.IsDir() {
			continue
		}

		// Refuse to execute symlinks to avoid plugin path hijacking.
		if fi.Mode()&os.ModeSymlink != 0 {
			continue
		}

		// Refuse group/world-writable plugin binaries.
		if fi.Mode().Perm()&0o022 != 0 {
			continue
		}

		// On unix-like systems, require the plugin file to be owned by the current user or root.
		// This allows normal system installs under /usr/local while still rejecting other-user-owned files.
		if runtime.GOOS != "windows" {
			if st, ok := fi.Sys().(*syscall.Stat_t); ok {
				if int(st.Uid) != os.Getuid() && st.Uid != 0 {
					continue
				}
			}
		}

		// Verify Plugin Signature
		pubKey, err := base64.StdEncoding.DecodeString(trustedPublicKeyB64)
		if err != nil {
			log.Fatalf("Invalid embedded public key: %v", err)
		}

		sigPath := p + ".sig"
		sig, err := os.ReadFile(sigPath)
		if err != nil {
			continue // signature missing
		}

		pluginBytes, err := os.ReadFile(p)
		if err != nil {
			continue
		}

		if !ed25519.Verify(pubKey, pluginBytes, sig) {
			log.Printf("WARNING: Plugin %s has an invalid signature. Skipping.", p)
			continue
		}

		return p, nil
	}

	return "", fmt.Errorf("plugin '%s' not found (or was rejected due to unsafe permissions/ownership) in any standard locations", binaryName)
}

func initPlugin() (plugins.Provider, func()) {
	var credCleanup func()
	if credPlugin != "" {
		if credItem == "" {
			log.Fatal("Error: --cred-item must be specified when using --cred-plugin")
		}

		credPluginPath, err := findPlugin("credential-plugin", credPlugin)
		if err != nil {
			log.Fatalf("Credential plugin resolution failed. Error: %v", err)
		}

		logger := hclog.NewNullLogger()
		if verbose {
			logger = hclog.Default()
		}

		client := plugin.NewClient(&plugin.ClientConfig{
			HandshakeConfig:  credentials.HandshakeConfig,
			Plugins:          credentials.PluginMap,
			Cmd:              exec.Command(credPluginPath),
			AllowedProtocols: []plugin.Protocol{plugin.ProtocolGRPC},
			Logger:           logger,
		})

		rpcClient, err := client.Client()
		if err != nil {
			log.Fatalf("Error connecting to credential plugin: %v", err)
		}

		raw, err := rpcClient.Dispense("provider")
		if err != nil {
			log.Fatalf("Error dispensing credential plugin: %v", err)
		}

		provider := raw.(credentials.Provider)

		fmt.Printf("Fetching credentials via %s (target: %s)...\n", credPlugin, credItem)
		creds, err := provider.GetCredentials(credItem)
		if err != nil {
			log.Fatalf("Failed to retrieve credentials via plugin %s: %v", credPlugin, err)
		}

		// Map all dynamically resolved credentials directly to plugin options
		for k, v := range creds {
			if pluginOpts == nil {
				pluginOpts = make(map[string]string)
			}
			// Don't overwrite explicit CLI `--plugin-opt` overrides
			if _, exists := pluginOpts[k]; !exists {
				pluginOpts[k] = v
			}
		}

		credCleanup = func() {
			client.Kill()
		}
	}

	pluginName := pluginFlag
	if pluginName == "" {
		pluginName = "backblaze"
	}

	pluginPath, err := findPlugin("storage-plugin", pluginName)
	if err != nil {
		log.Fatalf("Plugin resolution failed. Error: %v", err)
	}

	logger := hclog.NewNullLogger()
	if verbose {
		logger = hclog.Default()
	}

	client := plugin.NewClient(&plugin.ClientConfig{
		HandshakeConfig:  plugins.HandshakeConfig,
		Plugins:          plugins.PluginMap,
		Cmd:              exec.Command(pluginPath),
		AllowedProtocols: []plugin.Protocol{plugin.ProtocolGRPC},
		Logger:           logger,
	})

	rpcClient, err := client.Client()
	if err != nil {
		log.Fatalf("Error connecting to plugin: %v", err)
	}

	raw, err := rpcClient.Dispense("provider")
	if err != nil {
		log.Fatalf("Error dispensing plugin: %v", err)
	}

	provider := raw.(plugins.Provider)

	if err := provider.Init(pluginOpts); err != nil {
		if st, ok := status.FromError(err); ok {
			log.Fatalf("Failed to initialize plugin %s: %s", pluginName, st.Message())
		} else {
			log.Fatalf("Failed to initialize plugin %s: %v", pluginName, err)
		}
	}

	return provider, func() {
		if credCleanup != nil {
			credCleanup()
		}
		client.Kill()
	}
}

func runBackup(cmd *cobra.Command, args []string) {
	ensureAuth()

	provider, cleanup := initPlugin()
	defer cleanup()

	var targets []string
	targets = append(targets, args...)

	if fileListFile != "" {
		fileListTargets, err := parseFileList(fileListFile)
		if err != nil {
			log.Fatalf("Failed to parse filelist: %v", err)
		}
		targets = append(targets, fileListTargets...)
	}

	if len(targets) == 0 {
		log.Fatal("No files or folders specified for backup")
	}

	fmt.Println("Downloading manifest...")
	m, err := manifest.DownloadAndDecrypt(provider, password)
	if err != nil {
		log.Fatalf("Failed to retrieve manifest. Make sure credentials match plugin requirements: %v", err)
	}

	arc, err := archive.NewArchiver()
	if err != nil {
		log.Fatalf("Failed to initialize archiver: %v", err)
	}

	for _, target := range targets {
		fmt.Printf("Processing %s...\n", target)
		if err := arc.Add(target); err != nil {
			log.Printf("Error processing target %s: %v", target, err)
		}
	}

	chunkDir, err := arc.Finalize()
	if err != nil {
		log.Fatalf("Failed to finalize chunks: %v", err)
	}
	defer os.RemoveAll(chunkDir)

	for _, chunkID := range arc.Chunks {
		localChunkPath := filepath.Join(chunkDir, chunkID+".tar.bz2")

		data, err := os.ReadFile(localChunkPath)
		if err != nil {
			log.Fatalf("Failed to read chunk %s: %v", chunkID, err)
		}

		encryptedData, err := encrypt.EncryptData(data, password)
		if err != nil {
			log.Fatalf("Failed to encrypt chunk %s: %v", chunkID, err)
		}
		encrypt.ZeroBytes(data)

		encChunkPath := localChunkPath + ".enc"
		if err := os.WriteFile(encChunkPath, encryptedData, 0600); err != nil {
			log.Fatalf("Failed to write encrypted chunk %s: %v", chunkID, err)
		}
		encrypt.ZeroBytes(encryptedData)

		remoteName := fmt.Sprintf("data-%s.enc", chunkID)
		remotePath := filepath.Join(remotePrefix, remoteName)
		remotePath = filepath.ToSlash(remotePath)

		fmt.Printf("Uploading chunk %s...\n", remoteName)
		if err := provider.UploadFile(encChunkPath, remotePath); err != nil {
			log.Fatalf("Failed to upload chunk %s: %v", chunkID, err)
		}

		m.Chunks = append(m.Chunks, chunkID)
	}

	for path, meta := range arc.Files {
		m.Files[path] = meta
	}

	fmt.Println("Updating manifest...")
	if err := manifest.EncryptAndUpload(provider, password, m); err != nil {
		log.Fatalf("Failed to upload updated manifest: %v", err)
	}

	encrypt.ZeroBytes(password)
	fmt.Println("Backup complete.")
}

func runRestore(cmd *cobra.Command, args []string) {
	if !restoreAll && len(args) == 0 {
		log.Fatal("No files or prefixes specified for restore. Use --all to restore everything.")
	}

	ensureAuth()

	provider, cleanup := initPlugin()
	defer cleanup()

	fmt.Println("Downloading manifest...")
	m, err := manifest.DownloadAndDecrypt(provider, password)
	if err != nil {
		log.Fatalf("Failed to retrieve manifest. Make sure credentials match plugin requirements: %v", err)
	}

	if len(m.Files) == 0 {
		fmt.Println("Manifest is empty. Nothing to restore.")
		return
	}

	if destDir == "" {
		destDir = "."
	}
	baseDir, err := filepath.Abs(destDir)
	if err != nil {
		log.Fatalf("Failed to resolve destination directory: %v", err)
	}

	chunksToDownload := make(map[string]map[string]bool)

	for path, meta := range m.Files {
		match := false
		if restoreAll {
			match = true
		} else {
			for _, arg := range args {
				if strings.HasPrefix(path, arg) {
					match = true
					break
				}
			}
		}

		if match {
			if _, ok := chunksToDownload[meta.ChunkID]; !ok {
				chunksToDownload[meta.ChunkID] = make(map[string]bool)
			}
			chunksToDownload[meta.ChunkID][path] = true
		}
	}

	if len(chunksToDownload) == 0 {
		fmt.Println("No matched files found in manifest for requested paths.")
		return
	}

	if stripPrefix != "" {
		ss := strings.TrimPrefix(filepath.ToSlash(filepath.Clean(stripPrefix)), "/")
		ssDir := ss
		if ssDir != "" && !strings.HasSuffix(ssDir, "/") {
			ssDir += "/"
		}

		matchedPrefix := false
	CheckPrefix:
		for _, files := range chunksToDownload {
			for path := range files {
				sn := strings.TrimPrefix(filepath.ToSlash(filepath.Clean(path)), "/")
				if strings.HasPrefix(sn, ssDir) || strings.HasPrefix(sn, ss) {
					matchedPrefix = true
					break CheckPrefix
				}
			}
		}

		if !matchedPrefix {
			log.Fatalf("Error: The strip-prefix '%s' was not found in any of the files selected for restoration. Please check your paths for typos or run the 'list' command to see available files.", stripPrefix)
		}
	}

	for chunkID, files := range chunksToDownload {
		remoteName := fmt.Sprintf("data-%s.enc", chunkID)
		remotePath := filepath.Join(remotePrefix, remoteName)
		remotePath = filepath.ToSlash(remotePath)

		localEncFile, err := os.CreateTemp("", "chunk-*.enc")
		if err != nil {
			log.Fatalf("Failed to create temp chunk file: %v", err)
		}
		tempPath := localEncFile.Name()
		localEncFile.Close()

		fmt.Printf("Downloading chunk %s...\n", chunkID)
		if err := provider.DownloadFile(remotePath, tempPath); err != nil {
			log.Printf("Failed to download chunk %s: %v", chunkID, err)
			os.Remove(tempPath)
			continue
		}

		fmt.Printf("Decrypting and extracting from chunk %s...\n", chunkID)
		encryptedData, err := os.ReadFile(tempPath)
		if err != nil {
			log.Printf("Failed to read downloaded chunk %s: %v", chunkID, err)
			os.Remove(tempPath)
			continue
		}

		chunkData, err := encrypt.DecryptData(encryptedData, password)
		encrypt.ZeroBytes(encryptedData)
		if err != nil {
			log.Printf("Failed to decrypt %s: %v", chunkID, err)
			os.Remove(tempPath)
			continue
		}

		if err := archive.Extract(chunkData, files, baseDir, stripPrefix); err != nil {
			log.Printf("Failed to extract from chunk %s: %v", chunkID, err)
		}

		encrypt.ZeroBytes(chunkData)
		os.Remove(tempPath)
	}

	encrypt.ZeroBytes(password)
	fmt.Println("Restore complete.")
}

func runDelete(cmd *cobra.Command, args []string) {
	if !deleteAll && remotePrefix == "" && fileListFile == "" && len(args) == 0 {
		log.Fatal("Nothing to delete: specify paths, --all")
	}

	ensureAuth()
	provider, cleanup := initPlugin()
	defer cleanup()

	fmt.Println("Downloading manifest...")
	m, err := manifest.DownloadAndDecrypt(provider, password)
	if err != nil {
		log.Fatalf("Failed to retrieve manifest. Make sure credentials match plugin requirements: %v", err)
	}

	targets := make(map[string]bool)

	if deleteAll {
		for f := range m.Files {
			targets[f] = true
		}
	} else {
		for _, arg := range args {
			for f := range m.Files {
				if strings.HasPrefix(f, arg) {
					targets[f] = true
				}
			}
		}

		if fileListFile != "" {
			fileListTargets, err := parseFileList(fileListFile)
			if err != nil {
				log.Fatalf("Failed to parse filelist: %v", err)
			}
			for _, target := range fileListTargets {
				for f := range m.Files {
					if strings.HasPrefix(f, target) {
						targets[f] = true
					}
				}
			}
		}
	}

	if len(targets) == 0 && !deleteAll {
		fmt.Println("No objects found matching the given criteria.")
		return
	}

	if !force {
		fmt.Printf("This will logically delete %d file(s) from the manifest.\n", len(targets))
		fmt.Print("Proceed? [y/N]: ")
		var response string
		fmt.Scanln(&response)
		if strings.ToLower(response) != "y" {
			fmt.Println("Delete cancelled.")
			return
		}
	}

	for f := range targets {
		delete(m.Files, f)
	}

	// Determine active chunks
	activeChunks := make(map[string]bool)
	for _, meta := range m.Files {
		activeChunks[meta.ChunkID] = true
	}

	// Remove orphaned chunks
	var newChunks []string
	var errCount int
	for _, chunkID := range m.Chunks {
		if !activeChunks[chunkID] && (deleteAll || len(targets) > 0) {
			remoteName := fmt.Sprintf("data-%s.enc", chunkID)
			remotePath := filepath.Join(remotePrefix, remoteName)
			remotePath = filepath.ToSlash(remotePath)

			if err := provider.DeleteFile(remotePath); err != nil {
				log.Printf("Failed to physically delete chunk %s: %v", chunkID, err)
				errCount++
				newChunks = append(newChunks, chunkID) // keep it if deletion failed
			} else {
				fmt.Printf("Deleted orphaned chunk %s\n", chunkID)
			}
		} else {
			newChunks = append(newChunks, chunkID)
		}
	}
	m.Chunks = newChunks

	if deleteAll {
		fmt.Println("Deleting manifest...")
		_ = provider.DeleteFile(filepath.ToSlash(manifest.RemoteManifestName))
		fmt.Println("Successfully deleted all backups.")
	} else {
		fmt.Println("Updating manifest...")
		if err := manifest.EncryptAndUpload(provider, password, m); err != nil {
			log.Fatalf("Failed to upload updated manifest: %v", err)
		}
		if errCount > 0 {
			log.Printf("%d chunks could not be cleanly removed.", errCount)
		} else {
			fmt.Printf("Successfully removed %d file(s).\n", len(targets))
		}
	}
	encrypt.ZeroBytes(password)
}

func runList(cmd *cobra.Command, args []string) {
	ensureAuth()
	provider, cleanup := initPlugin()
	defer cleanup()

	m, err := manifest.DownloadAndDecrypt(provider, password)
	if err != nil {
		log.Fatalf("Failed to download manifest: %v", err)
	}

	fmt.Println("Files tracked in backup:")
	for file, meta := range m.Files {
		fmt.Printf(" - %s (Size: %d bytes, Chunk: %s)\n", file, meta.Size, meta.ChunkID)
	}
	encrypt.ZeroBytes(password)
}

func parseFileList(path string) ([]string, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var targets []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" && !strings.HasPrefix(line, "#") {
			targets = append(targets, line)
		}
	}

	return targets, scanner.Err()
}
