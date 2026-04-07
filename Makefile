.PHONY: all build install install-core install-plugins uninstall uninstall-core uninstall-plugins clean gen-security-keys sign-plugins

PREFIX ?= /usr/local
BINDIR ?= $(PREFIX)/bin
PLUGINDIR ?= $(PREFIX)/lib/secure-backup/plugins

PKG_GO_FILES := $(shell find ./pkg -type f -name '*.go')
CORE_GO_FILES := $(PKG_GO_FILES) main.go
CORE_BIN := build/bin/secure-backup

PLUGIN_DIRS := $(wildcard plugins/*)
PLUGIN_BINS := $(patsubst plugins/%,build/plugins/%,$(PLUGIN_DIRS))

all: build

build: $(CORE_BIN) $(PLUGIN_BINS) sign-plugins
	@echo "Build complete! Binaries are located in build/"

$(CORE_BIN): $(CORE_GO_FILES) go.mod go.sum
	@echo " -> Compiling core binary..."
	@mkdir -p build/bin
	@go mod tidy
	@go build -o $(CORE_BIN) .

.SECONDEXPANSION:
build/plugins/%: $$(wildcard plugins/%/*.go) plugins/%/go.mod plugins/%/Makefile $(PKG_GO_FILES)
	@echo " -> Compiling plugin: $*..."
	@mkdir -p build/plugins
	@$(MAKE) -C plugins/$* build OUT_BIN=../../build/plugins/$*

install-core:
	@if [ ! -f "build/bin/secure-backup" ]; then \
		echo "Error: secure-backup binary not found! Please run 'make build' first."; \
		exit 1; \
	fi
	@echo "Installing secure-backup to $(BINDIR)..."
	@mkdir -p "$(BINDIR)"
	@cp build/bin/secure-backup "$(BINDIR)/secure-backup"
	@chmod +x "$(BINDIR)/secure-backup"
	@echo "Core binary installed successfully."

install-plugins:
	@if [ ! -d "build/plugins" ] || [ -z "$$(find build/plugins -type f)" ]; then \
		echo "Error: Plugins not found! Please run 'make build' first."; \
		exit 1; \
	fi
	@echo "Installing plugins to $(PLUGINDIR)..."
	@mkdir -p "$(PLUGINDIR)"
	@cp build/plugins/* "$(PLUGINDIR)/"
	@chmod +x "$(PLUGINDIR)"/*
	@echo "Plugins installed successfully."

install: install-core install-plugins

uninstall-core:
	@echo "Uninstalling secure-backup from $(BINDIR)..."
	@rm -f "$(BINDIR)/secure-backup"
	@echo "Core binary uninstalled successfully."

uninstall-plugins:
	@echo "Uninstalling plugins from $(PLUGINDIR)..."
	@rm -rf "$(PREFIX)/lib/secure-backup"
	@echo "Plugins uninstalled successfully."

uninstall: uninstall-core uninstall-plugins

clean:
	@echo "Cleaning build artifacts..."
	@rm -rf build/
	@echo "Clean complete."

gen-security-keys:
	@echo "Generating new Ed25519 security keypair..."
	@go run scripts/security-tool/main.go -gen > .security-keys.txt
	@grep "Private Key" .security-keys.txt | cut -d' ' -f4 > .security-key
	@grep "Public Key" .security-keys.txt | cut -d' ' -f4 > .public-key
	@rm .security-keys.txt
	@echo "Keys generated: .security-key (PRIVATE) and .public-key (PUBLIC)"
	@echo "IMPORTANT: Update the 'trustedPublicKeyB64' in main.go with the content of .public-key"

sign-plugins:
	@if [ ! -f ".security-key" ]; then \
		echo "Warning: .security-key not found. Plugins will not be signed and will be rejected by secure-backup."; \
	else \
		echo " -> Signing plugins..."; \
		for plugin in build/plugins/*; do \
			if [ -f "$$plugin" ] && [ "$${plugin##*.}" != "sig" ]; then \
				go run scripts/security-tool/main.go -sign "$$plugin" -key "$$(cat .security-key)"; \
			fi \
		done \
	fi
