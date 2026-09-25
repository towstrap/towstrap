# towstrap 构建/发布。发布产物是三个二进制：服务器端（含账号管理）、被控端、MCP 入口。
VERSION := $(shell cat VERSION 2>/dev/null || echo dev)
COMMIT := $(shell git rev-parse --short HEAD 2>/dev/null)
LDFLAGS := -X github.com/towstrap/towstrap/internal/version.Version=$(VERSION) -X github.com/towstrap/towstrap/internal/version.Commit=$(COMMIT)
PLATFORMS := darwin/arm64 darwin/amd64 linux/amd64 linux/arm64 windows/amd64 windows/arm64

.PHONY: build test release clean

build:
	go build -ldflags "$(LDFLAGS)" -o bin/towstrap-server ./cmd/towstrap-server
	go build -ldflags "$(LDFLAGS)" -o bin/towstrap ./cmd/towstrap
	go build -ldflags "$(LDFLAGS)" -o bin/towstrap-mcp ./cmd/towstrap-mcp

test:
	go vet ./...
	go test ./... -count=1

# 交叉编译全平台 + 校验和。设了 MINISIGN_KEY_FILE 就顺带签名（minisign -H）。
release: clean
	@mkdir -p dist
	@set -e; for p in $(PLATFORMS); do \
		os=$${p%/*}; arch=$${p#*/}; \
		ext=""; [ "$$os" = windows ] && ext=".exe"; \
		echo "== $$os/$$arch"; \
		CGO_ENABLED=0 GOOS=$$os GOARCH=$$arch go build -trimpath -ldflags "$(LDFLAGS)" \
			-o dist/towstrap-$$os-$$arch$$ext ./cmd/towstrap; \
		for b in server mcp; do \
			CGO_ENABLED=0 GOOS=$$os GOARCH=$$arch go build -trimpath -ldflags "$(LDFLAGS)" \
				-o dist/towstrap-$$b-$$os-$$arch$$ext ./cmd/towstrap-$$b; \
		done; \
	done
	cd dist && shasum -a 256 * > SHA256SUMS
	@if [ -n "$$MINISIGN_KEY_FILE" ]; then \
		cd dist && minisign -H -Sm -s "$$MINISIGN_KEY_FILE" towstrap-* SHA256SUMS; \
		echo "已用 minisign 签名"; \
	else \
		echo "提示：设 MINISIGN_KEY_FILE 可在发布时签名"; \
	fi
	@ls -la dist/

clean:
	rm -rf bin dist
