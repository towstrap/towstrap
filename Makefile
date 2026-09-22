# towstrap 构建/发布。发布产物是三个二进制：服务器端（含账号管理）、被控端、MCP 入口。
VERSION := $(shell cat VERSION 2>/dev/null || echo dev)
LDFLAGS := -X github.com/towstrap/towstrap/internal/version.Version=$(VERSION)
PLATFORMS := darwin/arm64 darwin/amd64 linux/amd64 linux/arm64

.PHONY: build test release clean

build:
	go build -ldflags "$(LDFLAGS)" -o bin/towstrap-server ./cmd/towstrap-server
	go build -ldflags "$(LDFLAGS)" -o bin/towstrap-agent ./cmd/towstrap-agent
	go build -ldflags "$(LDFLAGS)" -o bin/towstrap-mcp ./cmd/towstrap-mcp

test:
	go vet ./...
	go test ./... -count=1

# 交叉编译全平台 + 校验和。设了 MINISIGN_KEY_FILE 就顺带签名（minisign -H）。
release: clean
	@mkdir -p dist
	@set -e; for p in $(PLATFORMS); do \
		os=$${p%/*}; arch=$${p#*/}; \
		echo "== $$os/$$arch"; \
		GOOS=$$os GOARCH=$$arch go build -trimpath -ldflags "$(LDFLAGS)" \
			-o dist/towstrap-server-$$os-$$arch ./cmd/towstrap-server; \
		GOOS=$$os GOARCH=$$arch go build -trimpath -ldflags "$(LDFLAGS)" \
			-o dist/towstrap-agent-$$os-$$arch ./cmd/towstrap-agent; \
		GOOS=$$os GOARCH=$$arch go build -trimpath -ldflags "$(LDFLAGS)" \
			-o dist/towstrap-mcp-$$os-$$arch ./cmd/towstrap-mcp; \
	done
	cd dist && shasum -a 256 * > SHA256SUMS
	@if [ -n "$$MINISIGN_KEY_FILE" ]; then \
		cd dist && minisign -H -Sm towstrap-server-* towstrap-agent-* towstrap-mcp-* SHA256SUMS; \
		echo "已用 minisign 签名"; \
	else \
		echo "提示：设 MINISIGN_KEY_FILE 可在发布时签名"; \
	fi
	@ls -la dist/

clean:
	rm -rf bin dist
