# ws2ssh 构建/发布。发布产物是两个二进制：服务器端（含账号管理）和被控端。
VERSION := $(shell cat VERSION 2>/dev/null || echo dev)
LDFLAGS := -X ws2ssh/internal/version.Version=$(VERSION)
PLATFORMS := darwin/arm64 darwin/amd64 linux/amd64 linux/arm64

.PHONY: build test release clean

build:
	go build -ldflags "$(LDFLAGS)" -o bin/ws2ssh-server ./cmd/ws2ssh-server
	go build -ldflags "$(LDFLAGS)" -o bin/ws2ssh-agent ./cmd/ws2ssh-agent

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
			-o dist/ws2ssh-server-$$os-$$arch ./cmd/ws2ssh-server; \
		GOOS=$$os GOARCH=$$arch go build -trimpath -ldflags "$(LDFLAGS)" \
			-o dist/ws2ssh-agent-$$os-$$arch ./cmd/ws2ssh-agent; \
	done
	cd dist && shasum -a 256 * > SHA256SUMS
	@if [ -n "$$MINISIGN_KEY_FILE" ]; then \
		cd dist && minisign -H -Sm ws2ssh-server-* ws2ssh-agent-* SHA256SUMS; \
		echo "已用 minisign 签名"; \
	else \
		echo "提示：设 MINISIGN_KEY_FILE 可在发布时签名"; \
	fi
	@ls -la dist/

clean:
	rm -rf bin dist
