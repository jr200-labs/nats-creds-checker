BUILD_OS ?= $(shell go env GOOS)
BUILD_ARCH ?= $(shell go env GOARCH)
VERSION ?= $(shell cat VERSION 2>/dev/null || echo dev)

.PHONY: build test clean docker lint sync-shared-lint

sync-shared-lint:
	@mkdir -p .shared
	@curl -sfL "https://raw.githubusercontent.com/jr200-labs/github-action-templates/master/shared/sync-shared-lint.sh" -o .shared/sync-shared-lint.sh
	@chmod +x .shared/sync-shared-lint.sh
	@./.shared/sync-shared-lint.sh go

lint: sync-shared-lint
	go vet ./...
	golangci-lint run --config .shared/.golangci.yml --timeout=5m

build:
	CGO_ENABLED=0 GOOS=$(BUILD_OS) GOARCH=$(BUILD_ARCH) \
		go build -ldflags="-s -w -X main.version=$(VERSION)" \
		-o build/nats-creds-checker ./cmd/

test:
	go test ./...

clean:
	rm -rf build/

docker:
	docker build -f docker/Dockerfile \
		--build-arg BUILD_OS=$(BUILD_OS) \
		--build-arg BUILD_ARCH=$(BUILD_ARCH) \
		-t ghcr.io/jr200-labs/nats-creds-checker:$(VERSION) .
