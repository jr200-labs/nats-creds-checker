BUILD_OS ?= $(shell go env GOOS)
BUILD_ARCH ?= $(shell go env GOARCH)
VERSION ?= $(shell cat VERSION 2>/dev/null || echo dev)

.PHONY: build test clean docker

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
		-t ghcr.io/jr200/nats-creds-checker:$(VERSION) .
