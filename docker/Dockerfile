ARG GOVERSION=1.25
FROM golang:${GOVERSION}-alpine AS builder

ARG BUILD_ARCH=amd64
ARG BUILD_OS=linux

RUN apk update && apk add --no-cache git make

WORKDIR /usr/src/app

COPY go.sum go.mod ./
RUN go mod download

COPY . .

RUN CGO_ENABLED=0 GOOS=${BUILD_OS} GOARCH=${BUILD_ARCH} \
    go build -ldflags="-s -w -X main.version=$(cat VERSION 2>/dev/null || echo dev)" \
    -o /usr/local/bin/nats-creds-checker ./cmd/

FROM alpine:3

LABEL org.opencontainers.image.source="https://github.com/jr200-labs/nats-creds-checker"
LABEL org.opencontainers.image.description="NATS credential validation and reporting tool"

RUN apk add --no-cache ca-certificates

COPY --from=builder /usr/local/bin/nats-creds-checker /usr/local/bin/nats-creds-checker

ENTRYPOINT ["nats-creds-checker"]
