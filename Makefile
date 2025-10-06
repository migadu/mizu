.PHONY: all clean build mizu mizu-admin install test 

# Binary names - can be overridden by environment variables
mizu_BINARY ?= mizu-server
mizu_ADMIN_BINARY ?= mizu-admin
mizu_LINUX_BINARY ?= mizu-linux-amd64
mizu_ADMIN_LINUX_BINARY ?= mizu-admin-linux-amd64
mizu_FREEBSD_BINARY ?= mizu-freebsd-amd64
mizu_ADMIN_FREEBSD_BINARY ?= mizu-admin-freebsd-amd64

# ====================================================================================
# Version Information
# You can override these variables during the build, e.g., make build VERSION=v1.0.0
# ====================================================================================
VERSION ?= $(shell git describe --tags --always --dirty --match='v*')
COMMIT ?= $(shell git rev-parse --short HEAD)
DATE ?= $(shell date -u +"%Y-%m-%dT%H:%M:%SZ")

# Go linker flags to inject version info
LDFLAGS_VARS = -X 'main.version=${VERSION}' -X 'main.commit=${COMMIT}' -X 'main.date=${DATE}'
LDFLAGS = -ldflags="${LDFLAGS_VARS}"

# Default target
all: build

# Build both executables
build: mizu-server mizu-admin

# Build the main mizu server
mizu-server:
	go build $(LDFLAGS) -o $(mizu_BINARY) ./cmd/mizu-server

# Build the mizu-admin tool
mizu-admin:
	go build $(LDFLAGS) -o $(mizu_ADMIN_BINARY) ./cmd/mizu-admin

# Install both executables to GOPATH/bin
install:
	go install ./cmd/mizu-server
	go install ./cmd/mizu-admin

# Clean build artifacts
clean:
	rm -f $(mizu_BINARY) $(mizu_ADMIN_BINARY) $(mizu_LINUX_BINARY) $(mizu_ADMIN_LINUX_BINARY) $(mizu_FREEBSD_BINARY) $(mizu_ADMIN_FREEBSD_BINARY)

# Run tests
test:
	go test -v ./...

# Run tests with coverage
coverage:
	go test -coverprofile=coverage.out ./...
	go tool cover -html=coverage.out

# Cross-compile with musl libc for Linux
build-linux-musl:
	CC=x86_64-linux-musl-gcc CXX=x86_64-linux-musl-g++ GOARCH=amd64 GOOS=linux go build -ldflags="${LDFLAGS_VARS} -extldflags -static" -o $(mizu_LINUX_BINARY) ./cmd/mizu-server
	CC=x86_64-linux-musl-gcc CXX=x86_64-linux-musl-g++ GOARCH=amd64 GOOS=linux go build -ldflags="${LDFLAGS_VARS} -extldflags -static" -o $(mizu_ADMIN_LINUX_BINARY) ./cmd/mizu-admin

# Cross-compile for FreeBSD
build-freebsd:
	GOARCH=amd64 GOOS=freebsd go build $(LDFLAGS) -o $(mizu_FREEBSD_BINARY) ./cmd/mizu-server
	GOARCH=amd64 GOOS=freebsd go build $(LDFLAGS) -o $(mizu_ADMIN_FREEBSD_BINARY) ./cmd/mizu-admin
