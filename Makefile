.PHONY: all build clean server client test fmt lint

# Build output directory
BUILD_DIR := bin

# Go build flags
LDFLAGS := -s -w

all: build

build: server client

server:
	@mkdir -p $(BUILD_DIR)
	go build -ldflags "$(LDFLAGS)" -o $(BUILD_DIR)/holepunch-server ./cmd/server

client:
	@mkdir -p $(BUILD_DIR)
	go build -ldflags "$(LDFLAGS)" -o $(BUILD_DIR)/holepunch-client ./cmd/client

clean:
	rm -rf $(BUILD_DIR)
	go clean

test:
	go test -v ./...

fmt:
	go fmt ./...

lint:
	golangci-lint run

# Install dependencies
deps:
	go mod tidy
	go mod download

# Run server
run-server: server
	./$(BUILD_DIR)/holepunch-server

# Run client
run-client: client
	./$(BUILD_DIR)/holepunch-client

# Build for multiple platforms
release:
	@mkdir -p $(BUILD_DIR)
	# Linux AMD64
	GOOS=linux GOARCH=amd64 go build -ldflags "$(LDFLAGS)" -o $(BUILD_DIR)/holepunch-server-linux-amd64 ./cmd/server
	GOOS=linux GOARCH=amd64 go build -ldflags "$(LDFLAGS)" -o $(BUILD_DIR)/holepunch-client-linux-amd64 ./cmd/client
	# Linux ARM64
	GOOS=linux GOARCH=arm64 go build -ldflags "$(LDFLAGS)" -o $(BUILD_DIR)/holepunch-server-linux-arm64 ./cmd/server
	GOOS=linux GOARCH=arm64 go build -ldflags "$(LDFLAGS)" -o $(BUILD_DIR)/holepunch-client-linux-arm64 ./cmd/client
	# macOS AMD64
	GOOS=darwin GOARCH=amd64 go build -ldflags "$(LDFLAGS)" -o $(BUILD_DIR)/holepunch-server-darwin-amd64 ./cmd/server
	GOOS=darwin GOARCH=amd64 go build -ldflags "$(LDFLAGS)" -o $(BUILD_DIR)/holepunch-client-darwin-amd64 ./cmd/client
	# macOS ARM64
	GOOS=darwin GOARCH=arm64 go build -ldflags "$(LDFLAGS)" -o $(BUILD_DIR)/holepunch-server-darwin-arm64 ./cmd/server
	GOOS=darwin GOARCH=arm64 go build -ldflags "$(LDFLAGS)" -o $(BUILD_DIR)/holepunch-client-darwin-arm64 ./cmd/client
	# Windows AMD64
	GOOS=windows GOARCH=amd64 go build -ldflags "$(LDFLAGS)" -o $(BUILD_DIR)/holepunch-server-windows-amd64.exe ./cmd/server
	GOOS=windows GOARCH=amd64 go build -ldflags "$(LDFLAGS)" -o $(BUILD_DIR)/holepunch-client-windows-amd64.exe ./cmd/client
