.PHONY: build build-linux clean test

# Build for current platform
build:
	go build -o bin/kubeenum ./cmd/kubeenum

# Build for Linux (for containers/CTFs)
build-linux:
	GOOS=linux GOARCH=amd64 go build -o bin/kubeenum-linux ./cmd/kubeenum

# Clean build artifacts
clean:
	rm -rf bin/

# Run tests
test:
	go test ./...

# Install dependencies
deps:
	go mod download
	go mod tidy

