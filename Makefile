BINARY        := spiffe-info
MOCK_BINARY   := mock-workload-api
MODULE        := github.com/mattiasGees/spiffe-info
BIN_DIR       := bin
DOCKER_IMAGE  := spiffe-info:dev
MOCK_SOCKET   := /tmp/spiffe-info-mock.sock

LDFLAGS := -s -w
BUILD_FLAGS := CGO_ENABLED=0

PLATFORMS := \
	linux/amd64 \
	linux/arm64 \
	darwin/amd64 \
	darwin/arm64

.PHONY: all build build-all docker test run mock dev clean deps

all: build

## deps: download and tidy Go modules
deps:
	go mod tidy
	go mod download

## build: build spiffe-info binary for the host platform
build: deps
	$(BUILD_FLAGS) go build -ldflags "$(LDFLAGS)" -o $(BIN_DIR)/$(BINARY) ./cmd/spiffe-info

## build-mock: build mock-workload-api binary for the host platform
build-mock: deps
	$(BUILD_FLAGS) go build -ldflags "$(LDFLAGS)" -o $(BIN_DIR)/$(MOCK_BINARY) ./cmd/mock-workload-api

## build-all: cross-compile spiffe-info for all platforms
build-all: deps
	$(foreach PLATFORM,$(PLATFORMS), \
		$(eval OS=$(word 1,$(subst /, ,$(PLATFORM)))) \
		$(eval ARCH=$(word 2,$(subst /, ,$(PLATFORM)))) \
		$(BUILD_FLAGS) GOOS=$(OS) GOARCH=$(ARCH) go build \
			-ldflags "$(LDFLAGS)" \
			-o $(BIN_DIR)/$(BINARY)_$(OS)_$(ARCH) \
			./cmd/spiffe-info; \
	)

## docker: build container image tagged spiffe-info:dev
docker:
	docker build -t $(DOCKER_IMAGE) .

## test: run all tests with race detector
test: deps
	go test -race -count=1 ./...

## run: build and run spiffe-info (uses SPIFFE_ENDPOINT_SOCKET env var)
run: build
	./$(BIN_DIR)/$(BINARY)

## mock: build and start the mock Workload API on a local unix socket
mock: build-mock
	./$(BIN_DIR)/$(MOCK_BINARY) --socket $(MOCK_SOCKET)

## dev: run mock Workload API and spiffe-info together (no SPIRE needed)
dev: build build-mock
	@echo "Starting mock Workload API and spiffe-info..."
	@./$(BIN_DIR)/$(MOCK_BINARY) --socket $(MOCK_SOCKET) --rotation-interval 30s & \
	sleep 1 && \
	SPIFFE_ENDPOINT_SOCKET=unix://$(MOCK_SOCKET) PORT=8080 ./$(BIN_DIR)/$(BINARY)

## clean: remove build artefacts
clean:
	rm -rf $(BIN_DIR)
