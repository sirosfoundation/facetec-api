.PHONY: all build test test-unit test-integration lint fmt vet clean \
        docker docker-push run dev proto help

# ── Build variables ──────────────────────────────────────────────────────────
BINARY      := facetec-api
VERSION     := $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
COMMIT      := $(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
BUILD_TIME  := $(shell date -u '+%Y-%m-%dT%H:%M:%SZ')
LDFLAGS     := -ldflags "-s -w \
	-X main.Version=$(VERSION) \
	-X main.Commit=$(COMMIT)"

# ── Docker variables ─────────────────────────────────────────────────────────
DOCKER_REGISTRY ?= registry.siros.org
DOCKER_IMAGE    := $(DOCKER_REGISTRY)/sirosfoundation/facetec-api
DOCKER_TAG      := $(VERSION)

# ── Go ────────────────────────────────────────────────────────────────────────
# Disable workspace mode so coverage instrumentation works without covdata.
GOTEST := GOWORK=off go test -v -race

# Packages that carry test files. Using ./... with -coverprofile requires the
# covdata tool (Go ≥ 1.20 multi-package coverage merge) which is not present in
# every toolchain installation. Limiting to tested packages avoids the error.
TESTPKGS := \
	./internal/config/... \
	./internal/middleware/... \
	./internal/policy/... \
	./internal/session/... \
	./internal/tenant/... \
	./tests/...

all: lint test build ## Run lint, test, build (default)

build: ## Build the server binary
	@echo "Building $(BINARY) $(VERSION)..."
	@mkdir -p bin
	@go build $(LDFLAGS) -o bin/$(BINARY) ./cmd/server

build-linux: ## Cross-compile for Linux amd64
	@echo "Building $(BINARY) for linux/amd64..."
	@mkdir -p bin
	@GOOS=linux GOARCH=amd64 go build $(LDFLAGS) -o bin/$(BINARY)-linux-amd64 ./cmd/server

run: build ## Build and run locally (requires configs/config.yaml)
	@./bin/$(BINARY) -config configs/config.yaml

dev: ## Run with hot reload (requires: go install github.com/air-verse/air@latest)
	@air

# ── Testing ───────────────────────────────────────────────────────────────────
test: ## Run all tests (unit + integration)
	@echo "Running all tests..."
	@$(GOTEST) ./...

test-unit: ## Run unit tests only
	@echo "Running unit tests..."
	@$(GOTEST) ./internal/...

test-integration: ## Run integration tests (requires no external services)
	@echo "Running integration tests..."
	@$(GOTEST) ./tests/integration/...

test-coverage: ## Generate per-package coverage summary and HTML report
	@echo "Running tests with coverage..."
	@$(GOTEST) -coverprofile=coverage.out $(TESTPKGS)
	@GOWORK=off go tool cover -func=coverage.out | tail -3
	@GOWORK=off go tool cover -html=coverage.out -o coverage.html
	@echo "Coverage report: coverage.html"

# ── Code quality ──────────────────────────────────────────────────────────────
lint: ## Run golangci-lint
	@golangci-lint run ./...

fmt: ## Format Go source
	@gofmt -s -w .

vet: ## Run go vet
	@go vet ./...

# ── Proto ─────────────────────────────────────────────────────────────────────
proto: ## Regenerate internal/gen/ from vc proto files
	@./scripts/generate-proto.sh

# ── Docker ────────────────────────────────────────────────────────────────────
docker: ## Build Docker image
	@echo "Building Docker image $(DOCKER_IMAGE):$(DOCKER_TAG)..."
	@docker build \
		--build-arg VERSION=$(VERSION) \
		--build-arg COMMIT=$(COMMIT) \
		-t $(DOCKER_IMAGE):$(DOCKER_TAG) \
		-t $(DOCKER_IMAGE):latest \
		.

docker-push: docker ## Push Docker image to registry
	@docker push $(DOCKER_IMAGE):$(DOCKER_TAG)
	@docker push $(DOCKER_IMAGE):latest

docker-run: docker ## Build and run in Docker (uses configs/config.yaml)
	@docker run --rm -p 8080:8080 \
		-v "$(PWD)/configs/config.yaml:/app/configs/config.yaml:ro" \
		-v "$(PWD)/rules:/app/rules:ro" \
		$(DOCKER_IMAGE):latest

# ── Cleanup ───────────────────────────────────────────────────────────────────
clean: ## Remove build artifacts
	@rm -rf bin/ coverage.out coverage.html

deps: ## Download and tidy dependencies
	@go mod download
	@go mod tidy

tools: ## Install required development tools
	@echo "Installing development tools..."
	@go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest
	@go install github.com/air-verse/air@latest
	@go install google.golang.org/protobuf/cmd/protoc-gen-go@latest
	@go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@latest
	@echo "Done."

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort \
		| awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-22s\033[0m %s\n", $$1, $$2}'
