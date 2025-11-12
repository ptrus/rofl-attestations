.PHONY: help format lint build run clean

help: ## Show this help message.
	@echo 'Usage: make [target]'
	@echo ''
	@echo 'Available targets:'
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / {printf "  %-15s %s\n", $$1, $$2}' $(MAKEFILE_LIST)

format: ## Format code with gofumpt and goimports.
	@echo "Running gofumpt..."
	@gofumpt -w ./go 2>/dev/null || true
	@echo "Running goimports..."
	@goimports -w -local github.com/ptrus/rofl-attestations ./go 2>/dev/null || true
	@echo "Formatting complete."

lint: ## Run golangci-lint.
	@echo "Running golangci-lint..."
	@cd go && golangci-lint run

build: ## Build the binary.
	@echo "Building rofl-registry..."
	@cd go && go build -o ../rofl-registry .
	@echo "Build complete: ./rofl-registry"

run: build ## Build and run the server.
	@echo "Starting server..."
	@./rofl-registry --config config.yaml

clean: ## Clean build artifacts and database.
	@echo "Cleaning..."
	@rm -f rofl-registry rofl-registry.db
	@echo "Clean complete."
