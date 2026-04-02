#!/usr/bin/env bash
# Set up the development environment for facetec-api

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

echo "Setting up facetec-api development environment..."

# Configure git to use .githooks directory
echo "Configuring git hooks..."
cd "$PROJECT_ROOT"
git config core.hooksPath .githooks
chmod +x .githooks/*
echo "✓ Git hooks configured"

# Download dependencies
echo "Downloading dependencies..."
go mod download
echo "✓ Dependencies downloaded"

# Verify build
echo "Verifying build..."
go build ./...
echo "✓ Build OK"

echo ""
echo "Development environment ready!"
echo "Run 'make help' to see available commands."
