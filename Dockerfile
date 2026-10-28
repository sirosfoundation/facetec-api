# Build stage
FROM golang:1.27.2-alpine AS builder

RUN apk add --no-cache git ca-certificates tzdata

WORKDIR /app

ARG VERSION=dev
ARG COMMIT=unknown

# Fetch dependencies separately for layer caching.
COPY go.mod go.sum ./
RUN go mod download

# Copy source and build.
COPY . .
# -tags production makes this a production build: config.Validate then refuses
# trust.required: false, which would disable document-signer trust and let OCR
# claims into issued credentials (#85). Build without the tag for a development
# stack that has no go-trust PDP.
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
    -tags production \
    -ldflags="-s -w -X main.Version=${VERSION} -X main.Commit=${COMMIT}" \
    -o facetec-api ./cmd/server

# Runtime stage — distroless contains only CA certs and no shell.
FROM gcr.io/distroless/static-debian12

WORKDIR /app

# Copy the binary and default rules directory.
COPY --from=builder /app/facetec-api /app/facetec-api
COPY --from=builder /app/rules        /app/rules

# Run as a non-root user (distroless nonroot UID 65532).
USER 65532:65532

EXPOSE 8080

# The config file is expected to be bind-mounted at /app/configs/config.yaml.
ENTRYPOINT ["/app/facetec-api"]
CMD ["-config", "/app/configs/config.yaml"]
