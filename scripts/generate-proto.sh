#!/usr/bin/env bash
# generate-proto.sh — Regenerate or sync the protobuf-generated Go files used
# by the facetec-api issuer gRPC client.
#
# The vc module currently declares `module vc` (a bare path not usable by
# external Go modules via `go mod tidy`). Until vc is published under a proper
# module path (e.g. github.com/SUNET/vc), this script copies the pre-generated
# Go files from the vc workspace sibling rather than running protoc directly.
#
# Usage:
#   ./scripts/generate-proto.sh          # copy from ../vc (default)
#   REGEN=1 ./scripts/generate-proto.sh  # run protoc to regenerate from source
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

DST="${ROOT}/internal/gen/issuer/apiv1_issuer"
VC_SRC="$(cd "${ROOT}/../vc" && pwd)"
VC_GEN="${VC_SRC}/internal/gen/issuer/apiv1_issuer"
VC_PROTO="${VC_SRC}/proto/v1-issuer.proto"

# -----------------------------------------------------------------------
# Mode 1 (default): copy pre-generated files from the vc sibling module.
# -----------------------------------------------------------------------
copy_from_vc() {
    if [[ ! -d "${VC_GEN}" ]]; then
        echo "ERROR: vc generated files not found at ${VC_GEN}" >&2
        exit 1
    fi

    mkdir -p "${DST}"
    for f in "${VC_GEN}"/*.go; do
        name="$(basename "${f}")"
        echo "  copy ${VC_GEN}/${name}  →  ${DST}/${name}"
        cp "${f}" "${DST}/${name}"
    done

    # Fix the package import path: the vc module uses `module vc`, but our
    # copy lives inside github.com/sirosfoundation/facetec-api. Rewrite all
    # vc-internal import references to our local package path.
    SED_SCRIPT='s|"vc/internal/gen/issuer/apiv1_issuer"|"github.com/sirosfoundation/facetec-api/internal/gen/issuer/apiv1_issuer"|g'
    for f in "${DST}"/*.go; do
        sed -i "${SED_SCRIPT}" "${f}"
        echo "  patched imports in $(basename "${f}")"
    done

    echo "Done. Files synced from ${VC_GEN}"
    echo "NOTE: If vc is published at github.com/SUNET/vc, replace this copy"
    echo "      with a direct require/replace in go.mod and the local files can"
    echo "      be deleted."
}

# -----------------------------------------------------------------------
# Mode 2 (REGEN=1): regenerate from proto source using protoc.
# -----------------------------------------------------------------------
regen_from_proto() {
    if ! command -v protoc &>/dev/null; then
        echo "ERROR: protoc not found — install protobuf-compiler" >&2
        exit 1
    fi
    if ! command -v protoc-gen-go &>/dev/null; then
        echo "ERROR: protoc-gen-go not found — run: go install google.golang.org/protobuf/cmd/protoc-gen-go@latest" >&2
        exit 1
    fi
    if ! command -v protoc-gen-go-grpc &>/dev/null; then
        echo "ERROR: protoc-gen-go-grpc not found — run: go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@latest" >&2
        exit 1
    fi

    mkdir -p "${DST}"
    echo "Generating from ${VC_PROTO}..."
    protoc \
        --proto_path="$(dirname "${VC_PROTO}")" \
        --go_out="${DST}" \
        --go_opt=paths=source_relative \
        --go-grpc_out="${DST}" \
        --go-grpc_opt=paths=source_relative \
        "${VC_PROTO}"

    # Rewrite the package declaration to fit our module path.
    SED_SCRIPT='s|^package .*|package apiv1_issuer|'
    for f in "${DST}"/*.go; do
        sed -i "${SED_SCRIPT}" "${f}"
    done

    echo "Done. Generated files written to ${DST}"
}

# -----------------------------------------------------------------------
# Dispatch
# -----------------------------------------------------------------------
if [[ "${REGEN:-0}" == "1" ]]; then
    regen_from_proto
else
    copy_from_vc
fi
