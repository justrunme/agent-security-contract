#!/usr/bin/env bash
# Reproducible kind quickstart: Envoy ext_authz -> ASC decision API -> MCP demo.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
EX="${ROOT}/examples/external-auth"
CLUSTER_NAME="${CLUSTER_NAME:-asc-external-auth}"
NS=asc-external-auth
ENVOY_IMAGE="${ENVOY_IMAGE:-envoyproxy/envoy:v1.31.5}"

log() { printf '+ %s\n' "$*"; }

need() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "missing required tool: $1" >&2
    exit 1
  }
}

need docker
need kind
need kubectl

cd "${ROOT}"

if ! kind get clusters 2>/dev/null | grep -qx "${CLUSTER_NAME}"; then
  log "creating kind cluster ${CLUSTER_NAME}"
  kind create cluster --config "${EX}/kind-config.yaml"
else
  log "reusing kind cluster ${CLUSTER_NAME}"
  kubectl cluster-info --context "kind-${CLUSTER_NAME}" >/dev/null
fi

log "building images"
docker build -t asc-sidecar:local -f "${EX}/Dockerfile.asc" "${ROOT}"
docker build -t asc-ext-authz:local -f "${EX}/Dockerfile.ext-authz" "${ROOT}"
docker build -t asc-mcp-demo:local -f "${EX}/Dockerfile.mcp" "${ROOT}"
docker pull "${ENVOY_IMAGE}"

load_image() {
  local image="$1"
  # Prefer kind load; fall back to ctr import (works when kind load hits content-store races).
  if ! kind load docker-image "${image}" --name "${CLUSTER_NAME}"; then
    log "kind load failed for ${image}; importing via ctr"
    docker save "${image}" | docker exec -i "${CLUSTER_NAME}-control-plane" \
      ctr -n k8s.io images import /dev/stdin
  fi
}

log "loading images into kind"
load_image asc-sidecar:local
load_image asc-ext-authz:local
load_image asc-mcp-demo:local
load_image "${ENVOY_IMAGE}"

log "applying manifests"
kubectl apply -f "${EX}/k8s/gateway.yaml"

log "waiting for gateway pod"
kubectl -n "${NS}" rollout status deploy/asc-gateway --timeout=240s

# Port-forward reaches the pod IP via the API server (no ClusterIP/NodePort needed).
pkill -f "kubectl -n ${NS} port-forward .*asc-gateway" >/dev/null 2>&1 || true

pick_port() {
  local start="${ASC_EXTERNAL_AUTH_PORT:-18080}"
  local p
  for p in "${start}" 18081 18082 18083 18084; do
    if ! ss -ltn "( sport = :${p} )" 2>/dev/null | grep -q ":${p}"; then
      echo "${p}"
      return 0
    fi
  done
  echo "${start}"
}

PF_PORT="$(pick_port)"
export ASC_EXTERNAL_AUTH_URL="http://127.0.0.1:${PF_PORT}"
log "port-forward deploy/asc-gateway ${PF_PORT}:8080"
kubectl -n "${NS}" port-forward --address 127.0.0.1 deploy/asc-gateway "${PF_PORT}:8080" \
  >/tmp/asc-external-auth-pf.log 2>&1 &
sleep 2
if ! grep -q "Forwarding from" /tmp/asc-external-auth-pf.log 2>/dev/null; then
  cat /tmp/asc-external-auth-pf.log >&2 || true
  echo "port-forward failed to start" >&2
  exit 1
fi

log "waiting for gateway HTTP on ${ASC_EXTERNAL_AUTH_URL}"
deadline=$((SECONDS + 120))
ready=0
while (( SECONDS < deadline )); do
  code="$(curl -sS -o /dev/null -w '%{http_code}' --connect-timeout 2 -X POST \
    -H 'Content-Type: application/json' -d '{}' \
    "${ASC_EXTERNAL_AUTH_URL}/mcp/v1/tools/call" || true)"
  if [[ "${code}" =~ ^[1-5][0-9][0-9]$ ]]; then
    ready=1
    break
  fi
  sleep 2
done
if [[ "${ready}" != "1" ]]; then
  echo "gateway did not become reachable at ${ASC_EXTERNAL_AUTH_URL}" >&2
  kubectl -n "${NS}" get pods -o wide >&2 || true
  kubectl -n "${NS}" logs deploy/asc-gateway -c envoy --tail=50 >&2 || true
  exit 1
fi

log "gateway ready at ${ASC_EXTERNAL_AUTH_URL}"
echo "${ASC_EXTERNAL_AUTH_URL}"
