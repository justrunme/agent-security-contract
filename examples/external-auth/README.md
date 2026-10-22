# External-auth quickstart (Envoy ext_authz + ASC)

This quickstart shows the ASC MCP tool-call gate enforced as an **external authorization** step in front of an MCP server on Kubernetes.

```
client  -->  kubectl port-forward -->  Envoy (:8080)
                                         |  ext_authz (failure_mode_allow=false)
                                         v
                                   asc-ext-authz (:9191)  --POST /v1/evaluate-->  asc-sidecar
                                         |
                                         | only on ASC ALLOW
                                         v
                                   mcp-demo (:8090)
```

All four processes run in one kind pod on localhost (Envoy, ext_authz adapter, ASC sidecar, MCP demo). `run-kind.sh` exposes Envoy with `kubectl port-forward` so the quickstart does not depend on ClusterIP/NodePort/hostPort DNAT.

Decisions come from the real ASC sidecar (`python -m asc.sidecar`, same `/v1/evaluate` contract as [`docs/INTEGRATION.md`](../../docs/INTEGRATION.md)). The adapter does not evaluate policy itself. Envoy is configured with `failure_mode_allow: false` so authorizer-down and authorizer-timeout fail closed.

## Prerequisites

- Docker
- [kind](https://kind.sigs.k8s.io/) v0.20+
- kubectl
- Python 3.11+ with this package installed (`pip install -e .`)

## Run

```bash
# from repo root
./examples/external-auth/run-kind.sh
export ASC_EXTERNAL_AUTH_URL=http://127.0.0.1:18080

python examples/external-auth/run_integration_tests.py \
  --results results/external-auth-results.json \
  --summary results/external-auth-summary.md \
  --evidence docs/EVIDENCE-EXTERNAL-AUTH.md
```

Demo credential required by the gateway edge: `Authorization: Bearer asc-demo`.

## What the integration corpus covers

Claims are scoped **on this corpus** only (see `docs/EVIDENCE-EXTERNAL-AUTH.md`):

| Scenario | Expected |
| --- | --- |
| Benign reads/lists/http/shell/write/email through the proxy | `ALLOW` (MCP executes) |
| Data exfiltration tool call | `BLOCK` (MCP does not execute) |
| Unapproved production deploy | `REQUIRE_APPROVAL` (MCP does not execute) |
| Malformed body | `BLOCK` (fail closed) |
| Missing credentials | `BLOCK` (fail closed) |
| Authorizer adapter process stopped (nothing listening on :9191) | `BLOCK` (Envoy fail closed) |
| Authorizer hangs past Envoy timeout | `BLOCK` (Envoy fail closed) |

## Manual probe

```bash
# ALLOW
curl -sS -D- "$ASC_EXTERNAL_AUTH_URL/mcp/v1/tools/call" \
  -H 'Authorization: Bearer asc-demo' \
  -H 'Content-Type: application/json' \
  --data-binary @<(python - <<'PY'
import json
from pathlib import Path
s=json.loads(Path("corpus/scenarios/benign_read_workspace_file.json").read_text())
print(json.dumps({"scenario_id":"manual","trace":s["trace"]}))
PY
)

# no credentials -> deny
curl -sS -D- "$ASC_EXTERNAL_AUTH_URL/mcp/v1/tools/call" \
  -H 'Content-Type: application/json' \
  -d '{"scenario_id":"x","trace":{"agent_id":"demo-agent","trace_id":"t","calls":[]}}'
```

## Cleanup

```bash
kind delete cluster --name asc-external-auth
```

## Limitations

- Lexical path checks and policy semantics are unchanged from ASC; this quickstart only proves **admission** via ext_authz.
- The MCP process is a demo stand-in (records admitted calls); it is not a full MCP SDK server.
- Evidence envelopes for `ALLOW` appear on the ASC sidecar path; the client-visible 200 is the MCP demo response after admission.
- Authorizer-timeout is induced with a test-only `ASC_FORCE_SLEEP_S_TEST` on the adapter so Envoy's 0.5s ext_authz timeout fires; production should omit that knob.
- Authorizer-down stops the adapter process (nothing listening on :9191), then restarts the gateway Deployment.
- Components share a pod on localhost so the quickstart remains reproducible on hosts where kube-proxy/nftables cannot install ClusterIP rules.
