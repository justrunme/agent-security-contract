#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
python -m asc corpus \
  --policy policy/demo-agent.policy.yaml \
  --corpus corpus/scenarios \
  --results results/results.json \
  --summary results/summary.md \
  --evidence docs/EVIDENCE.md
