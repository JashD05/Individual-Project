#!/usr/bin/env bash
# teardown-cluster.sh — Delete the chaos-sec Kind cluster.
set -euo pipefail

CLUSTER_NAME="chaos-sec"

if kind get clusters 2>/dev/null | grep -q "^${CLUSTER_NAME}$"; then
  echo "Deleting Kind cluster '${CLUSTER_NAME}'..."
  kind delete cluster --name "${CLUSTER_NAME}"
  echo "Done."
else
  echo "Cluster '${CLUSTER_NAME}' not found — nothing to do."
fi
