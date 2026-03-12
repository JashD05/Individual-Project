#!/usr/bin/env bash
# setup-cluster.sh — Spin up a Kind cluster with Falco and chaos-sec.
# Run from the chaos-sec/ project root.
set -euo pipefail

CLUSTER_NAME="chaos-sec"
NAMESPACE="chaos-sec-experiments"
FALCO_NAMESPACE="falco"

echo "──────────────────────────────────────────"
echo " Chaos-Sec Cluster Setup"
echo "──────────────────────────────────────────"

# ── 1. Create Kind cluster ─────────────────────────────────────────────────
if kind get clusters 2>/dev/null | grep -q "^${CLUSTER_NAME}$"; then
  echo "[1/6] Kind cluster '${CLUSTER_NAME}' already exists — skipping creation."
else
  echo "[1/6] Creating Kind cluster '${CLUSTER_NAME}'..."
  kind create cluster --config deploy/kind-config.yaml
fi

echo "      Installing Calico CNI (required for NetworkPolicy enforcement)..."
kubectl apply -f https://raw.githubusercontent.com/projectcalico/calico/v3.29.1/manifests/calico.yaml

echo "      Waiting for Calico to be ready (up to 3 min)..."
kubectl rollout status daemonset/calico-node -n kube-system --timeout=180s

echo "      Waiting for nodes to be Ready..."
kubectl wait --for=condition=Ready node --all --timeout=120s

echo "[1/6] Done. Cluster nodes:"
kubectl get nodes

# ── 2. Create experiment namespace with PSA ────────────────────────────────
echo ""
echo "[2/6] Creating namespace '${NAMESPACE}' with PSA restricted..."
kubectl apply -f deploy/namespace.yaml
echo "[2/6] Done."

# ── 3. Apply NetworkPolicy (default-deny egress) ──────────────────────────
echo ""
echo "[3/6] Applying default-deny egress NetworkPolicy..."
kubectl apply -f policies/default-deny-egress.yaml
echo "[3/6] Done."

# ── 4. Apply RBAC + Service for chaos-sec ─────────────────────────────────
echo ""
echo "[4/6] Applying chaos-sec RBAC and Service..."
kubectl apply -f deploy/rbac.yaml
kubectl apply -f deploy/service.yaml
echo "[4/6] Done."

# ── 5. Install Falco via Helm ──────────────────────────────────────────────
echo ""
echo "[5/6] Installing Falco via Helm..."
helm repo add falcosecurity https://falcosecurity.github.io/charts 2>/dev/null || true
helm repo update falcosecurity

helm upgrade --install falco falcosecurity/falco \
  -f falco/values.yaml \
  --namespace "${FALCO_NAMESPACE}" \
  --create-namespace \
  --timeout 5m

echo "[5/6] Falco installed. Waiting for DaemonSet to be ready (up to 3 min)..."
kubectl rollout status daemonset/falco -n "${FALCO_NAMESPACE}" --timeout=180s
kubectl get pods -n "${FALCO_NAMESPACE}"

# ── 6. Build binary and create ConfigMap for experiments ──────────────────
echo ""
echo "[6/6] Building chaos-sec binary and uploading experiment ConfigMap..."
make build

kubectl create configmap chaos-sec-experiments \
  --from-file=experiments/ \
  --namespace "${NAMESPACE}" \
  --dry-run=client -o yaml | kubectl apply -f -

echo "[6/6] Done."

echo ""
echo "──────────────────────────────────────────"
echo " Cluster is ready!"
echo ""
echo " Run experiments locally:"
echo "   ./bin/chaos-sec --experiments ./experiments \\"
echo "     --namespace ${NAMESPACE} \\"
echo "     --siem-port 8080 \\"
echo "     --report-out results.json"
echo "──────────────────────────────────────────"

