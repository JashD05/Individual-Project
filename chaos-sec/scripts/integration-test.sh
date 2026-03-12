#!/usr/bin/env bash
# integration-test.sh — End-to-end Phase 2 test:
#   1. Setup cluster (Kind + Calico + Falco)
#   2. Load chaos-sec Docker image into Kind
#   3. Create the chaos-sec Service (for Falco → SIEM routing)
#   4. Run chaos-sec as a Kubernetes Job (single-shot, no restart)
#   5. Wait for Job completion, stream logs, extract & validate JSON report
#
# Run via: make integration-test  (which chains docker-image -> this script)
# Run from the chaos-sec/ project root.
set -euo pipefail

NAMESPACE="chaos-sec-experiments"
REPORT="results-integration.json"
PASS=0

cleanup() {
  echo ""
  echo "── Teardown ──────────────────────────────"
  ./scripts/teardown-cluster.sh
}
trap cleanup EXIT

# ── 1. Setup cluster ───────────────────────────────────────────────────────
echo "══════════════════════════════════════════"
echo " Chaos-Sec Integration Test"
echo "══════════════════════════════════════════"
./scripts/setup-cluster.sh

# ── 2. Load image into Kind ────────────────────────────────────────────────
echo ""
echo "Loading chaos-sec:latest into Kind cluster..."
kind load docker-image chaos-sec:latest --name chaos-sec

# ── 3. Apply Service and RBAC (so Falco can reach the SIEM pod) ────────────
echo ""
echo "Applying RBAC and Service..."
kubectl apply -f deploy/rbac.yaml
kubectl apply -f deploy/service.yaml

# ── 4. Upload experiment files as ConfigMap ────────────────────────────────
echo ""
echo "Uploading experiment ConfigMap..."
kubectl create configmap chaos-sec-experiments \
  --from-file=experiments/ \
  --namespace "${NAMESPACE}" \
  --dry-run=client -o yaml | kubectl apply -f -

# ── 5. Wait for Falco to be fully ready ───────────────────────────────────
echo ""
echo "Waiting for Falco DaemonSet to be ready (may take 2-3 min)..."
kubectl rollout status daemonset/falco -n falco --timeout=240s

# Give Falco extra time to load rules after rollout reports ready
echo "Waiting 15s for Falco rule engine to warm up..."
sleep 15

# ── 6. Delete any previous Job run (idempotent) ───────────────────────────
echo ""
echo "Submitting chaos-sec Job..."
kubectl delete job chaos-sec-run -n "${NAMESPACE}" --ignore-not-found=true
kubectl apply -f deploy/job.yaml

# ── 7. Wait for the Job pod to be ready (SIEM is listening) ───────────────
echo ""
echo "Waiting for chaos-sec pod to become Ready..."
kubectl wait pod \
  -l app=chaos-sec \
  -n "${NAMESPACE}" \
  --for=condition=Ready \
  --timeout=120s

# ── 8. Stream logs until pod completes ────────────────────────────────────
echo ""
echo "Streaming chaos-sec experiment logs..."
POD=$(kubectl get pod -l app=chaos-sec -n "${NAMESPACE}" \
  -o jsonpath='{.items[0].metadata.name}')
kubectl logs -f "${POD}" -n "${NAMESPACE}" || true

# ── 9. Wait for Job to reach Complete/Failed ──────────────────────────────
echo ""
echo "Waiting for Job to complete (timeout 12m)..."
kubectl wait job/chaos-sec-run \
  -n "${NAMESPACE}" \
  --for=condition=complete \
  --timeout=12m 2>/dev/null \
|| kubectl wait job/chaos-sec-run \
  -n "${NAMESPACE}" \
  --for=condition=failed \
  --timeout=30s 2>/dev/null \
|| true

JOB_STATUS=$(kubectl get job chaos-sec-run -n "${NAMESPACE}" \
  -o jsonpath='{.status.conditions[0].type}' 2>/dev/null || echo "Unknown")
echo "  Job condition: ${JOB_STATUS}"

# ── 10. Extract JSON report via kubectl exec ───────────────────────────────
echo ""
echo "Extracting JSON report from pod..."
kubectl exec "${POD}" -n "${NAMESPACE}" \
  -- cat /reports/results.json > "${REPORT}" 2>/dev/null \
|| {
  echo "WARN: pod already terminated; reconstructing report from logs..."
  kubectl logs "${POD}" -n "${NAMESPACE}" 2>/dev/null \
    | python3 -c "
import sys, json
for line in sys.stdin:
    line = line.strip()
    try:
        obj = json.loads(line)
        # The report is a single JSON object with 'total_runs' key
        if 'total_runs' in obj:
            print(json.dumps(obj, indent=2))
            sys.exit(0)
    except Exception:
        pass
print('{}')
" > "${REPORT}" || echo "{}" > "${REPORT}"
}

# ── 11. Validate the JSON report ──────────────────────────────────────────
echo ""
echo "── Report Validation ─────────────────────"

if [ ! -f "${REPORT}" ] || [ ! -s "${REPORT}" ]; then
  echo "FAIL: report file '${REPORT}' is missing or empty."
  exit 1
fi

TOTAL=$(python3  -c "import json; d=json.load(open('${REPORT}')); print(d.get('total_runs', 0))")
PASSED=$(python3 -c "import json; d=json.load(open('${REPORT}')); print(d.get('passed', 0))")
FAILED=$(python3 -c "import json; d=json.load(open('${REPORT}')); print(d.get('failed', 0))")
MTTD_COUNT=$(python3 -c "
import json
d = json.load(open('${REPORT}'))
print(sum(1 for r in d.get('results', []) if r.get('mttd_seconds') is not None))
")

echo "  Total runs    : ${TOTAL}"
echo "  Passed        : ${PASSED}"
echo "  Failed        : ${FAILED}"
echo "  MTTD captured : ${MTTD_COUNT}/${TOTAL} experiments"

if [ "${FAILED}" -gt 0 ]; then
  echo ""
  echo "FAIL: ${FAILED} experiment(s) failed on the golden cluster."
  PASS=1
else
  echo ""
  echo "PASS: All ${TOTAL} experiments passed on the golden cluster. ✓"
fi

echo ""
echo "── Full Report ───────────────────────────"
python3 -m json.tool "${REPORT}"

exit "${PASS}"
