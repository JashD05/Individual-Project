# Chaos-Sec Architecture

## Overview

Chaos-Sec is a security chaos engineering tool for Kubernetes. It validates that security controls are working by spawning controlled "attacker" pods and comparing the observed outcome against what is expected. Results are written to a structured JSON report.

```
┌─────────────────────────────────────────────────────────────────┐
│                        chaos-sec binary                         │
│                                                                 │
│  ┌────────────┐   specs   ┌──────────────────────────────────┐  │
│  │  YAML      │ ────────► │           Engine                  │  │
│  │  Loader    │           │  for each spec:                  │  │
│  └────────────┘           │   1. ClearRule (AlertStore)      │  │
│                           │   2. PodRunner.Run(spec)         │  │
│  ┌────────────┐  alerts   │   3. WaitForAlert (SIEM)         │  │
│  │  Mock SIEM │ ◄──────── │   4. Compute MTTD                │  │
│  │  (webhook) │           │   5. Record ExperimentResult     │  │
│  └─────┬──────┘           └──────────────┬───────────────────┘  │
│        │                                 │ results              │
│        │ Falco JSON                      ▼                      │
│        │ alerts               ┌────────────────────┐           │
│        │                      │   Report Writer    │           │
│        │                      │   (JSON file /     │           │
│        │                      │    stdout)         │           │
│        │                      └────────────────────┘           │
└────────┼────────────────────────────────────────────────────────┘
         │
         │ HTTP POST /falco
         │
┌────────┴──────────┐     ┌──────────────────────────────────────┐
│   Falco DaemonSet │     │      Kubernetes API Server           │
│   (falco ns)      │     │                                      │
│                   │     │  - Pod Security Admission (PSA)      │
│  Watches syscalls │     │  - NetworkPolicy (Calico)            │
│  on all nodes     │     │  - RBAC                              │
└───────────────────┘     └──────────────────────────────────────┘
```

---

## Component Breakdown

### `cmd/chaos-sec/main.go`
CLI entry point. Parses flags, wires together all dependencies, and exits non-zero if any experiment fails (CI-friendly).

### `internal/experiment`
- **`types.go`** — `ExperimentSpec` (loaded from YAML) and `ExperimentResult` (output of one run).
- **`loader.go`** — Reads all `*.yaml` files from the experiments directory, validates required fields.

### `internal/k8s`
- **`client.go`** — Builds a Kubernetes clientset. Tries in-cluster config first, falls back to `~/.kube/config`.
- **`pod.go`** — `BuildAttackerPod`, `RunPod`, `WaitForPodCompletion`, `EvaluateOutcome`. Handles the PSA admission-error edge case as a PASS.

### `internal/engine`
- **`engine.go`** — Orchestrates experiments sequentially. For each spec: clears stale SIEM alerts, runs the pod, waits for a Falco alert, computes MTTD, records result.
- Depends on `PodRunner` interface — fully testable without a live cluster.

### `internal/siem`
- **`server.go`** — Lightweight HTTP webhook server. Stores incoming Falco JSON alerts in an in-memory `AlertStore` keyed by rule name.
- `WaitForAlert` polls every 500 ms until an alert arrives or the context times out.
- `ClearRule` removes stale alerts before each experiment (critical for accurate MTTD on repeated runs).

### `internal/report`
- **`report.go`** — Marshals `[]ExperimentResult` into a `Summary` JSON document and writes to a file or stdout.

---

## Data Flow

1. **Startup** — `main.go` loads YAML specs, starts Mock SIEM on `:8080`, builds Kubernetes clientset.
2. **Per-experiment loop** (sequential):
   - `AlertStore.ClearRule(spec.FalcoRule)` — prevents stale MTTD.
   - `k8s.RunPod(ctx, cs, spec, podName)` — creates pod, waits for completion, collects logs.
   - If admission control blocks pod creation and `expected_outcome == "blocked"` → immediate PASS.
   - `AlertStore.WaitForAlert(ctx, spec.FalcoRule)` — up to 30 s.
   - MTTD = `alert.ReceivedAt − result.StartTime`.
3. **Report** — Written to `--report-out` path (or stdout).
4. **Exit code** — Non-zero if any experiment failed (CI integration).

---

## Security Design Decisions

| Decision | Rationale |
|---|---|
| All experiments run in isolated Kind clusters | No production systems are ever affected |
| Attacker pods use `RestartPolicy: Never` | Run exactly once; no retry noise |
| Pod cleanup is deferred | Guaranteed cleanup even on error paths |
| `PodRunner` interface | Engine is fully unit-testable without a cluster |
| Structured JSON logging (`log/slog`) | Machine-readable; includes `experiment_name`, `timestamp`, `outcome` |
| Context propagation throughout | Experiments can never hang; all API calls respect the global timeout |
