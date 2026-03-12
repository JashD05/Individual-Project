# Chapter 3: Architecture & Implementation

**Word count target: ~3,500**

---

## 3.1 System Overview

Chaos-Sec is a Go binary that orchestrates security experiments against a Kubernetes cluster. Figure 3.1 shows the high-level architecture.

```
┌─────────────────────────────────────────────────────────────────┐
│                        chaos-sec binary                         │
│                                                                 │
│  ┌────────────┐   specs   ┌──────────────────────────────────┐  │
│  │  YAML      │ ────────► │           Engine                  │  │
│  │  Loader    │           │  for each spec:                   │  │
│  └────────────┘           │   1. ClearRule (AlertStore)       │  │
│                           │   2. PodRunner.Run(spec)          │  │
│  ┌────────────┐  alerts   │   3. WaitForAlert (SIEM)          │  │
│  │  Mock SIEM │ ◄──────── │   4. Compute MTTD                 │  │
│  │  (webhook) │           │   5. Record ExperimentResult      │  │
│  └─────┬──────┘           └──────────────┬────────────────────┘  │
│        │                                 │ results               │
│        │ Falco JSON                      ▼                       │
│        │ alerts               ┌────────────────────┐            │
│        │                      │   Report Writer    │            │
│        │                      └────────────────────┘            │
└────────┼────────────────────────────────────────────────────────┘
         │ HTTP POST /falco
┌────────┴──────────┐     ┌──────────────────────────────────────┐
│   Falco DaemonSet │     │      Kubernetes API Server           │
│   (falco ns)      │     │  - Pod Security Admission (PSA)      │
│  Watches syscalls │     │  - NetworkPolicy (Calico CNI)        │
└───────────────────┘     └──────────────────────────────────────┘
```
*Figure 3.1: Chaos-Sec system architecture*

The binary is structured around five internal packages: `experiment` (YAML loading), `k8s` (Kubernetes API), `engine` (orchestration), `siem` (Mock SIEM webhook), and `report` (JSON output). A `cmd/chaos-sec/main.go` entry point wires these together and exposes a CLI flag interface.

---

## 3.2 Experiment Definition (YAML Loader)

### 3.2.1 Schema Design

Experiments are defined as YAML files in a directory passed via `--experiments`. Each file maps to an `ExperimentSpec` struct:

```go
type ExperimentSpec struct {
    Name            string   `yaml:"name"`
    Description     string   `yaml:"description"`
    Image           string   `yaml:"image"`
    Command         []string `yaml:"command"`
    ExpectedOutcome string   `yaml:"expected_outcome"` // "blocked" or "permitted"
    FalcoRule       string   `yaml:"falco_rule"`
    Namespace       string   `yaml:"namespace"`
    HostPathMount   string   `yaml:"host_path_mount,omitempty"`
}
```

The `ExpectedOutcome` field constrains the tool's vocabulary to two values: `blocked` (the security control should prevent the action) and `permitted` (the action should succeed). This binary encoding simplifies pass/fail evaluation to a single string comparison.

### 3.2.2 Loader Implementation

`LoadAll(dir string)` reads all `*.yaml` files from the given directory using `os.ReadDir`, unmarshals each with `sigs.k8s.io/yaml` (which handles both YAML and JSON), and validates required fields. The validation function checks that `name`, `image`, `command`, `expected_outcome`, and `namespace` are non-empty, and that `expected_outcome` is one of the two accepted values. An invalid file causes the binary to exit immediately with an error, preventing silent failures.

The directory-scan approach means adding a new experiment requires no Go code changes — an operator drops a new YAML file into the `experiments/` directory and the next run picks it up.

---

## 3.3 Kubernetes Integration (client-go)

### 3.3.1 Client Initialisation

The Kubernetes client is built using `k8s.io/client-go`. The `NewClientset()` function attempts in-cluster configuration first (using the pod's service account token when Chaos-Sec runs as a cluster Job), falling back to the local `~/.kube/config` for development use. The `KUBECONFIG` environment variable is also honoured.

### 3.3.2 Attacker Pod Construction

`BuildAttackerPod` constructs a `corev1.Pod` spec from an `ExperimentSpec`. Key design decisions:

- **`RestartPolicy: Never`** — the pod runs exactly once. Kubernetes will not retry if it fails, preventing repeated attack attempts.
- **Labels** — `app=chaos-sec` and `experiment=<name>` are applied to every attacker pod, enabling bulk cleanup via label selectors.
- **hostPath injection** — if `spec.HostPathMount != ""`, a `HostPathVolumeSource` is injected into the pod spec. This is intentionally insecure — the `host-path-access` experiment needs the volume to be present so that PSA (or its absence) can be tested.

Notably, the attacker pod spec deliberately omits security context fields (`securityContext`, `capabilities.drop`, `seccompProfile`). This is intentional: a real attacker-controlled pod would not include these fields, and their absence triggers PSA `restricted` rejection on the golden cluster.

### 3.3.3 Pod Lifecycle

`RunPod` is the central function coordinating the pod lifecycle:

1. **Create** — `cs.CoreV1().Pods(ns).Create(ctx, pod, ...)`. If the API server returns a 403 with an admission error message (`is forbidden`, `violates PodSecurity`, `admission webhook`), and the experiment expects `blocked`, this is immediately treated as a PASS. No pod was created; no cleanup is needed.

2. **Wait** — `WaitForPodCompletion` uses `wait.PollUntilContextTimeout` with a 3-second poll interval and a 2-minute ceiling. This avoids hammering the API server while ensuring the tool does not wait indefinitely.

3. **Evaluate** — `EvaluateOutcome` reads the container's `TerminationState.ExitCode`. Exit code 0 → `permitted`; non-zero → `blocked`. This is compared to `spec.ExpectedOutcome` to produce the `pass` boolean.

4. **Cleanup** — a `defer` statement unconditionally deletes the pod with `GracePeriodSeconds=0` using a fresh background context (so cleanup succeeds even if the experiment context has timed out).

### 3.3.4 PSA Admission Edge Case

The most significant implementation challenge was correctly handling Pod Security Admission rejection. When PSA is active and a pod spec violates the `restricted` profile, the Kubernetes API server returns an HTTP 403 error during the `Create` call — not after scheduling. The pod never reaches `Pending` or `Running` state. A naive implementation waiting for `PodSucceeded` or `PodFailed` would hang indefinitely.

The solution is `isAdmissionError(err)`, which inspects the error string for markers (`is forbidden`, `violates PodSecurity`, `admission webhook`). When an admission error is detected and the experiment's `expected_outcome` is `blocked`, the result is immediately recorded as a PASS with `actual_outcome = "blocked"`. This design ensures that hardened clusters pass the `host-path-access` experiment without any pod actually running.

---

## 3.4 Mock SIEM & MTTD Feedback Loop

### 3.4.1 AlertStore

The Mock SIEM is an in-process HTTP server backed by an `AlertStore` — a thread-safe map from Falco rule name to a slice of received `FalcoAlert` structs:

```go
type AlertStore struct {
    mu     sync.Mutex
    alerts map[string][]FalcoAlert
}
```

`sync.Mutex` protects concurrent writes from Falco's HTTP POSTs and concurrent reads from the engine's `WaitForAlert` goroutine.

### 3.4.2 Webhook Handler

The `Handler` method decodes the incoming Falco JSON payload, stamps it with `ReceivedAt = time.Now()`, and appends it to the map. The `ReceivedAt` timestamp — rather than Falco's own `time` field — is used for MTTD calculation. This is intentional: Falco's `time` field reflects when the syscall occurred inside the kernel, whereas `ReceivedAt` reflects when the alert was actionable in the SIEM. MTTD from the operator's perspective is the time from attack start to actionable alert.

### 3.4.3 WaitForAlert and ClearRule

`WaitForAlert(ctx, ruleName)` polls the `AlertStore` every 500 milliseconds until a matching alert is found or the context deadline is exceeded (30 seconds by default). This blocking call is placed after the pod runner returns, so the timer starts at pod creation time, not at pod completion — capturing any Falco alerts that fire during pod execution.

`ClearRule(ruleName)` is called before each experiment to remove stale alerts for that rule. Without this, a Falco alert from run *N* could be matched during run *N+1*, producing an incorrect (and very low) MTTD value. This is critical for the Phase 3 five-repetition study.

### 3.4.4 MTTD Calculation

```go
mttd := alert.ReceivedAt.Sub(result.StartTime).Seconds()
result.MTTD = &mttd
```

`result.StartTime` is set at the beginning of `k8s.RunPod` — before the `Create` call. This means MTTD includes pod scheduling latency, which is appropriate: from an operator's perspective, the "attack" begins when the workload is submitted.

`MTTD` is a `*float64` (pointer). When no alert arrives within the timeout, it is `nil` and serialises to JSON `null`. This distinguishes "no detection" from "detected in 0 seconds."

---

## 3.5 Orchestration Engine

The `Engine` struct holds a `PodRunner` interface and a `*siem.AlertStore`. Using an interface rather than a concrete Kubernetes client is the central testability decision: unit tests inject a `fakePodRunner` that returns canned results without any cluster interaction.

```go
type PodRunner interface {
    Run(ctx context.Context, spec experiment.ExperimentSpec) (experiment.ExperimentResult, error)
}
```

The engine executes experiments **sequentially** — one at a time. Parallel execution was considered but deferred: parallel pod creation increases cluster load and makes MTTD attribution ambiguous when two experiments share a Falco rule.

Error handling follows a "keep going" policy: if one experiment errors (e.g., a transient API timeout), the engine records an `actual_outcome: "error"` result and continues with the next experiment, rather than aborting the entire run. This ensures the report always covers all experiments.

---

## 3.6 Report Writer

The `report.Write` function marshals a `Summary` struct (containing aggregate counts and the full `[]ExperimentResult` slice) to indented JSON. Writing to `-` outputs to stdout; any other value is treated as a file path. The JSON schema is stable across runs, making it suitable for ingestion by dashboards or data analysis scripts.

---

## 3.7 Falco Integration

### 3.7.1 Deployment

Falco is deployed as a DaemonSet via Helm (chart version 7.2.1, Falco 0.42.1). The `falco/values.yaml` configures:
- `driver.kind: modern_ebpf` — avoids kernel module compilation, which fails on many Docker Desktop / Kind setups.
- `falco.json_output: true` — all alerts emitted as JSON.
- `falco.http_output.url` — points to the chaos-sec Kubernetes Service at `http://chaos-sec.chaos-sec-experiments.svc.cluster.local:8080/falco`.
- `watch_config_files: false` — disables inotify-based config watching, which exhausts the kernel's `fs.inotify.max_user_instances` limit inside Kind nodes.

### 3.7.2 Chart Compatibility Issue

A notable implementation challenge arose from a bug in Falco Helm chart versions 7.x and 8.x: the chart's ConfigMap template generates both `rules_file` (deprecated singular key) and `rules_files` (current plural key) in `falco.yaml`. Falco 0.42+ treats this as a fatal configuration error, crashing the container immediately. The `setup-cluster.sh` script applies a Python-based post-install patch to remove the singular key before restarting the DaemonSet.

### 3.7.3 Custom Rules

Two custom Falco rules are defined in `falco/values.yaml` under `customRules`, mounted into the DaemonSet at `/etc/falco/chaos_sec_rules.yaml`:

- **`outbound_connection_not_in_allowlist`** — fires on outbound TCP connections from containers whose process name is not in the `allowed_network_binaries` macro.
- **`read_sensitive_file_untrusted`** — fires when a container reads a file in the `sensitive_files` macro (which includes `/etc/shadow`) via a process not in the `trusted_binaries` macro.

---

## 3.8 Testing Strategy

### Unit Tests

27 unit tests cover all five internal packages, run with `go test ./... -race -count=1`. Interface mocking is used throughout: the engine is tested against a `fakePodRunner`; the SIEM server tests use `httptest.NewRecorder` and crafted HTTP requests. Key test cases include:
- `TestEngine_MTTDComputed` — injects a Falco alert after 50 ms and verifies MTTD is non-nil and non-negative.
- `TestIsAdmissionError` — verifies the admission error detector on both matching and non-matching error strings.
- `TestClearRule_RemovesOnlyTargetRule` — verifies stale alert clearing does not affect other rules.

### Integration Test

`make integration-test` builds the Docker image, loads it into Kind, applies all manifests, submits chaos-sec as a Kubernetes Job, and validates the JSON report. This test exercises the full end-to-end pipeline including the Falco → Mock SIEM webhook path.

---

## 3.9 Implementation Challenges

| Challenge | Root Cause | Resolution |
|---|---|---|
| PSA blocks pod before scheduling | API server rejects at admission, not at scheduling | `isAdmissionError` handler treats 403 as conditional PASS |
| Falco crashes on startup | Helm chart generates duplicate `rules_file`/`rules_files` keys | Post-install ConfigMap patch in `setup-cluster.sh` |
| Inotify limit in Kind | Kind nodes share host kernel inotify instances | `watch_config_files: false` in Falco values |
| `fd.dport` invalid output token | Falco 0.42.x removed this field from output formatting | Removed from custom rule output strings |
| MTTD null in local runs | Falco sends to cluster-internal URL; local process unreachable | Documented as limitation; MTTD works in `make integration-test` (in-cluster Job) |
| network-egress false positive | Kind does not route to external IPs regardless of NetworkPolicy | Documented as threat to validity; separate validation on cloud cluster recommended |

---

## 3.10 Deployment Architecture

Chaos-Sec can be run in two modes:

### Local Mode (development)

The binary runs on the developer's workstation and connects to the cluster via `~/.kube/config`. This is the primary mode used during Phase 3 evaluation. The Mock SIEM listens on a local port (e.g., `:8080`), but Falco's webhook URL points to the cluster-internal Service, so Falco alerts do not reach the local SIEM — MTTD is not measured.

```
Developer workstation                  Kind cluster (Docker)
┌────────────────────────┐            ┌─────────────────────────────┐
│  ./bin/chaos-sec       │            │  chaos-sec-experiments ns   │
│  (SIEM on :8080)       │◄──────────►│  attacker pod               │
│                        │  kubectl   │                             │
│  results.json          │            │  Falco → svc:8080           │
└────────────────────────┘            │  (unreachable from host)    │
                                      └─────────────────────────────┘
```

### In-Cluster Mode (integration test / production)

Chaos-Sec runs as a Kubernetes Job inside the cluster. Falco's webhook URL resolves to the Chaos-Sec Service, enabling MTTD measurement. The JSON report is written to a volume mount.

```
chaos-sec-experiments ns
┌─────────────────────────────────────┐
│  chaos-sec Job pod                  │
│  (SIEM on :8080)                    │◄── Falco alerts (HTTP POST)
│  mounts: experiments ConfigMap      │
│           reports EmptyDir          │
└─────────────────────────────────────┘
              ▲
              │ spawns + polls
              ▼
┌─────────────────────────────────────┐
│  attacker pod (short-lived)         │
│  labels: app=chaos-sec              │
│  RestartPolicy: Never               │
└─────────────────────────────────────┘
```

The Service (`deploy/service.yaml`) exposes port 8080 as a ClusterIP, making the webhook reachable from Falco's DaemonSet pods on all nodes.

### RBAC

The Chaos-Sec ServiceAccount is granted only the permissions needed:

| Resource | Verbs |
|---|---|
| pods | create, get, list, delete, watch |
| pods/log | get |
| namespaces | get |

This minimal footprint follows the principle of least privilege — Chaos-Sec cannot modify cluster configuration, access secrets, or interact with any resource beyond its attacker pods.

---

## 3.11 CI/CD Integration

The binary's exit code design enables direct use as a CI gate:

```bash
# In a CI pipeline (e.g., GitHub Actions):
./bin/chaos-sec \
  --experiments ./experiments \
  --namespace chaos-sec-experiments \
  --report-out results-${CI_RUN_NUMBER}.json

# Returns exit code 1 if any experiment failed → pipeline fails
```

A JSON report is archived as a CI artefact, providing an audit trail of security posture over time. The `make integration-test` target packages this into a full cluster lifecycle (create → run → validate → destroy).

---

## 3.12 Extensibility

Adding a new security experiment requires only creating a YAML file:

```yaml
name: privilege-escalation
description: Tests that privileged container mode is blocked by PSA.
image: busybox:1.36
command: ["nsenter", "--mount=/proc/1/ns/mnt", "--", "cat", "/etc/shadow"]
namespace: chaos-sec-experiments
expected_outcome: blocked
falco_rule: launch_privileged_container
```

No Go code changes, rebuilds, or redeployments are required. This plugin-like design means that as new Kubernetes security features are released (e.g., ValidatingAdmissionPolicy in Kubernetes 1.30), experiments can be added immediately.

The `PodRunner` interface could similarly be implemented for cloud providers: an AWS-specific implementation could spawn ECS tasks or Lambda functions instead of Kubernetes pods, extending the validation framework beyond Kubernetes.
