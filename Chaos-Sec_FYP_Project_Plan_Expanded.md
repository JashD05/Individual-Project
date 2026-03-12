# FYP Project Plan: Chaos-Sec (Final)

**Author:** Jash Dashandi
**Goal:** Complete the orchestration platform, execute security experiments, integrate feedback loops, and evaluate the system against the defined Research Questions.
**Deadline:** 06 May 2026
**Plan Version:** 2.2 — Phases 1 & 2 Complete
**Last Updated:** 12 March 2026

---

## Timeline Overview

> [!IMPORTANT]
> All dates assume a **Week 1 start of 10 March 2026**. Deadline is **06 May 2026**. The plan targets completion by **04 May** to leave a 2-day buffer.

| Phase | Weeks | Calendar Dates | Focus | Status |
|---|---|---|---|---|
| 1 – Core Experiment Implementation | 1–2 | 10 Mar – 23 Mar | Go codebase, YAML payloads, K8s logic | ✅ Complete |
| 2 – Feedback Loop & Mock SIEM | 3–4 | 24 Mar – 06 Apr | SIEM webhook, Falco, MTTD calculation | ✅ Complete (ahead of schedule) |
| 3 – Evaluation & Data Gathering | 5 | 07 Apr – 13 Apr | Golden/misconfigured clusters, comparative analysis | ⏳ Up next |
| 4 – Data Analysis & Thesis Writing | 6–7 | 14 Apr – 27 Apr | Chapters 1–5 drafting and iteration | ⏳ Pending |
| 5 – Final Polish & Presentation | 8 | 28 Apr – 04 May | Code cleanup, demo video, slide deck, **submission** | ⏳ Pending |

> [!TIP]
> **Start writing early.** Begin drafting Chapters 1–2 (Introduction & Methodology) in the evenings during Phase 2 — these chapters don't depend on evaluation data and will take pressure off the compressed Phase 4.

---

## Prerequisites & Tooling

Ensure the following are installed and verified **before Week 1** begins.

| Tool | Version | Purpose |
|---|---|---|
| Go | ≥ 1.21 | Core language (required for `log/slog`) |
| Docker Desktop | Latest | Container runtime for Kind |
| Kind | ≥ 0.20 | Local Kubernetes clusters |
| kubectl | Matching cluster version | Cluster interaction |
| Helm | ≥ 3.12 | Falco deployment |
| Git | Latest | Version control |
| Python 3 (optional) | ≥ 3.10 | Data analysis & matplotlib charts |

**Verify with:**
```bash
go version && docker --version && kind version && kubectl version --client && helm version
```

---

## Phase 1: Core Experiment Implementation (Weeks 1–2 · 10–23 Mar)

*Focus: Transitioning from "Hello World" to actual security validation (Addressing Objective 2 & RQ1).*

### Deliverables
- [x] Compiling Go binary with `go build ./cmd/chaos-sec/`
- [x] Two working YAML experiment payloads
- [x] Unit tests passing for loader, pod builder, and evaluation logic
- [x] `go test ./...` exits cleanly

---

### 1A: Go Code Architecture & Structure

The Go codebase should follow a clean, modular layout from day one. This avoids costly refactors later and makes the codebase examinable.

**Recommended directory structure:**

```
chaos-sec/
├── cmd/
│   └── chaos-sec/
│       └── main.go            # Entry point — parses flags, wires dependencies
├── internal/
│   ├── engine/
│   │   ├── engine.go          # Orchestration Engine: runs experiments end-to-end
│   │   └── engine_test.go
│   ├── experiment/
│   │   ├── loader.go          # Reads & validates YAML payloads from disk
│   │   ├── types.go           # ExperimentSpec, ExperimentResult structs
│   │   └── loader_test.go
│   ├── k8s/
│   │   ├── client.go          # Wraps client-go: creates kubeconfig, returns clientset
│   │   ├── pod.go             # CreatePod, WaitForPod, GetPodLogs, DeletePod
│   │   └── pod_test.go
│   ├── siem/
│   │   ├── server.go          # HTTP webhook receiver (Mock SIEM)
│   │   ├── matcher.go         # Matches incoming Falco alerts to running experiments
│   │   └── server_test.go
│   └── report/
│       ├── report.go          # Aggregates results into JSON report
│       └── report_test.go
├── experiments/               # YAML experiment payload files
│   ├── network-egress.yaml
│   └── host-path-access.yaml
├── policies/                  # Kubernetes policy manifests
│   └── default-deny-egress.yaml
├── Makefile                   # Build, test, lint targets
├── go.mod
├── go.sum
└── README.md
```

**Key design principles to follow:**

- **Dependency injection over globals.** Pass the Kubernetes clientset and SIEM server as interfaces into the engine, not as package-level variables. This makes unit testing possible without a real cluster.
- **Interfaces for testability.** Define a `PodRunner` interface in `engine.go` so tests can inject a fake pod runner instead of hitting the Kubernetes API.
- **Structured logging.** Use `log/slog` (Go 1.21+) with JSON output so log lines are machine-readable. Every log entry should include `experiment_name`, `timestamp`, and `outcome`.
- **Context propagation.** Every function that calls the Kubernetes API must accept a `context.Context` as its first argument. Pass a timeout context (e.g., `context.WithTimeout(ctx, 2*time.Minute)`) from the engine so experiments can never hang indefinitely.

**Core structs (`internal/experiment/types.go`):**

```go
// ExperimentSpec is loaded from a YAML payload file.
type ExperimentSpec struct {
    Name           string   `yaml:"name"`
    Description    string   `yaml:"description"`
    Image          string   `yaml:"image"`           // e.g. "curlimages/curl:latest"
    Command        []string `yaml:"command"`          // e.g. ["curl", "-m", "5", "http://8.8.8.8"]
    ExpectedOutcome string  `yaml:"expected_outcome"` // "blocked" or "permitted"
    FalcoRule      string   `yaml:"falco_rule"`       // rule name expected to fire
    Namespace      string   `yaml:"namespace"`
    HostPathMount  string   `yaml:"host_path_mount,omitempty"` // optional, e.g. "/etc"
}

// ExperimentResult is produced by the engine after running one experiment.
type ExperimentResult struct {
    Spec        ExperimentSpec `json:"spec"`
    StartTime   time.Time      `json:"start_time"`
    EndTime     time.Time      `json:"end_time"`
    PodExitCode int            `json:"pod_exit_code"`
    ActualOutcome string       `json:"actual_outcome"` // "blocked" or "permitted"
    Pass        bool           `json:"pass"`            // true if actual == expected
    PodLogs     string         `json:"pod_logs"`
    MTTD        *float64       `json:"mttd_seconds,omitempty"` // nil if no Falco alert received
}
```

---

### 1B: YAML Experiment Payload Design

Each experiment is defined as a standalone YAML file in the `experiments/` directory. The loader reads all `*.yaml` files in that directory at startup, so adding a new experiment requires only dropping in a new file — no Go code changes.

**Network Egress Experiment (`experiments/network-egress.yaml`):**

```yaml
name: network-egress
description: >
  Spawns an attacker pod that attempts an outbound HTTP connection to 8.8.8.8:80.
  A correctly configured default-deny egress NetworkPolicy should block this.
  If the connection succeeds, the network policy has failed open.

image: curlimages/curl:8.7.1
command:
  - curl
  - --max-time
  - "5"
  - --silent
  - --output
  - /dev/null
  - --write-out
  - "%{http_code}"
  - http://8.8.8.8

namespace: chaos-sec-experiments

# "blocked" means we expect the pod to exit non-zero (connection refused/timeout).
# "permitted" means the curl succeeded — which is a FAIL in a hardened cluster.
expected_outcome: blocked

# The Falco rule we expect to fire when the egress attempt is made.
falco_rule: outbound_connection_not_in_allowlist
```

**Host Path Access Experiment (`experiments/host-path-access.yaml`):**

```yaml
name: host-path-access
description: >
  Attempts to create a pod that mounts a sensitive host directory (/etc) and
  reads /etc/shadow. Pod Security Admission (restricted profile) should block
  pod creation entirely. If the pod is created and the read succeeds, PSA has
  failed open or is misconfigured.

image: busybox:1.36
command:
  - sh
  - -c
  - "cat /host-etc/shadow && echo SUCCESS || echo BLOCKED"

namespace: chaos-sec-experiments

host_path_mount: /etc   # Chaos-Sec will inject this as a hostPath volume

expected_outcome: blocked

falco_rule: read_sensitive_file_untrusted
```

**Loader logic (`internal/experiment/loader.go`):**

```go
func LoadAll(dir string) ([]ExperimentSpec, error) {
    entries, err := os.ReadDir(dir)
    // ...
    for _, entry := range entries {
        if filepath.Ext(entry.Name()) != ".yaml" {
            continue
        }
        data, _ := os.ReadFile(filepath.Join(dir, entry.Name()))
        var spec ExperimentSpec
        if err := yaml.Unmarshal(data, &spec); err != nil {
            return nil, fmt.Errorf("invalid experiment %s: %w", entry.Name(), err)
        }
        if err := validate(spec); err != nil {
            return nil, fmt.Errorf("experiment %s failed validation: %w", entry.Name(), err)
        }
        specs = append(specs, spec)
    }
    return specs, nil
}
```

The `validate()` function should check that required fields (`name`, `image`, `command`, `expected_outcome`) are non-empty and that `expected_outcome` is one of `"blocked"` or `"permitted"`.

---

### 1C: Kubernetes Experiment Logic (client-go)

**Setting up the client (`internal/k8s/client.go`):**

```go
func NewClientset() (*kubernetes.Clientset, error) {
    // Try in-cluster config first (when Chaos-Sec runs inside the cluster).
    config, err := rest.InClusterConfig()
    if err != nil {
        // Fall back to kubeconfig for local development.
        kubeconfig := filepath.Join(os.Getenv("HOME"), ".kube", "config")
        config, err = clientcmd.BuildConfigFromFlags("", kubeconfig)
        if err != nil {
            return nil, fmt.Errorf("could not build kubeconfig: %w", err)
        }
    }
    return kubernetes.NewForConfig(config)
}
```

**Building the attacker pod spec (`internal/k8s/pod.go`):**

The pod spec must be constructed carefully. The attacker pod needs to be:
- **Labelled** with `app=chaos-sec` and `experiment=<name>` so it can be selected and cleaned up.
- **Short-lived** — `restartPolicy: Never` ensures it runs once and terminates.
- **Optionally privilege-limited** — for the network egress test, run as a non-root user to mimic a realistic escaped container. For the host-path test, the pod spec *intentionally* requests a hostPath volume to test whether PSA blocks it.

```go
func BuildAttackerPod(spec experiment.ExperimentSpec, podName string) *corev1.Pod {
    pod := &corev1.Pod{
        ObjectMeta: metav1.ObjectMeta{
            Name:      podName,
            Namespace: spec.Namespace,
            Labels: map[string]string{
                "app":        "chaos-sec",
                "experiment": spec.Name,
            },
        },
        Spec: corev1.PodSpec{
            RestartPolicy: corev1.RestartPolicyNever,
            Containers: []corev1.Container{
                {
                    Name:    "attacker",
                    Image:   spec.Image,
                    Command: spec.Command,
                },
            },
        },
    }

    // Inject hostPath volume if the experiment requires it.
    if spec.HostPathMount != "" {
        pod.Spec.Volumes = []corev1.Volume{{
            Name: "host-vol",
            VolumeSource: corev1.VolumeSource{
                HostPath: &corev1.HostPathVolumeSource{Path: spec.HostPathMount},
            },
        }}
        pod.Spec.Containers[0].VolumeMounts = []corev1.VolumeMount{{
            Name:      "host-vol",
            MountPath: "/host-etc",
        }}
    }

    return pod
}
```

**Polling for pod completion with retry (`internal/k8s/pod.go`):**

The naive approach of calling `Get` in a tight loop will hit Kubernetes API rate limits quickly. Use `wait.PollUntilContextTimeout` with exponential backoff:

```go
func WaitForPodCompletion(ctx context.Context, cs *kubernetes.Clientset, namespace, name string) (*corev1.Pod, error) {
    var completedPod *corev1.Pod

    err := wait.PollUntilContextTimeout(ctx, 3*time.Second, 2*time.Minute, true,
        func(ctx context.Context) (bool, error) {
            pod, err := cs.CoreV1().Pods(namespace).Get(ctx, name, metav1.GetOptions{})
            if err != nil {
                // Transient API error — retry.
                return false, nil
            }
            switch pod.Status.Phase {
            case corev1.PodSucceeded, corev1.PodFailed:
                completedPod = pod
                return true, nil
            default:
                return false, nil
            }
        },
    )
    return completedPod, err
}
```

**Determining pass/fail from pod exit code:**

```go
func EvaluateOutcome(pod *corev1.Pod, expected string) (actual string, pass bool) {
    exitCode := pod.Status.ContainerStatuses[0].State.Terminated.ExitCode
    if exitCode != 0 {
        actual = "blocked"
    } else {
        actual = "permitted"
    }
    return actual, actual == expected
}
```

**Important edge case — PSA blocks pod creation entirely:**
For the host-path experiment on a hardened cluster, the Kubernetes API server will reject the pod creation request immediately (HTTP 403). The `CreatePod` call itself will return an error. Chaos-Sec must treat this error as a PASS for `expected_outcome: blocked`:

```go
_, err = cs.CoreV1().Pods(ns).Create(ctx, pod, metav1.CreateOptions{})
if err != nil {
    if isAdmissionError(err) && spec.ExpectedOutcome == "blocked" {
        // PSA blocked pod creation — this is a PASS.
        return ExperimentResult{Pass: true, ActualOutcome: "blocked"}, nil
    }
    return ExperimentResult{}, fmt.Errorf("unexpected pod creation error: %w", err)
}
```

**Always clean up attacker pods after each experiment:**

```go
defer cs.CoreV1().Pods(ns).Delete(ctx, podName, metav1.DeleteOptions{
    GracePeriodSeconds: ptr(int64(0)),
})
```

---

## Phase 2: Feedback Loop & Mock SIEM Integration (Weeks 3–4 · 24 Mar – 06 Apr)

*Focus: Closing the loop to answer RQ3 regarding Mean Time to Detect (MTTD).*

### Deliverables
- [x] Mock SIEM server accepting Falco webhooks and storing alerts
- [x] MTTD computed and included in JSON report
- [x] Falco deployed on Kind cluster with custom rules firing on both experiments
- [x] Integration test: spawn experiment → receive Falco alert → calculate MTTD

---

### 2A: Mock SIEM Webhook Server (`internal/siem/server.go`)

The Mock SIEM is a lightweight Go HTTP server that listens for incoming Falco JSON alerts. It stores alerts in an in-memory map keyed by Falco rule name, so the engine can query it after spawning an attacker pod.

**Falco alert JSON structure (what arrives at the webhook):**

```json
{
  "rule": "outbound_connection_not_in_allowlist",
  "time": "2025-03-09T14:23:01.456789012Z",
  "priority": "WARNING",
  "output": "Outbound connection attempt by non-whitelisted binary (proc=curl ...)",
  "output_fields": {
    "container.id": "abc123",
    "proc.name": "curl",
    "fd.sip": "8.8.8.8"
  }
}
```

**Webhook server implementation:**

```go
type AlertStore struct {
    mu     sync.Mutex
    alerts map[string][]FalcoAlert // keyed by rule name
}

func (s *AlertStore) Handler(w http.ResponseWriter, r *http.Request) {
    var alert FalcoAlert
    if err := json.NewDecoder(r.Body).Decode(&alert); err != nil {
        http.Error(w, "bad request", http.StatusBadRequest)
        return
    }
    alert.ReceivedAt = time.Now() // Record exact receipt time for MTTD calc
    s.mu.Lock()
    s.alerts[alert.Rule] = append(s.alerts[alert.Rule], alert)
    s.mu.Unlock()
    w.WriteHeader(http.StatusOK)
}

// WaitForAlert blocks until an alert matching the given rule name is received,
// or the context deadline is exceeded.
func (s *AlertStore) WaitForAlert(ctx context.Context, ruleName string) (*FalcoAlert, error) {
    ticker := time.NewTicker(500 * time.Millisecond)
    defer ticker.Stop()
    for {
        select {
        case <-ctx.Done():
            return nil, fmt.Errorf("timed out waiting for Falco alert: %s", ruleName)
        case <-ticker.C:
            s.mu.Lock()
            alerts := s.alerts[ruleName]
            s.mu.Unlock()
            if len(alerts) > 0 {
                a := alerts[len(alerts)-1]
                return &a, nil
            }
        }
    }
}
```

**Starting the server in `main.go`:**

```go
store := siem.NewAlertStore()
http.HandleFunc("/falco", store.Handler)
go http.ListenAndServe(":8080", nil)
```

**MTTD calculation in the engine:**

```go
experimentStart := time.Now()
// ... spawn attacker pod, wait for completion ...

alertCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
defer cancel()
alert, err := siemStore.WaitForAlert(alertCtx, spec.FalcoRule)
if err == nil {
    mttd := alert.ReceivedAt.Sub(experimentStart).Seconds()
    result.MTTD = &mttd
}
```

---

### 2B: Falco Configuration

Falco must be deployed as a DaemonSet and configured to forward alerts to the Chaos-Sec webhook. Install via Helm:

```bash
helm repo add falcosecurity https://falcosecurity.github.io/charts
helm install falco falcosecurity/falco \
  --set falco.json_output=true \
  --set falco.http_output.enabled=true \
  --set falco.http_output.url=http://chaos-sec-siem.chaos-sec-experiments.svc:8080/falco \
  --namespace falco --create-namespace
```

**Custom Falco rules file (`falco-rules.yaml`):**

The default Falco ruleset needs two custom rules appended to reliably fire on the Chaos-Sec experiment scenarios:

```yaml
- rule: outbound_connection_not_in_allowlist
  desc: Detects outbound TCP connections from containers not in the allowlist
  condition: >
    outbound and container and
    not proc.name in (allowed_network_binaries) and
    fd.sip != "127.0.0.1"
  output: >
    Outbound connection attempt (proc=%proc.name sip=%fd.sip sport=%fd.sport
    container=%container.name pod=%k8s.pod.name)
  priority: WARNING
  tags: [network, chaos-sec]

- rule: read_sensitive_file_untrusted
  desc: Detects attempts to read sensitive host files from a container
  condition: >
    open_read and container and
    fd.name in (sensitive_files) and
    not proc.name in (trusted_binaries)
  output: >
    Sensitive file read attempt (file=%fd.name proc=%proc.name
    container=%container.name pod=%k8s.pod.name)
  priority: CRITICAL
  tags: [filesystem, chaos-sec]
```

---

## Phase 3: Evaluation & Data Gathering (Week 5 · 07–13 Apr)

*Focus: Proving the tool works and generating data for the dissertation (Addressing Next Step 3 & RQ2).*

### Deliverables
- [ ] `results-golden.json` — full run on hardened cluster (all experiments pass)
- [ ] `results-misconfigured.json` — full run on weak cluster (experiments fail)
- [ ] Manual timing comparison spreadsheet
- [ ] At least 5 repeated runs per cluster for statistical significance

---

### Task 3.1: Golden Cluster Setup

```bash
# Spin up a clean Kind cluster
kind create cluster --name golden

# Create experiment namespace
kubectl create namespace chaos-sec-experiments

# Apply default-deny egress NetworkPolicy
kubectl apply -f policies/default-deny-egress.yaml

# Enable Pod Security Admission (restricted)
kubectl label namespace chaos-sec-experiments \
  pod-security.kubernetes.io/enforce=restricted

# Install Falco with custom rules
helm install falco falcosecurity/falco -f falco-rules.yaml --namespace falco --create-namespace
```

**`policies/default-deny-egress.yaml`:**

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny-egress
  namespace: chaos-sec-experiments
spec:
  podSelector: {}
  policyTypes:
    - Egress
```

### Task 3.2: Misconfigured Cluster Setup

```bash
# Remove the egress policy
kubectl delete networkpolicy default-deny-egress -n chaos-sec-experiments

# Relabel namespace to disable PSA enforcement
kubectl label namespace chaos-sec-experiments \
  pod-security.kubernetes.io/enforce=privileged --overwrite
```

### Task 3.3: Comparative Analysis Data Collection

For each cluster configuration, run Chaos-Sec **5 times** and record every JSON report:

```bash
for i in $(seq 1 5); do
  ./chaos-sec \
    --experiments ./experiments \
    --namespace chaos-sec-experiments \
    --siem-port 8080 \
    --report-out "results-golden-run${i}.json"
done
```

**Manual timing checklist for comparison (perform alongside each automated run):**

| Step | Manual kubectl Method | Time to Record |
|---|---|---|
| Network egress check | `kubectl exec <pod> -- curl -m 5 http://8.8.8.8` | Stopwatch start→result |
| Egress result interpretation | Inspect stdout manually | Included above |
| Host path check | `kubectl apply -f priv-pod.yaml`, observe admission | Stopwatch start→response |
| Record findings | Write to spreadsheet | ~2 min overhead |

### Task 3.4: Data Analysis

- Compute **mean, median, and standard deviation** of MTTD across runs.
- Compute **total time for automated vs. manual** per experiment.
- Generate charts using Python (matplotlib/seaborn) or a spreadsheet tool:
  - Bar chart: automated vs. manual time per experiment
  - Box plot: MTTD distribution across runs
  - Table: pass/fail matrix for golden vs. misconfigured cluster

---

## Phase 4: Data Analysis & Thesis Writing (Weeks 6–7 · 14–27 Apr)

*Focus: Translating implementation and data into a well-structured dissertation.*

### Deliverables
- [ ] Complete thesis draft (target: 12,000–15,000 words)
- [ ] All figures, tables, and charts embedded
- [ ] Bibliography with ≥ 20 sources

### Chapter Plan

| Chapter | Title | Target Words | Key Content |
|---|---|---|---|
| 1 | Introduction & Literature Review | 3,000 | Chaos Engineering definition, "validation gap", existing tools (Chaos Mesh, kube-bench, Gremlin), research questions |
| 2 | Methodology | 2,000 | 5 Whys RCA, MoSCoW requirements, Go + Kubernetes API justification, ethical considerations |
| 3 | Architecture & Implementation | 3,500 | System architecture diagram, module walkthroughs, client-go challenges, Mock SIEM design |
| 4 | Results & Evaluation | 2,500 | RQ1 (experiment variety), RQ2 (automated vs manual comparison table), RQ3 (MTTD graphs from Mock SIEM) |
| 5 | Conclusion & Future Work | 1,000 | Summary of achievements, limitations, future directions (Azure Sentinel / AWS GuardDuty integration, expanded experiment library) |

### Thesis Milestones

| When | Target |
|---|---|
| During Phase 2 (evenings) | Chapters 1–2 first draft (Introduction & Methodology — no evaluation data needed) |
| Week 6 (14–20 Apr) | Chapter 3 (Architecture & Implementation) + Chapter 4 (Results & Evaluation) first draft, all charts generated |
| Week 7 (21–27 Apr) | Chapter 5 (Conclusion) complete, full proofread, submit to supervisor for quick feedback |

---

## Phase 5: Final Polish & Presentation Prep (Week 8 · 28 Apr – 04 May)

### Deliverables
- [ ] Clean, well-documented codebase with GoDoc comments on all exported functions
- [ ] `README.md` with setup instructions, quickstart guide, and architecture diagram
- [ ] Demo video (3–5 minutes) showing Chaos-Sec detecting a vulnerability
- [ ] Presentation slide deck (15–20 slides) addressing all three Research Questions with data

### Tasks

- **Task 5.1:** Clean up Go code, run `go vet`, `staticcheck`, ensure all tests pass. Add GoDoc comments to all exported functions. Write a solid `README.md` with setup instructions and a quickstart guide.
- **Task 5.2:** Record a pristine demo video of Chaos-Sec finding a vulnerability on the misconfigured cluster and the alert appearing in the Mock SIEM webhook logs.
- **Task 5.3:** Finalise the slide deck, ensuring all three Research Questions are answered with concrete data. Rehearse the presentation (aim for 15 minutes + 5 for questions).
- **Task 5.4:** Final thesis submission after incorporating supervisor feedback.

---

## Risk Register

| # | Risk | Likelihood | Impact | Mitigation |
|---|---|---|---|---|
| R1 | Falco fails to deploy on Kind (kernel module issues) | Medium | High | Use Falco in eBPF-probe mode (`--set driver.kind=ebpf`); test deployment in Week 2 before it's critical |
| R2 | Kind networking doesn't enforce NetworkPolicies | Medium | High | Install a CNI plugin that supports NetworkPolicies (e.g., Calico) via Kind config |
| R3 | client-go API changes break build | Low | Medium | Pin `k8s.io/client-go` to a specific version in `go.mod`; avoid `@latest` |
| R4 | MTTD measurements are inconsistent/noisy | Medium | Medium | Run each experiment 5+ times; report mean ± std dev; acknowledge variability in thesis |
| R5 | Time overrun on thesis writing | High | High | Start Chapters 1–2 during Phase 2 evenings; set daily word-count targets of ~1,500 words during Phase 4 |
| R6 | Supervisor unavailable for feedback in Week 7 | Medium | High | Submit draft by 24 Apr; have a peer reviewer as backup; don't block on feedback for polish phase |
| R7 | Docker Desktop resource limits cause cluster instability | Low | Medium | Allocate ≥ 4 CPU / 8 GB RAM to Docker; close unneeded applications during experiments |

---

## Testing Strategy

### Unit Tests (continuous throughout Phases 1–2)
- **Scope:** `internal/experiment`, `internal/k8s`, `internal/siem`, `internal/report`
- **Approach:** Interface-based mocking (fake `PodRunner`, fake `AlertStore`)
- **Command:** `go test ./... -v -race -cover`
- **Target:** ≥ 70% code coverage across core packages

### Integration Tests (Phase 2, end of Week 4)
- Spin up a Kind cluster, deploy Falco, run the full engine pipeline
- Validate that the JSON report contains correct pass/fail results and MTTD values
- Script this as a `make integration-test` target

### End-to-End Validation (Phase 3)
- Golden cluster: **all experiments must pass**
- Misconfigured cluster: **all experiments must fail** (detecting the misconfiguration)
- These runs double as evaluation data for the thesis

---

## Build & CI Automation

**`Makefile` targets:**

```makefile
.PHONY: build test lint integration-test clean

build:
	go build -o bin/chaos-sec ./cmd/chaos-sec/

test:
	go test ./... -v -race -cover

lint:
	go vet ./...
	staticcheck ./...

integration-test: build
	./scripts/integration-test.sh

clean:
	rm -rf bin/
	kind delete cluster --name golden 2>/dev/null || true
```

> [!TIP]
> Even without a full CI system, running `make lint test` before every commit prevents regressions.

---

## Ethical Considerations

- All experiments run inside **isolated, local Kind clusters** — no production systems are affected.
- No real user data is processed or stored.
- The "attacker" pods perform benign actions (HTTP requests, file reads) that only test policy enforcement.
- All container images used are **publicly available** and unmodified.
- This project does not require formal ethics board approval, but include a brief ethics statement in the Methodology chapter.

---

## Supervision & Milestone Schedule

| Date | Milestone | Agenda |
|---|---|---|
| End of Week 2 (23 Mar) | Phase 1 review | Demo: Go binary compiles, experiments load, pod spawns |
| End of Week 4 (06 Apr) | Phase 2 review | Demo: Falco alert → Mock SIEM → MTTD in JSON report |
| End of Week 5 (13 Apr) | Phase 3 review | Present: golden vs. misconfigured results, comparison table |
| Mid-Week 7 (24 Apr) | Thesis draft review | Submit Chapters 1–5 draft for supervisor feedback |
| 04 May | Final submission | Thesis, code, demo video, slide deck — **2 days before deadline** |

---

## Implementation Checklist

### Phase 1 — Core Implementation
| Task | Area | Status |
|---|---|---|
| Directory structure & `go.mod` | Architecture | ✅ |
| `ExperimentSpec` / `ExperimentResult` structs | Architecture | ✅ |
| YAML loader + validator | YAML Payloads | ✅ |
| `network-egress.yaml` payload | YAML Payloads | ✅ |
| `host-path-access.yaml` payload | YAML Payloads | ✅ |
| `NewClientset()` with in-cluster fallback | client-go | ✅ |
| `BuildAttackerPod()` with hostPath injection | client-go | ✅ |
| `WaitForPodCompletion()` with backoff | client-go | ✅ |
| PSA admission error handling | client-go | ✅ |
| Pod cleanup (deferred delete) | client-go | ✅ |
| Unit tests for loader, pod builder, evaluator | Testing | ✅ |

### Phase 2 — Mock SIEM & Feedback Loop
| Task | Area | Status |
|---|---|---|
| Falco webhook HTTP server | Mock SIEM | ✅ |
| `WaitForAlert()` polling logic | Mock SIEM | ✅ |
| `ClearRule()` for stale alert prevention | Mock SIEM | ✅ |
| MTTD calculation in engine | Mock SIEM | ✅ |
| Engine calls `ClearRule` before each pod spawn | Engine | ✅ |
| Falco Helm deployment + custom rules | Falco | ✅ |
| Falco chart ConfigMap patch (Kind compatibility) | Falco | ✅ |
| Integration test (end-to-end pipeline) | Testing | ✅ |
| JSON report output | Architecture | ✅ |
| `docs/` folder with architecture, setup, experiment, report docs | Documentation | ✅ |

### Phase 3 — Evaluation
| Task | Area | Status |
|---|---|---|
| Golden cluster setup & validation | Evaluation | ☐ |
| Misconfigured cluster setup & validation | Evaluation | ☐ |
| 5× repeated runs per cluster | Evaluation | ☐ |
| Manual timing comparison | Evaluation | ☐ |
| Data analysis & chart generation | Evaluation | ☐ |

### Phase 4 — Thesis
| Task | Area | Status |
|---|---|---|
| Chapter 1: Introduction & Literature Review | Writing | ☐ |
| Chapter 2: Methodology | Writing | ☐ |
| Chapter 3: Architecture & Implementation | Writing | ☐ |
| Chapter 4: Results & Evaluation | Writing | ☐ |
| Chapter 5: Conclusion & Future Work | Writing | ☐ |
| Proofreading & formatting | Writing | ☐ |

### Phase 5 — Polish
| Task | Area | Status |
|---|---|---|
| Code cleanup, GoDoc, `go vet` | Code Quality | ☐ |
| `README.md` with quickstart | Documentation | ☐ |
| Demo video recording | Presentation | ☐ |
| Slide deck (15–20 slides) | Presentation | ☐ |
| Final thesis submission | Submission | ☐ |
