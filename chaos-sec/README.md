# Chaos-Sec

A security chaos engineering orchestration tool for Kubernetes. Chaos-Sec automates the validation of security controls (NetworkPolicy, Pod Security Admission, runtime detection) by spawning controlled "attacker" pods and comparing observed behaviour against expected outcomes.

## Documentation

| Document | Description |
|---|---|
| [docs/architecture.md](docs/architecture.md) | System design, component breakdown, data flow |
| [docs/setup-guide.md](docs/setup-guide.md) | Full setup instructions, Makefile targets, troubleshooting |
| [docs/experiments.md](docs/experiments.md) | Experiment YAML schema, built-in experiments, adding new ones |
| [docs/report-format.md](docs/report-format.md) | JSON report schema with field descriptions and examples |

---

## Prerequisites

| Tool | Version |
|---|---|
| Go | ≥ 1.21 |
| Docker Desktop | Latest |
| Kind | ≥ 0.20 |
| kubectl | ≥ 1.28 |
| Helm | ≥ 3.12 (Phase 2 only) |

## Quickstart

```bash
# 1. Clone and enter the project
git clone <repo-url> && cd chaos-sec

# 2. Fetch dependencies
go mod tidy

# 3. Build the binary
make build

# 4. Create a Kind cluster
kind create cluster --name chaos-sec

# 5. Create the experiment namespace
kubectl create namespace chaos-sec-experiments

# 6. Run experiments (outputs JSON to stdout)
./bin/chaos-sec \
  --experiments ./experiments \
  --namespace   chaos-sec-experiments \
  --siem-port   8080 \
  --report-out  results.json
```

## Directory Layout

```
chaos-sec/
├── cmd/chaos-sec/        # Entry point
├── internal/
│   ├── engine/           # Orchestration engine (PodRunner interface)
│   ├── experiment/       # YAML loader + ExperimentSpec/Result types
│   ├── k8s/              # client-go wrappers (pod create, wait, delete)
│   ├── report/           # JSON report writer
│   └── siem/             # Mock Falco webhook server + AlertStore
├── experiments/          # YAML experiment payloads
├── policies/             # Kubernetes NetworkPolicy manifests
└── Makefile
```

## Running Tests

```bash
make test          # All unit tests with -race
make test-cover    # + coverage report
```

## CLI Flags

| Flag | Default | Description |
|---|---|---|
| `--experiments` | `./experiments` | Directory of YAML payload files |
| `--namespace` | `chaos-sec-experiments` | Kubernetes namespace |
| `--siem-port` | `8080` | Port for Mock SIEM webhook (`/falco`) |
| `--report-out` | `-` (stdout) | Path for JSON report |
| `--timeout` | `5m` | Overall run timeout |

## Adding an Experiment

Drop a new `*.yaml` file in `experiments/`. No Go code changes needed.

```yaml
name: my-experiment
description: What this tests.
image: busybox:1.36
command: ["sh", "-c", "echo test"]
namespace: chaos-sec-experiments
expected_outcome: blocked   # or "permitted"
falco_rule: my_falco_rule
```

## Report Format

```json
{
  "generated_at": "2026-03-10T09:00:00Z",
  "total_runs": 2,
  "passed": 2,
  "failed": 0,
  "results": [ ... ]
}
```
