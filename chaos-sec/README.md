# Chaos-Sec

[![Go](https://img.shields.io/badge/Go-1.21+-00ADD8?logo=go)](https://go.dev)
[![Coverage](https://img.shields.io/badge/coverage-89.3%25-brightgreen)](chaos-sec/internal)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

A security chaos engineering tool for Kubernetes. Chaos-Sec automates validation of security controls (Pod Security Admission, NetworkPolicy, Falco runtime detection) by spawning controlled attacker pods and comparing observed behaviour against expected outcomes — producing a structured JSON report with pass/fail results and Mean Time To Detect (MTTD).

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                     chaos-sec binary                     │
│  Loader → Engine → k8s pkg → Report                     │
│                ↕                                         │
│            Mock SIEM (HTTP :8080/falco)                 │
└──────────────────────────┬──────────────────────────────┘
                           │ Kubernetes API
              ┌────────────┴───────────────┐
              │  Kind cluster              │
              │  ├── PSA (restricted)      │
              │  ├── Calico NetworkPolicy  │
              │  └── Falco DaemonSet       │
              └────────────────────────────┘
```

## Documentation

| Document | Description |
|---|---|
| [docs/architecture.md](docs/architecture.md) | System design, component breakdown, data flow |
| [docs/setup-guide.md](docs/setup-guide.md) | Full setup instructions, Makefile targets, troubleshooting |
| [docs/experiments.md](docs/experiments.md) | Experiment YAML schema, built-in experiments, adding new ones |
| [docs/report-format.md](docs/report-format.md) | JSON report schema with field descriptions and examples |
| [thesis/slides.md](thesis/slides.md) | Presentation slide deck (16 slides) |

---

## Prerequisites

| Tool | Version |
|---|---|
| Go | ≥ 1.21 |
| Docker | Latest |
| Kind | ≥ 0.20 |
| kubectl | ≥ 1.28 |
| Helm | ≥ 3.12 |

## Quickstart

```bash
# 1. Clone and enter the project
git clone https://github.com/JashD05/Individual-Project.git
cd Individual-Project/chaos-sec

# 2. Spin up Kind cluster with Calico + Falco
make setup-cluster

# 3. Build the binary
make build

# 4. Run all experiments
./bin/chaos-sec \
  --experiments ./experiments \
  --namespace   chaos-sec-experiments \
  --siem-port   8080 \
  --report-out  results.json

# 5. Tear down when done
make teardown-cluster
```

Expected output:
```
All 2 experiments PASSED ✓
```

## Makefile Targets

| Target | Description |
|---|---|
| `make build` | Compile `bin/chaos-sec` |
| `make test` | Unit tests with race detector |
| `make test-cover` | Tests + coverage report (89.3%) |
| `make setup-cluster` | Create Kind cluster + Calico + Falco |
| `make teardown-cluster` | Delete Kind cluster |
| `make integration-test` | Full end-to-end in-cluster test |
| `make analyse` | Phase 3 statistical analysis |

## Directory Layout

```
chaos-sec/
├── cmd/chaos-sec/        # CLI entry point (flags, wiring)
├── internal/
│   ├── engine/           # Experiment orchestration + MTTD measurement
│   ├── experiment/       # YAML loader + ExperimentSpec/Result types
│   ├── k8s/              # Pod create/wait/delete + outcome evaluation
│   ├── report/           # JSON report writer
│   └── siem/             # Mock Falco webhook server + AlertStore
├── experiments/          # Built-in YAML attack scenarios
├── falco/                # Falco Helm values + custom detection rules
├── policies/             # Kubernetes NetworkPolicy manifests
├── deploy/               # Kubernetes manifests for in-cluster deployment
├── scripts/              # Setup, teardown, integration, analysis scripts
├── docs/                 # Reference documentation
├── results/              # Phase 3 evaluation data (10 runs)
└── thesis/               # 5 thesis chapters + presentation slides
```

## CLI Flags

| Flag | Default | Description |
|---|---|---|
| `--experiments` | `./experiments` | Directory of YAML experiment files |
| `--namespace` | `chaos-sec-experiments` | Kubernetes namespace |
| `--siem-port` | `8080` | Mock SIEM webhook port (`/falco`) |
| `--report-out` | `-` (stdout) | Path for JSON report |
| `--timeout` | `5m` | Overall run timeout |

## Adding an Experiment

Drop a `*.yaml` file in `experiments/` — no Go changes needed:

```yaml
name: my-experiment
description: "What this attack tests"
image: busybox:1.36
command: ["sh", "-c", "cat /etc/shadow"]
namespace: chaos-sec-experiments
expected_outcome: blocked   # or "permitted"
falco_rule: read_sensitive_file_untrusted
host_path_mount: /etc       # optional
```

## Report Format

```json
{
  "generated_at": "2026-03-10T09:00:00Z",
  "total_runs": 2,
  "passed": 2,
  "failed": 0,
  "results": [
    {
      "spec": { "name": "host-path-access", ... },
      "actual_outcome": "blocked",
      "pass": true,
      "mttd_seconds": null
    }
  ]
}
```

## Test Coverage

```
engine      100.0%
experiment   96.2%
k8s          80.8%
report       86.7%
siem         94.7%
─────────────────
total        89.3%
```

