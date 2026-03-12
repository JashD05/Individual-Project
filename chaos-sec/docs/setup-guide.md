# Setup Guide

Complete instructions for running Chaos-Sec locally against a Kind cluster.

---

## Prerequisites

| Tool | Version | Install |
|---|---|---|
| Go | ≥ 1.21 | https://go.dev/dl |
| Docker Desktop | Latest | https://docs.docker.com/get-docker |
| Kind | ≥ 0.20 | `go install sigs.k8s.io/kind@latest` |
| kubectl | ≥ 1.28 | https://kubernetes.io/docs/tasks/tools |
| Helm | ≥ 3.12 | `sudo snap install helm --classic` |
| Python 3 | ≥ 3.10 | (used by setup scripts) |

Verify:

```bash
go version && docker --version && kind version && kubectl version --client && helm version
```

---

## Quick Setup (automated)

The `make setup-cluster` target does everything: creates a Kind cluster, installs Calico CNI, applies NetworkPolicy and PSA labels, deploys Falco, and uploads experiment configs.

```bash
git clone https://github.com/jashd34/Individual-Project.git
cd Individual-Project/chaos-sec

make build
make setup-cluster

./bin/chaos-sec \
  --experiments ./experiments \
  --namespace   chaos-sec-experiments \
  --siem-port   8080 \
  --report-out  results.json
```

---

## Manual Step-by-Step

### 1. Create the Kind cluster

```bash
kind create cluster --config deploy/kind-config.yaml
```

The Kind config (`deploy/kind-config.yaml`) disables the default CNI so Calico can be used instead — required for NetworkPolicy enforcement.

### 2. Install Calico CNI

```bash
kubectl apply -f https://raw.githubusercontent.com/projectcalico/calico/v3.29.1/manifests/calico.yaml
kubectl rollout status daemonset/calico-node -n kube-system --timeout=180s
kubectl wait --for=condition=Ready node --all --timeout=120s
```

### 3. Create the experiment namespace

```bash
kubectl apply -f deploy/namespace.yaml
```

This creates `chaos-sec-experiments` with PSA `restricted` enforcement — pods requesting hostPath volumes, root access, or missing seccomp profiles will be rejected by the API server.

### 4. Apply NetworkPolicy

```bash
kubectl apply -f policies/default-deny-egress.yaml
```

Blocks all egress from the experiment namespace. The `network-egress` experiment validates this policy is enforced.

### 5. Apply RBAC and Service

```bash
kubectl apply -f deploy/rbac.yaml
kubectl apply -f deploy/service.yaml
```

The Service exposes port 8080 inside the cluster so Falco can reach the Mock SIEM webhook.

### 6. Install Falco

```bash
helm repo add falcosecurity https://falcosecurity.github.io/charts
helm repo update falcosecurity

helm upgrade --install falco falcosecurity/falco \
  --version 7.2.1 \
  -f falco/values.yaml \
  --namespace falco \
  --create-namespace \
  --timeout 5m
```

> **Note:** Falco chart 7.x generates a duplicate `rules_file` key alongside `rules_files` in the ConfigMap, which causes Falco to crash. The `make setup-cluster` script patches this automatically. If installing manually, run:
>
> ```bash
> kubectl get configmap falco -n falco -o json \
>   | python3 -c "
> import json, sys
> cm = json.load(sys.stdin)
> lines = cm['data']['falco.yaml'].splitlines()
> out, skip = [], False
> for line in lines:
>     if line == 'rules_file:': skip = True; continue
>     if skip:
>         if line.startswith('- '): continue
>         skip = False
>     out.append(line)
> cm['data']['falco.yaml'] = '\n'.join(out)
> print(json.dumps(cm))
> " | kubectl replace -f -
> kubectl rollout restart daemonset/falco -n falco
> kubectl rollout status daemonset/falco -n falco --timeout=180s
> ```

### 7. Build and run

```bash
make build

./bin/chaos-sec \
  --experiments ./experiments \
  --namespace   chaos-sec-experiments \
  --siem-port   8080 \
  --report-out  results.json \
  --timeout     5m
```

---

## Makefile Targets

| Target | Description |
|---|---|
| `make build` | Compile `bin/chaos-sec` |
| `make test` | Run all unit tests with `-race` |
| `make test-cover` | Unit tests + coverage report |
| `make lint` | `go vet ./...` |
| `make setup-cluster` | Full cluster setup (Kind + Calico + Falco) |
| `make teardown-cluster` | Delete the Kind cluster |
| `make docker-build` | Build Docker image `chaos-sec:latest` |
| `make docker-image` | Build + load image into Kind |
| `make integration-test` | Full end-to-end test inside cluster |

---

## Teardown

```bash
make teardown-cluster
```

This deletes the Kind cluster and all associated resources.

---

## Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| `both 'rules_files' and 'rules_file' keys set` | Falco chart bug | Run the ConfigMap patch in step 6 above |
| `could not initialize inotify handler` | Kind hits inotify limit | Already handled: `watch_config_files: false` in `falco/values.yaml` |
| `NetworkPolicy not enforced` | kindnet CNI doesn't support NetworkPolicy | Ensure Calico is installed and `disableDefaultCNI: true` in kind-config |
| Experiments pass but MTTD is nil | PSA blocks pod before it runs — no syscalls reach Falco | Expected on golden cluster; MTTD populated on misconfigured cluster |
| `pods is forbidden: violates PodSecurity` for network-egress | PSA restricted blocks plain pods | This is the correct PASS — attacker pod intentionally has no securityContext |
