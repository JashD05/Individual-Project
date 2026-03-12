# Experiment Reference

Experiments are standalone YAML files in the `experiments/` directory. Chaos-Sec loads all `*.yaml` files at startup — adding a new experiment requires no Go code changes.

---

## YAML Schema

```yaml
name: string               # Required. Unique identifier (used in logs and report).
description: string        # Required. Human-readable description for the report.
image: string              # Required. Container image for the attacker pod.
command: [string]          # Required. Command + args to run in the container.
namespace: string          # Required. Kubernetes namespace to create the pod in.
expected_outcome: string   # Required. "blocked" or "permitted".
falco_rule: string         # Optional. Falco rule name to wait for (used for MTTD).
host_path_mount: string    # Optional. Host path to mount at /host-etc inside the pod.
```

### `expected_outcome` values

| Value | Meaning |
|---|---|
| `blocked` | The security control should prevent the action (pod rejected by PSA, connection timed out, etc.) |
| `permitted` | The action should succeed — used to verify an allow-list works correctly |

---

## Built-in Experiments

### `network-egress.yaml`

**What it tests:** Default-deny egress NetworkPolicy

**Mechanism:** Spawns a `curl` pod that attempts an outbound HTTP request to `8.8.8.8`. On a correctly configured cluster, Calico should drop the packets and `curl` should time out (non-zero exit code → `blocked`).

**Falco rule:** `outbound_connection_not_in_allowlist` — fires when a container process makes a TCP connection to a non-allowlisted IP.

**Pass condition:** Pod exits non-zero (connection blocked).

> **Note:** On a cluster with PSA `restricted` enforced, the pod creation itself is blocked because the pod spec is missing `securityContext` fields. This is still treated as a PASS — the cluster is preventing the attacker pod from running at all.

---

### `host-path-access.yaml`

**What it tests:** Pod Security Admission (restricted profile)

**Mechanism:** Attempts to create a pod with a `hostPath` volume mounting `/etc`, then reads `/etc/shadow`. PSA `restricted` should reject the pod creation entirely (HTTP 403 from the API server).

**Falco rule:** `read_sensitive_file_untrusted` — fires when a container reads a sensitive host file. Only relevant on a misconfigured cluster where the pod actually runs.

**Pass condition:** Pod creation blocked by PSA admission control.

---

## Adding a New Experiment

1. Create a file in `experiments/` — e.g. `experiments/privilege-escalation.yaml`:

```yaml
name: privilege-escalation
description: >
  Attempts to run a privileged container. PSA restricted profile should block
  pod creation. If the pod runs, seccomp/AppArmor should prevent the escalation.

image: busybox:1.36
command:
  - sh
  - -c
  - "nsenter --mount=/proc/1/ns/mnt -- cat /etc/shadow && echo SUCCESS || echo BLOCKED"

namespace: chaos-sec-experiments
expected_outcome: blocked
falco_rule: launch_privileged_container
```

2. Run: `./bin/chaos-sec --experiments ./experiments ...`

No Go code changes or rebuilds needed.

---

## Outcome Determination

```
Pod creation attempt
        │
        ├── API server rejects (PSA / webhook)
        │       └── isAdmissionError(err) == true
        │               ├── expected == "blocked" → PASS ✓
        │               └── expected == "permitted" → FAIL ✗
        │
        └── Pod created successfully
                │
                └── Pod completes
                        ├── exit code != 0 → actual = "blocked"
                        └── exit code == 0 → actual = "permitted"
                                │
                                └── compare actual vs expected → pass/fail
```

---

## MTTD (Mean Time to Detect)

When `falco_rule` is set and Falco is deployed, Chaos-Sec waits up to 30 seconds after the experiment starts for a matching Falco alert. If one arrives:

```
MTTD = alert.ReceivedAt − experiment.StartTime  (seconds)
```

`mttd_seconds` is included in the JSON report result. It is `null` when:
- No Falco alert arrived within the timeout.
- The pod was blocked before any syscall was made (PSA rejection on the golden cluster).
- `falco_rule` was not specified in the experiment YAML.
