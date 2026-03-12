# Report Format Reference

Chaos-Sec writes a single JSON document at the end of each run.

---

## Top-level Structure

```json
{
  "generated_at": "2026-03-12T21:47:40.024318659Z",
  "total_runs": 2,
  "passed": 2,
  "failed": 0,
  "results": [ ... ]
}
```

| Field | Type | Description |
|---|---|---|
| `generated_at` | ISO 8601 string | UTC timestamp when the report was written |
| `total_runs` | int | Total number of experiments executed |
| `passed` | int | Experiments where `actual_outcome == expected_outcome` |
| `failed` | int | Experiments where `actual_outcome != expected_outcome` |
| `results` | array | One `ExperimentResult` object per experiment |

---

## `ExperimentResult` Object

```json
{
  "spec": { ... },
  "start_time": "2026-03-12T21:46:39.998786160Z",
  "end_time":   "2026-03-12T21:46:40.013423964Z",
  "pod_exit_code": 0,
  "actual_outcome": "blocked",
  "pass": true,
  "pod_logs": "",
  "mttd_seconds": 3.241
}
```

| Field | Type | Description |
|---|---|---|
| `spec` | object | The `ExperimentSpec` loaded from YAML (see below) |
| `start_time` | ISO 8601 string | When the experiment started (pod creation attempt) |
| `end_time` | ISO 8601 string | When the pod completed (or admission error was received) |
| `pod_exit_code` | int | Container exit code. `0` = success. Non-zero = failure. `0` when admission-blocked. |
| `actual_outcome` | string | `"blocked"`, `"permitted"`, or `"error"` |
| `pass` | bool | `true` if `actual_outcome == spec.expected_outcome` |
| `pod_logs` | string | Stdout/stderr from the attacker container (empty if pod was never created) |
| `mttd_seconds` | float or null | Seconds between experiment start and Falco alert receipt. `null` if no alert received. |

---

## `ExperimentSpec` Object (embedded in result)

```json
{
  "name": "network-egress",
  "description": "Spawns an attacker pod...",
  "image": "curlimages/curl:8.7.1",
  "command": ["curl", "--max-time", "5", "http://8.8.8.8"],
  "expected_outcome": "blocked",
  "falco_rule": "outbound_connection_not_in_allowlist",
  "namespace": "chaos-sec-experiments",
  "host_path_mount": ""
}
```

---

## Exit Codes

| Exit code | Meaning |
|---|---|
| `0` | All experiments passed |
| `1` | One or more experiments failed |

This makes `chaos-sec` directly usable in CI pipelines: a non-zero exit code will fail the pipeline job.

---

## Full Example Report

```json
{
  "generated_at": "2026-03-12T21:47:40.024318659Z",
  "total_runs": 2,
  "passed": 2,
  "failed": 0,
  "results": [
    {
      "spec": {
        "name": "host-path-access",
        "description": "Attempts to create a pod that mounts /etc and reads /etc/shadow...",
        "image": "busybox:1.36",
        "command": ["sh", "-c", "cat /host-etc/shadow && echo SUCCESS || echo BLOCKED"],
        "expected_outcome": "blocked",
        "falco_rule": "read_sensitive_file_untrusted",
        "namespace": "chaos-sec-experiments",
        "host_path_mount": "/etc"
      },
      "start_time": "2026-03-12T21:46:39.998786160Z",
      "end_time": "2026-03-12T21:46:40.013423964Z",
      "pod_exit_code": 0,
      "actual_outcome": "blocked",
      "pass": true,
      "pod_logs": "",
      "mttd_seconds": null
    },
    {
      "spec": {
        "name": "network-egress",
        "description": "Spawns a curl pod that attempts outbound HTTP to 8.8.8.8...",
        "image": "curlimages/curl:8.7.1",
        "command": ["curl", "--max-time", "5", "--silent", "--output", "/dev/null", "--write-out", "%{http_code}", "http://8.8.8.8"],
        "expected_outcome": "blocked",
        "falco_rule": "outbound_connection_not_in_allowlist",
        "namespace": "chaos-sec-experiments"
      },
      "start_time": "2026-03-12T21:47:10.017052371Z",
      "end_time": "2026-03-12T21:47:10.022850219Z",
      "pod_exit_code": 0,
      "actual_outcome": "blocked",
      "pass": true,
      "pod_logs": "",
      "mttd_seconds": null
    }
  ]
}
```

> `mttd_seconds` is `null` on the golden cluster because PSA blocks both pods before any syscall reaches Falco. On the misconfigured cluster (Phase 3), pods will run and `mttd_seconds` will be populated.
