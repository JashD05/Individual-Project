# Chapter 2: Methodology

**Word count target: ~2,000**

---

## 2.1 Research Approach

This project follows a **design science research** methodology (Hevner et al., 2004), in which an artefact (Chaos-Sec) is designed, built, and evaluated against defined criteria. The research questions are answered through empirical experimentation: controlled runs of the tool against known-good and deliberately misconfigured Kubernetes clusters, with quantitative comparison of outcomes.

The experimental design uses a two-condition study:
- **Golden cluster** — all security controls correctly configured (NetworkPolicy, PSA restricted).
- **Misconfigured cluster** — controls deliberately disabled, simulating a real-world oversight.

Five repeated runs are performed on each cluster to account for non-determinism in pod scheduling, network jitter, and Falco alert latency. Descriptive statistics (mean, median, standard deviation) are computed for experiment duration and MTTD.

---

## 2.2 Requirements Elicitation

Requirements were derived using a combination of **5 Whys Root Cause Analysis** applied to a representative security incident (a publicly documented Kubernetes misconfiguration leading to data exfiltration) and **MoSCoW prioritisation**.

### 5 Whys: Why did the misconfiguration go undetected?

1. **Why was data exfiltrated?** — A pod was able to make outbound connections to an attacker-controlled server.
2. **Why was the pod able to make outbound connections?** — No egress NetworkPolicy was enforced.
3. **Why was no NetworkPolicy enforced?** — The policy was accidentally deleted during a namespace cleanup.
4. **Why was the deletion not caught?** — There was no automated check that policies were present and active.
5. **Why was there no automated check?** — Security validation was manual and infrequent.

This chain motivates the core requirement: automated, repeatable, behavioural validation of security controls.

### MoSCoW Requirements

**Must Have:**
- Load experiment definitions from YAML files without code changes.
- Spawn attacker pods and evaluate pass/fail against expected outcomes.
- Support NetworkPolicy validation (egress blocking).
- Support Pod Security Admission validation (hostPath volume blocking).
- Produce a structured JSON report.
- Exit non-zero on failure for CI/CD integration.

**Should Have:**
- Measure and report MTTD when Falco is deployed.
- Clean up attacker pods after each run.
- Run within an isolated Kind cluster (no production impact).

**Could Have:**
- Parallel experiment execution.
- Web dashboard for results visualisation.
- Integration with cloud-native SIEM (AWS GuardDuty, Azure Sentinel).

**Won't Have (in scope):**
- Fuzzing or exploit generation.
- Automated remediation of detected misconfigurations.

---

## 2.3 Technology Selection

### Go (≥ 1.21)

Go was chosen as the implementation language for three reasons. First, the Kubernetes ecosystem's primary client library, `client-go`, is written in Go, providing first-class API access without FFI overhead. Second, Go compiles to a single static binary, simplifying deployment in a container. Third, Go 1.21 introduced `log/slog` — a structured logging package that produces JSON output by default, aligning with the project's machine-readable output requirement.

Python and Rust were considered. Python would have required a heavier runtime image and lacks the type safety desirable for concurrent Kubernetes API interactions. Rust, while offering memory safety, has a steeper learning curve and less mature Kubernetes client libraries.

### Kubernetes / Kind

Kind (Kubernetes-in-Docker) provides a lightweight, reproducible local Kubernetes cluster that runs entirely within Docker containers, making it suitable for developer workstations without dedicated infrastructure. Kind v0.20 supports Kubernetes 1.27+, which includes stable Pod Security Admission.

### Calico CNI

Kind's default CNI (`kindnet`) does not enforce NetworkPolicies. Calico was selected as the CNI replacement because it fully implements the Kubernetes NetworkPolicy specification and is widely used in production environments, making the experimental results more representative.

### Falco

Falco was selected as the runtime security tool because it is the most widely adopted cloud-native runtime detection solution (CNCF graduated project), supports eBPF-based probing (avoiding kernel module compilation issues on modern kernels), and natively supports HTTP webhook output — enabling direct integration with the Mock SIEM.

### Helm

Falco is distributed as a Helm chart, making Helm the natural choice for reproducible deployment. The chart version is pinned (7.2.1) to ensure consistent behaviour across environments.

---

## 2.4 Experimental Design

### Cluster Configurations

| Configuration | NetworkPolicy | PSA Profile | Falco |
|---|---|---|---|
| Golden | default-deny-egress | restricted | Deployed |
| Misconfigured | None | privileged | Deployed |

The misconfigured cluster is created by removing the egress NetworkPolicy and relabelling the namespace PSA profile, simulating two common real-world misconfigurations.

### Experiment Definitions

Two experiments are defined as YAML payloads:

1. **`network-egress`** — Spawns a `curlimages/curl:8.7.1` pod attempting `curl http://8.8.8.8`. Expected outcome: `blocked`. Falco rule: `outbound_connection_not_in_allowlist`.

2. **`host-path-access`** — Spawns a `busybox:1.36` pod with a hostPath volume mounting `/etc`, attempting `cat /host-etc/shadow`. Expected outcome: `blocked`. Falco rule: `read_sensitive_file_untrusted`.

### Measurement Protocol

For each of the 5 runs per cluster:
1. Start `./bin/chaos-sec` with a fresh report output path.
2. Record start/end timestamps per experiment (captured in JSON report).
3. Capture pod logs for diagnosis.
4. Record MTTD if a Falco alert is received within the 30-second window.

### Manual Comparison Baseline

To answer RQ2, manual equivalents are estimated:
- **Network egress check:** `kubectl exec` into a pod + `curl -m 5 http://8.8.8.8` + manual interpretation of stdout (~45 seconds).
- **Host path check:** `kubectl apply -f priv-pod.yaml`, observe admission response, interpret result (~60 seconds).

These estimates are conservative; they exclude the time to write the test manifests or remember the correct commands.

---

## 2.5 Validity Threats

### Internal Validity

- **Pod scheduling variance:** Pod creation time varies with cluster load. Mitigated by 5 repeated runs and reporting standard deviation.
- **Falco warm-up time:** Falco may not have loaded all rules immediately after deployment. The setup script waits 15 seconds after rollout before running experiments.

### External Validity

- **Kind vs. production:** Kind runs on a single node with no multi-tenant workloads. Real clusters may have different CNI implementations, admission webhook configurations, and API server response times. Results should be treated as indicative rather than directly transferable to all production environments.
- **network-egress Kind limitation:** Kind's networking does not route packets to external IPs (`8.8.8.8`) regardless of NetworkPolicy state. The `curl` exits with HTTP `000` (connection error) in both cluster configurations, meaning this experiment cannot distinguish between "NetworkPolicy blocked it" and "infrastructure routing prevented it." This is discussed further in Chapter 4.

### Construct Validity

- **MTTD measurement:** MTTD is measured as `alert.ReceivedAt − experiment.StartTime`. `ReceivedAt` is the timestamp when the HTTP POST arrives at the Mock SIEM server, not when Falco detected the syscall. Falco-to-webhook latency (typically <1 second on a local cluster) introduces a small positive bias.

---

## References

- Hevner, A. R., March, S. T., Park, J., & Ram, S. (2004). Design science in information systems research. *MIS Quarterly*, 28(1), 75–105.
- Kubernetes Authors. (2023). *Pod Security Admission*. https://kubernetes.io/docs/concepts/security/pod-security-admission/
- Project Calico Authors. (2024). *Calico network policy documentation*. https://docs.tigera.io/calico/latest/network-policy/
- Sysdig. (2024). *Falco documentation*. https://falco.org/docs/
