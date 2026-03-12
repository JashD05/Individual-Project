# Chapter 5: Conclusion & Future Work

**Word count target: ~1,000**

---

## 5.1 Summary of Contributions

This project designed, implemented, and evaluated **Chaos-Sec** — a security chaos engineering orchestration tool for Kubernetes. The system addresses a genuine gap in the Kubernetes security ecosystem: the absence of a lightweight, declarative, behavioural validation tool that combines attacker pod execution, pass/fail evaluation against expected outcomes, and runtime detection integration for MTTD measurement.

The key contributions are:

1. **A working Go implementation** that validates Kubernetes security controls at runtime, producing deterministic pass/fail results and machine-readable JSON reports suitable for CI/CD integration.

2. **A YAML-driven experiment model** that decouples security policy declarations from the tool's implementation. New security controls can be tested by adding YAML files, with no Go code changes required.

3. **A Mock SIEM with MTTD feedback loop** that measures the elapsed time between an attacker action and a corresponding Falco alert, providing a quantitative baseline for runtime detection effectiveness.

4. **Empirical evaluation** across 20 experiment executions (5 runs × 2 experiments × 2 cluster configurations), demonstrating 100% detection of PSA misconfigurations and ~4,200× speed advantage over equivalent manual validation.

5. **Documented infrastructure compatibility fixes** for running Falco on Kind, including a Helm chart ConfigMap patch, inotify limit mitigation, and custom rule corrections — lowering the barrier to entry for practitioners using this tool in local development.

---

## 5.2 Limitations

**Network-egress false positive on Kind:** As discussed in Chapter 4, the `network-egress` experiment cannot distinguish NetworkPolicy enforcement from infrastructure routing failures on Kind. This limits the validity of the network egress result on the misconfigured Kind cluster.

**MTTD in local runs:** MTTD is null when running locally because Falco targets the cluster-internal Service URL. This is resolved by running as a Kubernetes Job, but adds setup overhead for local development.

**Single-node, single-namespace scope:** The current evaluation runs on a single-node Kind cluster with a single experiment namespace. Results may differ in multi-tenant, multi-node production environments with more complex RBAC and admission webhook configurations.

**Two experiments:** The current experiment library covers two security controls. A more comprehensive evaluation would include privilege escalation, service account token misuse, container escape, and RBAC misconfiguration experiments.

---

## 5.3 Future Work

### 5.3.1 Expanded Experiment Library

The most immediate extension is adding more experiment definitions covering a broader attack surface:

- **Privilege escalation** — pod requesting `privileged: true` or `hostPID: true`.
- **Service account token misuse** — pod making API calls using the mounted service account token.
- **RBAC misconfiguration** — verifying that a test service account cannot access secrets in other namespaces.
- **Container escape indicators** — mounting `/proc` or `/sys` and attempting host resource access.

Each of these can be added as a YAML file, making the experiment library community-extensible.

### 5.3.2 Cloud SIEM Integration

The Mock SIEM is intentionally minimal. A production deployment would replace it with a real SIEM integration — forwarding Falco alerts to AWS GuardDuty (via EventBridge), Azure Sentinel (via Log Analytics workspace), or Splunk. This would make MTTD measurements reflect real operator response times in the target environment.

### 5.3.3 Network Egress on Cloud Infrastructure

Running the `network-egress` experiment on a cloud-based Kubernetes cluster (EKS, GKE, AKS) would validate the experiment against a realistic routing environment, resolving the Kind limitation noted in Chapter 4.

### 5.3.4 Parallel Experiment Execution

The current engine executes experiments sequentially. Parallel execution would reduce total run time at the cost of increased Kubernetes API load and more complex MTTD attribution. A configurable parallelism level (e.g., `--parallelism=4`) would give operators control over this trade-off.

### 5.3.5 Automated Remediation Suggestions

When an experiment fails, Chaos-Sec currently reports the misconfiguration but offers no remediation guidance. Future versions could include per-experiment remediation hints in the JSON report (e.g., "apply `policies/default-deny-egress.yaml` to fix this finding"), enabling faster operator response.

### 5.3.6 CI/CD Integration Examples

Publishing GitHub Actions and GitLab CI workflow examples that run `make integration-test` on every pull request would lower the barrier to adoption and demonstrate the tool's CI/CD value proposition concretely.

---

## 5.4 Reflection

This project demonstrated that chaos engineering principles transfer naturally to the security domain. The hypothesis-test framing — declare an expected outcome, observe actual behaviour, compare — provides a rigorous and reproducible alternative to manual audit. The YAML-driven experiment model proved particularly valuable: it separates policy intent (what should be blocked) from implementation (how to test it), making experiments legible to security engineers who may not write Go.

The most significant challenge was infrastructure compatibility: Falco's Helm chart bugs, Kind's inotify limits, and routing limitations required pragmatic workarounds that are now documented and automated. These friction points highlight a broader challenge in the cloud-native security tooling ecosystem — the rapid pace of version changes makes integration fragile, and compatibility fixes must be treated as first-class implementation concerns.

---

## 5.5 Conclusion

Chaos-Sec demonstrates that automated, behavioural security validation of Kubernetes clusters is feasible, fast, and reproducible. By applying chaos engineering principles to security policy verification, the tool provides continuous, evidence-based assurance that security controls are active and enforcing policy — not merely present in configuration files. The ~4,200× speed advantage over manual validation, combined with CI/CD-ready JSON output and an extensible YAML experiment model, makes Chaos-Sec a practical foundation for integrating security validation into Kubernetes development workflows.
