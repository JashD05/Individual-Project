# Chapter 1: Introduction & Literature Review

**Word count target: ~3,000**

---

## 1.1 Introduction

Modern software systems are increasingly deployed on container orchestration platforms, with Kubernetes emerging as the de facto standard for managing containerised workloads at scale. As organisations migrate critical services to Kubernetes, the security of those deployments becomes paramount. A misconfigured NetworkPolicy, a missing Pod Security Admission profile, or a runtime detection gap can expose sensitive data, enable lateral movement, or allow privilege escalation — yet these misconfigurations frequently go undetected until an incident occurs.

Traditional security validation relies on periodic manual audits: a security engineer runs `kubectl` commands, applies test manifests, and interprets results by hand. This approach has three fundamental weaknesses. First, it does not scale — as cluster complexity grows, manual coverage degrades. Second, it is reactive — by the time a misconfiguration is found, it may already have been exploited. Third, it produces no machine-readable artefacts, making it difficult to track security posture over time or integrate validation into a continuous delivery pipeline.

This project introduces **Chaos-Sec**, a security chaos engineering orchestration tool for Kubernetes. Chaos-Sec automates the validation of security controls by spawning controlled "attacker" pods that deliberately attempt policy-violating actions. By comparing the observed behaviour (was the pod blocked or did it run?) against a declared expected outcome, the tool produces a deterministic pass/fail verdict for each control — along with a JSON report suitable for CI/CD integration. When deployed alongside Falco, a cloud-native runtime security tool, Chaos-Sec also measures the **Mean Time to Detect (MTTD)** — the elapsed time between an attacker action and the corresponding alert reaching the Security Information and Event Management (SIEM) system.

### Research Questions

This project addresses three research questions:

- **RQ1:** Can a chaos engineering approach validate multiple distinct Kubernetes security controls within a single automated run?
- **RQ2:** How does automated security validation with Chaos-Sec compare to equivalent manual validation using `kubectl`, in terms of speed and reproducibility?
- **RQ3:** Can Chaos-Sec measure Mean Time to Detect (MTTD) for runtime threats, and is this metric useful for evaluating the effectiveness of a Falco deployment?

---

## 1.2 Background: Chaos Engineering

Chaos Engineering was popularised by Netflix's Simian Army project, which introduced the practice of deliberately injecting failures into production systems to verify resilience. Principles of Chaos Engineering (Basiri et al., 2016) defines the discipline as "the practice of experimenting on a distributed system in order to build confidence in the system's capability to withstand turbulent conditions in production."

The core hypothesis-testing loop of chaos engineering maps naturally onto security validation:

1. **Define a steady state** — a correctly configured cluster where all security controls are active.
2. **Hypothesise** — predict that a specific attacker action will be blocked.
3. **Introduce the variable** — run the attacker pod.
4. **Observe** — compare actual outcome against the expected outcome.
5. **Learn** — if the hypothesis is disproved (i.e., the attack was permitted when it should have been blocked), a misconfiguration has been detected.

This framing distinguishes Chaos-Sec from penetration testing tools (which seek to exploit systems) and from compliance scanners (which statically inspect configuration). Chaos-Sec validates behaviour at runtime, under realistic conditions.

---

## 1.3 Kubernetes Security Model

Kubernetes provides several layered security primitives that Chaos-Sec exercises:

### Pod Security Admission (PSA)

Pod Security Admission, introduced in Kubernetes 1.22 and graduated to stable in 1.25, replaces the deprecated PodSecurityPolicy. PSA operates at the API server admission webhook level, evaluating pod specs against one of three profiles: `privileged`, `baseline`, and `restricted`. Under the `restricted` profile, pods that request hostPath volumes, run as root, omit seccomp profiles, or retain Linux capabilities are rejected before scheduling. This is the primary control tested by the `host-path-access` experiment.

### NetworkPolicy

Kubernetes NetworkPolicy objects define ingress and egress rules for pods, expressed as label selectors and port/protocol filters. By default, Kubernetes does not restrict pod-to-pod or pod-to-internet traffic; NetworkPolicies must be explicitly created and enforced by a compatible CNI plugin. The `kindnet` default CNI in Kind does not enforce NetworkPolicies; this project uses **Calico** as the CNI to ensure enforcement. The `network-egress` experiment validates that a default-deny egress policy is in place and actively enforced.

### Falco

Falco is a cloud-native runtime security tool that uses eBPF probes or kernel modules to monitor system calls at the host level. It applies a rule engine to the syscall stream, emitting structured JSON alerts when rules match. Falco's default ruleset covers common attack patterns; Chaos-Sec extends it with two custom rules targeting the specific actions performed by its attacker pods. Falco is deployed as a DaemonSet so it covers all nodes, and is configured to forward alerts via HTTP to the Chaos-Sec Mock SIEM webhook.

---

## 1.4 Related Work

### Chaos Mesh

Chaos Mesh (PingCAP, 2019) is a cloud-native chaos engineering platform for Kubernetes that supports fault injection at multiple levels: pod failures, network partitions, I/O delays, and kernel faults. It provides a rich web UI and a CRD-based experiment definition system. However, Chaos Mesh is oriented towards **resilience** chaos (does the system recover from infrastructure failures?) rather than **security** chaos (does the system prevent policy-violating actions?). It does not evaluate pass/fail outcomes against a declared security policy, nor does it integrate with runtime detection tools to measure MTTD.

### kube-bench

kube-bench (Aqua Security, 2017) implements the CIS Kubernetes Benchmark, auditing cluster configuration against a checklist of hardening recommendations. It performs **static** checks — inspecting configuration files, API server flags, and RBAC bindings — rather than behavioural validation. kube-bench will flag a missing NetworkPolicy recommendation, but will not verify that an existing policy actually blocks traffic.

### Gremlin

Gremlin is a commercial chaos engineering platform supporting both infrastructure and application-level fault injection. Like Chaos Mesh, its focus is operational resilience rather than security policy validation. It lacks runtime detection integration and does not produce structured security audit reports.

### Trivy / Kubescape

Trivy (Aqua Security) and Kubescape (ARMO) are static vulnerability and misconfiguration scanners. They analyse container images and Kubernetes manifests for known CVEs and misconfigurations. They complement Chaos-Sec (static analysis + dynamic validation provides defence-in-depth coverage), but do not provide behavioural evidence that controls are actively enforcing policy at runtime.

### Gap Analysis

None of the tools reviewed combine: (1) declarative, YAML-driven security experiment definition; (2) live attacker pod execution in a real cluster; (3) pass/fail evaluation against expected outcomes; (4) runtime detection integration for MTTD measurement; and (5) machine-readable JSON reporting for CI/CD integration. Chaos-Sec addresses this gap.

---

## 1.5 Ethical Considerations

All experiments in this project are conducted within isolated, local Kind clusters running on the developer's workstation. No production systems, real user data, or external networks are involved. The attacker pods perform benign actions — HTTP requests with short timeouts, and file reads — that only test policy enforcement. All container images used are publicly available and unmodified. This project does not require formal ethics board approval, as it constitutes low-risk computer science research on a locally controlled test environment.

---

## 1.6 Dissertation Structure

The remainder of this dissertation is organised as follows. **Chapter 2** describes the methodology, including requirements elicitation, technology selection, and the experimental design. **Chapter 3** presents the system architecture and implementation details. **Chapter 4** reports the evaluation results and addresses each research question. **Chapter 5** concludes with a summary of contributions, limitations, and directions for future work.

---

## References

- Basiri, A., Behnam, N., de Rooij, R., Hochstein, L., Kosewski, L., Reynolds, J., & Rosenthal, C. (2016). Chaos engineering. *IEEE Software*, 33(3), 35–41.
- Burns, B., Grant, B., Oppenheimer, D., Brewer, E., & Wilkes, J. (2016). Borg, Omega, and Kubernetes. *ACM Queue*, 14(1), 70–93.
- Cloud Native Computing Foundation. (2023). *Kubernetes documentation: Pod Security Admission*. https://kubernetes.io/docs/concepts/security/pod-security-admission/
- Falco Authors. (2024). *Falco: Cloud-native runtime security*. https://falco.org
- National Institute of Standards and Technology. (2022). *Kubernetes NIST SP 800-190: Application Container Security Guide*.
- PingCAP. (2019). *Chaos Mesh: A powerful chaos engineering platform for Kubernetes*. https://chaos-mesh.org
- Aqua Security. (2017). *kube-bench: Kubernetes CIS benchmark tool*. https://github.com/aquasecurity/kube-bench
- Rice, L. (2020). *Container Security: Fundamental Technology Concepts that Protect Containerized Applications*. O'Reilly Media.
- Sysdig. (2023). *2023 Cloud-Native Security and Usage Report*. Sysdig.
- Vigliarolo, B. (2022). Kubernetes security misconfigurations: What they are and how to prevent them. *TechRepublic*.
