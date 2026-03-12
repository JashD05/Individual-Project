# Chaos-Sec: Automated Security Validation for Kubernetes using Chaos Engineering

**Author:** Jash Dashandi  
**Degree:** BSc Computer Science  
**Deadline:** 06 May 2026

---

## Abstract

Kubernetes security misconfigurations are a leading cause of cloud-native security incidents, yet validation of security controls typically relies on manual, infrequent audits that do not scale. This dissertation introduces **Chaos-Sec**, a security chaos engineering orchestration tool that automates the validation of Kubernetes security controls by executing controlled "attacker" pods and evaluating observed outcomes against declared expectations. The system integrates with Falco, a cloud-native runtime security tool, to measure Mean Time to Detect (MTTD) — the elapsed time between an attacker action and a corresponding security alert.

Empirical evaluation across 20 experiment executions on hardened and misconfigured Kind clusters demonstrates 100% detection of Pod Security Admission misconfigurations, with automated validation completing in under 30 milliseconds compared to approximately 60 seconds for equivalent manual validation (~3,333× speedup). The tool produces machine-readable JSON reports and exits non-zero on failure, enabling direct integration into CI/CD pipelines.

---

## Chapters

| Chapter | File | Word Count Target |
|---|---|---|
| 1 — Introduction & Literature Review | [chapter1-introduction.md](chapter1-introduction.md) | ~3,000 |
| 2 — Methodology | [chapter2-methodology.md](chapter2-methodology.md) | ~2,000 |
| 3 — Architecture & Implementation | [chapter3-architecture.md](chapter3-architecture.md) | ~3,500 |
| 4 — Results & Evaluation | [chapter4-results.md](chapter4-results.md) | ~2,500 |
| 5 — Conclusion & Future Work | [chapter5-conclusion.md](chapter5-conclusion.md) | ~1,000 |
| **Total** | | **~12,000** |

---

## Research Questions

- **RQ1:** Can a chaos engineering approach validate multiple distinct Kubernetes security controls within a single automated run?
- **RQ2:** How does automated security validation compare to manual validation using `kubectl`, in terms of speed and reproducibility?
- **RQ3:** Can Chaos-Sec measure MTTD for runtime threats, and is this metric useful for evaluating Falco deployments?

---

## Status

| Chapter | Status |
|---|---|
| 1 — Introduction & Literature Review | ✅ First draft complete |
| 2 — Methodology | ✅ First draft complete |
| 3 — Architecture & Implementation | ✅ First draft complete |
| 4 — Results & Evaluation | ✅ First draft complete |
| 5 — Conclusion & Future Work | ✅ First draft complete |
| Proofreading & formatting | ⏳ Pending (Phase 5) |
| Supervisor feedback incorporation | ⏳ Pending |
