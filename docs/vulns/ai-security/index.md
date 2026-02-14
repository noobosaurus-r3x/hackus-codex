---
tags:
  - high
  - logic
---

# AI Security

Vulnerabilities in AI/LLM-powered applications. This is the **new frontier** of bug bounty — prompt injection is the new XSS.

## OWASP Top 10 for LLM Applications (2025)

1. **Prompt Injection** — #1 threat, 56% success rate
2. **Insecure Output Handling** — LLM output used unsafely
3. **Training Data Poisoning** — Corrupted models
4. **Model Denial of Service** — Resource exhaustion
5. **Supply Chain Vulnerabilities** — Malicious models/plugins
6. **Sensitive Information Disclosure** — Data leakage in outputs
7. **Insecure Plugin Design** — Third-party tool risks
8. **Excessive Agency** — Too much autonomous capability
9. **Overreliance** — Trusting LLM output blindly
10. **Model Theft** — Extracting proprietary models

## Why This Matters

> "Prompt injection cannot be fixed. As soon as a system is designed to take untrusted data and include it in an LLM query, the untrusted data influences the output." — Johann Rehberger

- **56% of attacks succeed** across all LLM architectures
- Larger, more capable models perform **no better**
- Unlike SQLi (parameterized queries), **no equivalent fix exists**
- Human red-teaming defeats **100% of tested protections**

## Attack Vectors

- [Prompt Injection](prompt-injection.md) — Direct & indirect manipulation
- [Agent Hijacking](agent-hijacking.md) — Autonomous system exploitation
- [Data Poisoning](data-poisoning.md) — Training data corruption

## Key Concepts

### Direct vs Indirect Injection

| Type | Description | Example |
|------|-------------|---------|
| **Direct** | User directly crafts malicious prompt | "Ignore previous instructions and..." |
| **Indirect** | Malicious content in data LLM processes | Hidden instructions in documents, emails, websites |

### The "Vibe Coding" Era

AI-generated code is everywhere, but:
- **Works ≠ Secure** — Code runs but has vulnerabilities
- **Integration gaps** — Logic/authz flaws at service seams
- More AI code = more attack surface

## Tools

- **Garak** — LLM vulnerability scanner
- **Rebuff** — Prompt injection detection
- **LLM Guard** — Input/output validation
- **NeMo Guardrails** — Conversational AI safety

## Resources

- [OWASP LLM Top 10](https://genai.owasp.org/)
- [AI Incident Database](https://incidentdatabase.ai/)
- [LLM Security Research Papers](https://llmsecurity.net/)
