---
tags:
  - high
  - infra
---

# Infrastructure Vulnerabilities

Attacks targeting web infrastructure components: CDNs, caches, proxies, DNS, and server configurations.

## Categories

| Vulnerability | Description | Impact |
|--------------|-------------|--------|
| [Subdomain Takeover](subdomain-takeover.md) | Claim abandoned third-party services | Phishing, cookie theft, XSS |
| [Cache Poisoning](cache-poisoning.md) | Store malicious responses in cache | XSS to all users, data theft |
| [Request Smuggling](request-smuggling.md) | Desync front-end/back-end parsing | Request hijacking, bypass security |

## Quick Detection

### Subdomain Takeover
```bash
# Find dangling CNAMEs
dig sub.target.com CNAME
# Check for "NoSuchBucket", "There isn't a GitHub Pages site here", etc.

# Automated scan
subfinder -d target.com | nuclei -tags takeover
```

### Cache Poisoning
```bash
# Check cache headers
curl -sI https://target.com | grep -iE "x-cache|age|cache-control"

# Test unkeyed inputs with Param Miner (Burp)
```

### Request Smuggling
```http
# CL.TE detection
POST / HTTP/1.1
Content-Length: 6
Transfer-Encoding: chunked

0

G
```

## Common Patterns

### Trust Boundaries

| Component | Trusts | Attack Vector |
|-----------|--------|---------------|
| CDN/Cache | Cache key components | Unkeyed input injection |
| Proxy | Content-Length vs Transfer-Encoding | Request desync |
| DNS | CNAME targets | Dangling records |
| Backend | Front-end security | Smuggled requests |

### Infrastructure Stack

```
User → CDN/WAF → Load Balancer → Reverse Proxy → App Server
         ↓              ↓               ↓
       Cache         Security        Routing
       Rules         Rules           Rules
```

Each layer may parse requests differently → exploitable gaps.

## Testing Approach

1. **Map infrastructure** - Identify CDN, proxies, cache layers
2. **Test parsing differences** - CL vs TE, path normalization
3. **Find unkeyed inputs** - Headers that affect response but not cache key
4. **Check DNS** - Dangling CNAMEs, expired domains
5. **Test concurrency** - Race conditions in infrastructure

## Tools

| Tool | Purpose |
|------|---------|
| **Param Miner** | Find unkeyed cache inputs |
| **HTTP Request Smuggler** | Smuggling detection |
| **nuclei** | Subdomain takeover templates |
| **Subdominator** | Modern takeover scanner |

## Impact Escalation

### Subdomain Takeover → Cookie Theft
Subdomains often share cookies with parent domain.

### Cache Poisoning → Stored XSS
Single request poisons response for all users.

### Request Smuggling → Request Hijacking
Steal other users' requests, bypass WAF.

### Chain: Subdomain Takeover → CSP Bypass → XSS
If subdomain whitelisted in CSP, takeover enables script injection.
