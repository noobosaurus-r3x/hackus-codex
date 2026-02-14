---
tags:
  - high
  - logic
---

# Logic Vulnerabilities

Business logic flaws occur when application workflows can be exploited to achieve unintended outcomes. Unlike technical vulnerabilities, these exploit the *design* rather than the implementation.

## Categories

| Vulnerability | Description | Impact |
|--------------|-------------|--------|
| [Race Conditions](race-conditions.md) | Exploit timing gaps in concurrent operations | Duplicate resources, bypass limits |
| [Rate Limiting](rate-limiting.md) | Evade request throttling mechanisms | Brute force, enumeration |
| [Payment Bypass](payment.md) | Manipulate payment flows and pricing | Financial fraud |

## Quick Detection Checklist

- [ ] **State-dependent actions** - Can you access step 3 without completing step 2?
- [ ] **Numerical limits** - Coupons, trials, seats, transfers
- [ ] **Concurrent requests** - Send multiple requests simultaneously
- [ ] **Parameter tampering** - Prices, quantities, plan IDs
- [ ] **Rate limits** - Test if limits can be bypassed via headers/rotation

## Common Patterns

### Check-Then-Act (TOCTOU)
```python
# Vulnerable: Gap between check and action
if user.balance >= amount:  # CHECK
    # Race window here!
    user.balance -= amount  # ACT
```

### Client-Trusted Values
```http
POST /checkout
price=9999&quantity=1&discount=0
# What if price=1 or quantity=-1?
```

### Session State Gaps
```
Step 1: Login (session created)
Step 2: MFA verification (flag set)
# Race window between 1 and 2
```

## Testing Approach

1. **Map the workflow** - Document every step and state change
2. **Identify trust boundaries** - What values come from the client?
3. **Find race windows** - Where are check-then-act patterns?
4. **Test concurrency** - Use Turbo Intruder or Burp's parallel send
5. **Test limits** - Negative values, zero, maximum integers
6. **Test order** - Skip steps, repeat steps, go backwards

## Tools

| Tool | Purpose |
|------|---------|
| Caido Replay | "Send group in parallel" for race conditions |
| Turbo Intruder | HTTP/2 single-packet attacks |
| Custom scripts | Async request batching |
