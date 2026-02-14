---
tags:
  - high
  - logic
---

# IDOR - Insecure Direct Object Reference

## TL;DR

IDOR occurs when user-controllable identifiers directly access objects without authorization checks, enabling horizontal/vertical privilege escalation and data theft.

```http
# Change user_id in any request
GET /api/users/1234 → GET /api/users/1235

# Your ID is 1234, victim is 1235
```

## Quick Links

- [Finding IDOR](find.md) — Where to look, parameter patterns
- [Exploitation](exploit.md) — Enumeration, data extraction
- [Bypasses](bypasses.md) — ID manipulation, encoding tricks
- [Escalation](escalate.md) — ATO chains, impact maximization

## Impact

| Scenario | Severity |
|----------|----------|
| Read own data with different ID | Informational |
| Read other user's non-sensitive data | Low |
| Read other user's sensitive data (PII) | Medium-High |
| Modify other user's data | High |
| Delete other user's data | High |
| Access admin resources | Critical |
| Financial data / transactions | Critical |
| Account takeover via IDOR | Critical |

## Quick Test

```bash
# URL path
GET /api/user/123/profile → GET /api/user/124/profile

# Query parameters
GET /documents?id=42 → GET /documents?id=43

# POST body
POST /api/delete
{"user_id": 123} → {"user_id": 124}

# Headers/Cookies
Cookie: UID2=YOUR_ID → Cookie: UID2=VICTIM_ID
```

## Common ID Patterns

| Pattern | Example | Predictability |
|---------|---------|----------------|
| Sequential integers | `123, 124, 125` | High |
| Predictable strings | `ORD-2024-00001` | Medium-High |
| Base64 encoded | `MTIz` (123) | Medium |
| UUID v1 (timestamp) | `550e8400-e29b-...` | Medium |
| UUID v4 (random) | Random | Low |
| Hashed IDs | SHA256 | Low (unless known pattern) |

## Where to Find IDORs

```
# URL path
/api/users/123/profile
/files/550e8400-e29b-41d4-a716-446655440000

# Query parameters
?id=42&invoice=2024-00001

# POST/PUT body
{"user_id": 321, "order_id": 987}

# Headers/Cookies
X-Client-ID: 4711
Cookie: UID2=4820041
```

## High-Value Endpoints

- [ ] User profiles, settings
- [ ] Orders, invoices, transactions
- [ ] Documents, files, attachments
- [ ] Messages, notifications
- [ ] API keys, credentials
- [ ] Admin functions
- [ ] Export/download endpoints
- [ ] GraphQL node IDs

## Real-World Examples

| Target | Technique | Impact |
|--------|-----------|--------|
| McHire/Paradox | Sequential lead_id | 64M records (PII + JWT) |
| CrowdSignal | User ID enumeration | Full ATO |
| DoD | Record ID in redirect | Medical records |
| GitLab | External status check ID | Private project data |

If basic ID swap fails, check [Bypasses](bypasses.md).
