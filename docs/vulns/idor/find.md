---
tags:
  - high
  - logic
---

# Finding IDOR

## Where to Look

### High-Value Targets

- [ ] User profile endpoints (`/user/ID/profile`)
- [ ] Document/file access (`/documents/ID`)
- [ ] API endpoints with IDs (`/api/orders/ID`)
- [ ] Download endpoints (`/download?file=ID`)
- [ ] Message/inbox endpoints
- [ ] Transaction/payment history
- [ ] Settings/preferences
- [ ] Export functions

### Parameter Names to Target

```
id, user_id, account_id
uid, uuid, guid
doc_id, document_id, file_id
order_id, transaction_id
ref, reference
number, num, no
handle, username, email
```

### Hidden IDORs

- [ ] UUIDs in API responses (not in URL)
- [ ] Base64 encoded IDs
- [ ] Hashed/encrypted IDs (predictable?)
- [ ] GraphQL node IDs
- [ ] Nested objects in JSON
- [ ] IDs in WebSocket messages
- [ ] Mobile API endpoints (different from web)

---

## Methodology

### 1. Create Two Test Accounts

- **Account A** (attacker) — your main test account
- **Account B** (victim) — secondary account with different data

### 2. Map Object References

Identify all IDs/references in:

```
URL path:       /user/123/orders
Query params:   ?user_id=123&order_id=456
POST body:      {"user_id": 123, "action": "delete"}
Headers:        X-User-ID: 123
Cookies:        user=123
```

### 3. Cross-Account Testing

1. Login as Account A
2. Capture request containing Account B's ID
3. Send request with Account A's session
4. Check if access granted

### 4. Document What You Can Do

| Action | Test |
|--------|------|
| **Read** | Can you view others' data? |
| **Create** | Can you create on behalf of others? |
| **Update** | Can you modify others' data? |
| **Delete** | Can you delete others' data? |

---

## ID Patterns

### Sequential IDs

```bash
123 → 124, 122, 125
```

Just increment/decrement. Most common and easiest to exploit.

### UUIDs

```
550e8400-e29b-41d4-a716-446655440000
```

**UUID v1** (timestamp-based): Contains timestamp and MAC address - potentially predictable!

**UUID v4** (random): Truly random - need to harvest from other sources.

Harvest UUIDs from:
- API responses
- WebSocket messages
- HTML/JS source
- Error messages
- Other user's public profiles

### Encoded IDs

```bash
# Base64
MTIz → base64 -d → 123
# Try: MTI0 (124)

# Hex
7b → 123
# Try: 7c (124)

# URL encoded
%31%32%33 → 123
```

### Hashed IDs

If IDs look hashed:
```
a665a45920422f9d417e4867efdc4fb8a04a1f3fff1fa07e998e86f7f7a27ae3
```

Try common patterns:
```bash
echo -n "123" | sha256sum
echo -n "user_123" | md5sum
echo -n "123|secret_salt" | sha256sum
```

### Signed IDs

If IDs have signatures/MACs:
```
123.HMAC_SIGNATURE
```

Try:
- Removing signature
- Using signature from another valid ID
- Signature confusion attacks

---

## Error-Based Enumeration

Different errors reveal valid IDs:

```
Invalid user → "User not found"
Valid user, no access → "Access denied"
# Second error confirms user exists
```

Use this for reconnaissance even when you can't access the data.

---

## Automation

### Burp Extension: Autorize

1. Login as low-priv user
2. Browse as high-priv user
3. Autorize replays requests with low-priv cookies
4. Highlights access control issues

### Manual with ffuf

```bash
# Enumerate user IDs
ffuf -u "https://target.com/api/user/FUZZ/profile" \
     -w <(seq 1 1000) \
     -H "Cookie: session=YOUR_SESSION" \
     -fc 403,404

# File download IDOR
ffuf -u "http://target.com/download.php?id=FUZZ" \
     -H "Cookie: PHPSESSID=xxx" \
     -w <(seq 0 6000) \
     -fr 'File Not Found'
```

### Mass Enumeration Script

```bash
for id in $(seq 1 10000); do
  curl -s "https://target.com/api/users/$id" \
    -H "Authorization: Bearer $TOKEN" | jq '.email'
done
```

---

## GraphQL IDOR

### Node ID Enumeration

```graphql
query {
  node(id: "VXNlcjoxMjM=") {  # base64: User:123
    ... on User {
      email
      phone
      privateData
    }
  }
}
```

Try changing the ID:
```graphql
query {
  node(id: "VXNlcjoxMjQ=") {  # base64: User:124
    ...
  }
}
```

### Batch Enumeration

```graphql
query {
  u1: user(id: "1") { email }
  u2: user(id: "2") { email }
  u3: user(id: "3") { email }
}
```

---

## Detection Checklist

- [ ] Map all endpoints with IDs
- [ ] Identify ID format (sequential, UUID, encoded)
- [ ] Create two accounts
- [ ] Test horizontal access (same role, different user)
- [ ] Test vertical access (lower role accessing higher)
- [ ] Check mobile API vs web API
- [ ] Test batch/bulk operations
- [ ] Look for IDs in cookies, headers, not just params
- [ ] Test encoded/hashed IDs
- [ ] Check error messages for information disclosure

---

Found an IDOR? Move to [Exploitation](exploit.md).

Need to bypass validation? Check [Bypasses](bypasses.md).
