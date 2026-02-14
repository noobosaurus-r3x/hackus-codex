# Access Control Vulnerabilities

Access control flaws allow unauthorized access to resources, data manipulation, and privilege escalation by bypassing authorization checks.

## Categories

| Category | Description | Key Attacks |
|----------|-------------|-------------|
| **CORS** | Cross-origin resource sharing misconfiguration | Origin reflection, null origin, credential theft |
| **Mass Assignment** | Binding user input directly to models | Role escalation, privilege modification |
| **IDOR** | Insecure direct object references | See [IDOR section](../idor/index.md) |
| **BAC** | Broken access control | Horizontal/vertical privilege escalation |

## Quick Wins

```http
# CORS test
Origin: https://evil.com
→ Check: Access-Control-Allow-Origin: https://evil.com

# Mass assignment
PUT /api/users/me
{"name": "user", "role": "admin"}

# Path traversal
/admin → 403
/admin/ → 200
/Admin → 200

# Method switching
GET /admin → 403
POST /admin → 200
```

## Impact Scale

- **Critical** — Admin access, privilege escalation
- **High** — Cross-origin data theft with credentials
- **Medium** — Unauthorized resource access
- **Low** — Information disclosure

## In This Section

- [**cors.md**](cors.md) — CORS misconfiguration attacks
- [**mass-assignment.md**](mass-assignment.md) — Mass assignment / parameter injection

## Common Patterns

**Vertical Privilege Escalation:**
```
User → Admin
Regular → Superuser
Free tier → Premium
```

**Horizontal Privilege Escalation:**
```
User A → User B's resources
Same role, different ownership
```

## Testing Checklist

- [ ] Test CORS with arbitrary origins
- [ ] Test null origin via sandboxed iframe
- [ ] Try adding privileged parameters (role, isAdmin)
- [ ] Check for IDOR on all endpoints
- [ ] Test path variations (/admin vs /Admin)
- [ ] Try HTTP method switching
- [ ] Check for bypasses via headers (X-Original-URL)
- [ ] Test subdomain trust relationships
