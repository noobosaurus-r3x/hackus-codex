# Framework-Specific Security

*Security vulnerabilities and misconfigurations unique to modern web frameworks and platforms*

---

## Overview

Modern frameworks introduce their own attack surfaces beyond standard web vulnerabilities. Each framework has unique patterns, helper functions, and architectural decisions that create specific security gaps.

**This section covers:**

- **[FastAPI](fastapi.md)** — Python async framework with dependency injection, Pydantic validation, and OpenAPI
- **[Next.js](nextjs.md)** — React SSR framework with middleware, server actions, and edge runtime
- **[BaaS Platforms](baas.md)** — Supabase & Firebase backend-as-a-service security rules

---

## Why Framework-Specific Matters

Traditional web security focuses on OWASP Top 10, but frameworks add:

- **New attack surfaces** — Dependency injection, server actions, RLS policies
- **Abstraction gaps** — Security assumed by framework, not actually enforced
- **Configuration drift** — Dev settings shipped to production
- **Type coercion** — Validation bypasses through unexpected types
- **Hidden endpoints** — Debug routes, admin panels, OpenAPI schemas

**Example:** A developer using FastAPI's `Depends()` might assume authentication is enforced, but without `Security()` with scopes, it's just dependency injection—no authorization check happens.

---

## Common Patterns Across Frameworks

### 1. Client-Side Authz Assumptions
```javascript
// Developer thinks: "If you can render this component, you're authorized"
// Reality: API endpoint has no checks

// Frontend
if (user.role === 'admin') {
  <AdminPanel />
}

// Backend API
GET /api/admin/users  // No role check → IDOR
```

### 2. Development Endpoints in Production
```
/docs              → Swagger UI (FastAPI)
/__nextjs_original-stack-frame  → Next.js debug info
/openapi.json      → Full API schema
/_next/static/chunks/*.js.map   → Source maps
```

### 3. Middleware/Policy Bypass
```
# Path normalization differences
/api/admin      → blocked
/api//admin     → bypass (FastAPI, Next.js)
/api/./admin    → bypass
```

### 4. Overprivileged Functions
```sql
-- Supabase RPC with SECURITY DEFINER
CREATE FUNCTION bypass_rls() SECURITY DEFINER
-- Firebase Admin SDK in Cloud Functions
admin.firestore().collection('users').get()  // Bypasses rules
```

---

## Attack Strategy

1. **Identify the framework** — Check response headers, file paths, error messages
2. **Enumerate hidden endpoints** — `/docs`, `/_next/*`, `/openapi.json`
3. **Test authorization gaps** — Authenticated ≠ authorized
4. **Bypass validation** — Type coercion, content-type switching
5. **Exploit misconfigurations** — CORS, cache poisoning, exposed secrets

---

## Detection Fingerprints

| Framework | Indicators |
|-----------|-----------|
| **FastAPI** | `"detail":` in errors, `/docs`, `/openapi.json`, `uvicorn` headers |
| **Next.js** | `_next/static/`, `__NEXT_DATA__` in HTML, `x-nextjs-cache` header |
| **Supabase** | `/rest/v1/`, `postgrest` headers, `sb-` prefixed cookies |
| **Firebase** | `firestore.googleapis.com`, `__/auth/`, Firebase SDK in JS |

---

## Quick Wins

**FastAPI:**
- Access `/docs` and `/openapi.json` in production
- Test `Depends()` routes without valid tokens
- Mass assignment via Pydantic `extra="allow"`

**Next.js:**
- Extract `__NEXT_DATA__` from page source for leaked props
- Download source maps: `/_next/static/chunks/*.js.map`
- Path normalization bypass: `/api//admin`

**Supabase:**
- Test CRUD operations separately (SELECT ≠ UPDATE policies)
- Look for service_role key in client bundle
- Enumerate via embedded relations: `?select=*,private_table(*)`

**Firebase:**
- List collections with authenticated user
- Test rules with direct REST API calls
- Subscribe to Realtime listeners for other users

---

## Validation Checklist

- [ ] Framework debug endpoints accessible in production
- [ ] Authorization enforced server-side (not just UI)
- [ ] All CRUD operations have security policies
- [ ] Secrets not leaked in client bundles/source maps
- [ ] Path normalization bypasses don't work
- [ ] Type coercion exploits fail validation
- [ ] Middleware/policies apply to all routes (including sub-apps/mounted routes)
- [ ] Cache doesn't leak data between users

---

## Pro Tips

1. **Read the framework's security docs** — Most vulnerabilities come from misusing features, not framework bugs
2. **Test every permission model** — `Depends` vs `Security`, RLS policies per operation, Firebase rules per collection
3. **Enumerate aggressively** — Hidden routes, source maps, manifests, debug endpoints
4. **Type coercion is your friend** — Empty strings, unions, Optional types often bypass validation
5. **Client-side code is documentation** — Source maps, `__NEXT_DATA__`, build manifests reveal server architecture

---

## Next Steps

Pick your target framework and dive deep:

- **[FastAPI →](fastapi.md)** Dependency injection, JWT flaws, Pydantic bypasses
- **[Next.js →](nextjs.md)** Middleware bypass, server actions, cache poisoning
- **[BaaS →](baas.md)** RLS gaps, security rules, service key leaks

---

## References

- [OWASP API Security Top 10](https://owasp.org/www-project-api-security/)
- FastAPI Security Documentation
- Next.js Security Headers Guide
- Supabase RLS Documentation
- Firebase Security Rules Guide
