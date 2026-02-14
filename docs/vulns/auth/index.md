---
tags:
  - high
  - logic
---

# Authentication Vulnerabilities

Authentication flaws allow attackers to bypass login mechanisms, hijack sessions, and impersonate users.

## Categories

| Category | Description | Key Attacks |
|----------|-------------|-------------|
| **OAuth** | Authorization protocol flaws | redirect_uri manipulation, token theft |
| **JWT** | JSON Web Token weaknesses | alg:none, secret brute-force, key confusion |
| **2FA/MFA** | Multi-factor bypass | Response manipulation, rate limiting gaps |
| **Sessions** | Session management flaws | Fixation, hijacking, weak tokens |
| **Password Reset** | Recovery flow abuse | Host header injection, token leakage |

## Quick Wins

```
# JWT alg:none attack
{"alg":"none","typ":"JWT"}

# 2FA direct access
Skip /2fa-verify → Go directly to /dashboard

# OAuth redirect manipulation
?redirect_uri=https://evil.com

# Session fixation test
Does session ID change after login?

# Password reset
Host: evil.com
```

## Impact Scale

- **Critical** — Full account takeover, admin access
- **High** — Session hijacking, token theft
- **Medium** — Information disclosure, privilege escalation
- **Low** — Session prolongation, token replay

## In This Section

- [**oauth.md**](oauth.md) — OAuth/OpenID Connect vulnerabilities
- [**jwt.md**](jwt.md) — JWT token attacks
- [**2fa.md**](2fa.md) — 2FA/MFA bypass techniques
- [**session.md**](session.md) — Session and cookie security

## Common Tools

- **Caido** — Intercept auth flows
- **jwt_tool** — JWT testing and cracking
- **SAML Raider** — SAML attacks (Burp extension)
- **hashcat** — Crack JWT secrets

## Testing Checklist

- [ ] Test authentication on all endpoints
- [ ] Check session handling (fixation, regeneration)
- [ ] Test OAuth redirect_uri validation
- [ ] Analyze JWT tokens for weaknesses
- [ ] Attempt 2FA bypass methods
- [ ] Test password reset token security
- [ ] Check for default/weak credentials
- [ ] Test account lockout behavior
