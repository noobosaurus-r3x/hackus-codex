---
tags:
  - high
  - logic
---

# FIDO2 / WebAuthn / Passkeys Attacks

## TL;DR

FIDO2/WebAuthn is "phishing-resistant" but not invulnerable:
- Authentication can be **downgraded** to phishable methods
- **Session tokens** post-auth are not protected
- **Server implementations** can have bugs
- **BitM + XSS** can bypass even hardware keys

## Attack 1: Authentication Downgrade

**Presented at OutOfTheBox 2025 Bangkok (IOActive)**

### Concept
Force user to use weaker MFA (push notification, OTP) even if FIDO2 is configured.

### Technique: JSON Configuration Manipulation

Server sends auth methods config:
```json
[
  {"authMethodId":"FidoKey", "isDefault":true},
  {"authMethodId":"PhoneAppNotification", "isDefault":false}
]
```

Proxy modifies in transit:
```javascript
// Disable FIDO2 as default
content = content.replace(
  /(\"authMethodId\":\"FidoKey\"[^}]*\"isDefault\":)true/g,
  '$1false'
);
// Force Push Notification
content = content.replace(
  /(\"authMethodId\":\"PhoneAppNotification\"[^}]*\"isDefault\":)false/g,
  '$1true'
);
```

### Technique: CSS Injection

Hide FIDO2 option completely:
```css
div[data-value="FidoKey"],
div[aria-label*="security key"] {
  display: none !important;
}
```

**Impact:** Bypasses $500K+ hardware key investment. Logs show legitimate auth.

## Attack 2: Session Hijacking Post-Auth

**Silverfort Research 2024**

### The Problem
```
User → FIDO2 Auth (secure) → Session Cookie (not protected) → Attacker captures
```

FIDO2 protects authentication, **not session tokens**.

### Affected
- **Microsoft Entra ID:** OIDC/SAML tokens valid 1h, refresh tokens for long sessions
- **Yubico Playground:** Session cookie without device validation
- **PingFederate:** MITM possible if RP doesn't validate tokens

### Solution: Token Binding
Binds token to TLS handshake. Only Edge supports it. Chrome removed it.

Microsoft launched **Token Protection** (preview) — TPM variant.

## Attack 3: BitM+ (Browser in the Middle + XSS)

**Paper 2025: "Defeating FIDO2 with BitM and XSS"**

### Flow
1. Victim clicks malicious link
2. XSS executes, establishes BitM channel
3. Attacker controls victim's browser
4. FIDO2 auth happens **in legitimate context** (correct origin)
5. Attacker captures session post-auth

### Why It Works
FIDO2 verifies origin → victim's browser IS on correct origin. Key signs normally.

## Attack 4: Server Implementation Flaws

### CVE-2025-26788 — StrongKey FIDO Server

**Affected:** SKFS 4.10.0 → 4.15.0

Server doesn't distinguish discoverable vs non-discoverable credentials:

1. Attacker starts auth with `victim` username
2. Server returns victim's credential ID
3. Attacker **modifies response** → swaps in attacker's credential ID
4. Attacker authenticates with own passkey
5. Server accepts → `victim` session created

```http
POST /basicdemo/fido2/preauthenticate
{"username": "victim"}

# Response contains victim's credential ID
# Attacker swaps to attacker's credential ID
# Auth succeeds as victim
```

**Fix:** Update to SKFS 4.15.1

## Checklist

- [ ] Mixed-mode auth enabled? (FIDO2 + push/OTP)
- [ ] Session tokens bound to device?
- [ ] Token binding supported?
- [ ] Conditional Access enforces FIDO2-only?
- [ ] Server validates credential ownership?
- [ ] XSS on target? (enables BitM+)

## Endpoints to Test

```
/authorize
/token
/authenticate
/preauthenticate
/.well-known/webauthn
```

## Mitigations (for defenders)

1. **FIDO2-only policy** — no fallback to push/OTP
2. **Conditional Access** — enforce by group/role
3. **Token Binding** if available
4. **Monitor auth method changes**
5. **Validate credential ID belongs to requested user**

## References

- [IOActive: Authentication Downgrade Attacks](https://www.ioactive.com/authentication-downgrade-attacks-deep-dive-into-mfa-bypass/) (Feb 2025)
- [Silverfort: Using MITM to bypass FIDO2](https://www.silverfort.com/blog/using-mitm-to-bypass-fido2/) (Nov 2024)
- [CVE-2025-26788: StrongKey FIDO Server](https://www.securing.pl/en/cve-2025-26788-passkey-authentication-bypass-in-strongkey-fido-server/)
- [BitM+ Paper: Defeating FIDO2 with XSS](https://link.springer.com/article/10.1007/s11416-025-00556-2) (2025)
