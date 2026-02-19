---
tags:
  - critical
---

# Exploit Chains

Single bugs are good. Chains are better.

## What's a Chain?

Combining multiple vulnerabilities (or techniques) to achieve greater impact than any single bug.

| Single Bug | Impact | Chained | Impact |
|------------|--------|---------|--------|
| Self-XSS | None | Self-XSS + CSRF | Medium |
| Low IDOR | Low | IDOR + Info Disclosure | High |
| Blind SSRF | Low | SSRF + Redis | Critical |
| Open Redirect | Low | OAuth + Open Redirect | High |

## Documented Chains

### [XSS → Account Takeover](xss-to-ato.md)

Turn XSS into full account compromise:

- Cookie/token theft
- Password change via XSS
- Email change + password reset
- OAuth token exfiltration
- Prototype pollution → XSS → ATO
- Admin XSS → mass compromise

### [SSRF → RCE](ssrf-to-rce.md)

From internal requests to code execution:

- SSRF → Redis → webshell/SSH key
- SSRF → Docker API → host compromise
- SSRF → FastCGI → PHP execution
- SSRF → AWS metadata → cloud takeover
- SSRF → Jenkins → CI/CD compromise
- XXE → SSRF → RCE

### [OAuth → Account Takeover](oauth-to-ato.md)

From OAuth misconfigs to full account access:

- redirect_uri bypass → token theft
- Missing state → CSRF account linking
- response_mode=web_message → postMessage theft
- XSS on callback domain → code exfil
- Pre-account takeover (classic-federated merge)
- SSRF → cloud metadata → OAuth secrets

### [SQLi → RCE](sqli-to-rce.md)

From database injection to code execution:

- MySQL INTO OUTFILE → webshell
- MSSQL xp_cmdshell → direct command exec
- PostgreSQL COPY PROGRAM → direct command exec
- Oracle Java/DBMS_SCHEDULER → code execution
- NTLM hash theft → relay → lateral movement
- UDF injection → custom functions → RCE

### [Prototype Pollution → XSS/RCE](prototype-pollution-to-rce.md)

From JavaScript prototype pollution to code execution:

- Client-side PP → DOM gadgets → XSS
- Server-side PP → NODE_OPTIONS → RCE
- PP → Template engines (EJS, Pug, Handlebars) → RCE
- PP → child_process gadgets → RCE
- PP → require() path hijacking → RCE
- Lodash/jQuery merge vulnerabilities

### [Race Condition → Business Logic Bypass](race-to-bypass.md)

Exploiting timing windows to break application state:

- Limit overrun (coupons, gift cards, votes)
- Balance manipulation (double-spend, overdraw)
- State confusion (password reset token swap)
- 2FA bypass via session race window
- HTTP/2 single-packet attack technique
- Partial construction races (empty token auth)

### [Cache Poisoning → XSS](cache-poison-to-xss.md)

From cache manipulation to persistent XSS:

- Unkeyed header → cached XSS
- Request smuggling → cache poison
- CSPT + cache deception
- Cookie poisoning → cached XSS
- Fat GET → cache poison
- Static extension abuse

### [OAuth Wildcard State Bypass → Cross-Tenant ATO](oauth-wildcard-state-bypass.md)

Shared OAuth infrastructure with wildcard subdomain allowlists → cross-tenant authorization code theft:

- Shared OAuth client across all tenants (SaaS platforms)
- State URL validated against `*.saas.com` (wildcard) → any tenant is valid target
- Attacker controls a tenant → routes auth codes to their endpoint
- `prompt=none` for silent attack (zero user interaction with active session)
- Open redirect chaining if no direct subdomain control

### [XXE → SSRF → Internal Access](xxe-to-ssrf.md)

Weaponizing XML parsers to reach internal infrastructure:

- XXE → internal port scanning
- XXE → AWS/GCP/Azure metadata → cloud takeover
- XXE → internal services (Redis, Elasticsearch, K8s)
- Blind XXE with OOB exfiltration → SSRF
- SVG/DOCX upload → XXE → SSRF
- XInclude attacks when DOCTYPE is blocked

## Quick Chain Ideas

### Authentication Chains

| Start | Chain With | Result |
|-------|------------|--------|
| Open Redirect | OAuth callback | Token theft |
| XSS | Password change endpoint | ATO |
| IDOR on email | Password reset | ATO |
| Info disclosure | Brute force | Account access |
| postMessage | OAuth tokens | ATO |

### Escalation Chains

| Start | Chain With | Result |
|-------|------------|--------|
| Low SSRF | Cloud metadata | IAM creds |
| Read SSRF | Internal Redis | RCE |
| XSS on user | Admin views report | Admin compromise |
| Low IDOR | Sensitive endpoint | Critical data |
| Cache poison | Static resources | Mass XSS |
| SQLi (MySQL) | FILE priv + web root | Webshell RCE |
| SQLi (MSSQL) | xp_cmdshell enabled | Direct RCE |
| SQLi (PostgreSQL) | superuser role | COPY PROGRAM RCE |

### Logic Chains

| Start | Chain With | Result |
|-------|------------|--------|
| Race condition | 2FA verification | Auth bypass |
| Race condition | Payment flow | Financial impact |
| IDOR | Invite system | Org takeover |
| Prototype pollution | XSS gadget | DOM XSS |

## Chain Methodology

### 1. Map Impact Potential

For each bug, ask:
- What can I **read**?
- What can I **write**?
- What can I **trigger**?

### 2. Identify Trust Boundaries

- User → Admin
- External → Internal
- Unauthenticated → Authenticated
- Client → Server
- Cache → Origin

### 3. Connect the Dots

```
Bug A allows X
X gives access to Y
Y contains credentials for Z
Z has permissions for RCE
```

### 4. Document the Full Chain

Always show:
1. Starting vulnerability
2. Each step in chain
3. Final impact
4. Why each step is necessary

---

## Cross-Signal Connections

Key chains from technique analysis:

| Chain | Files Involved |
|-------|---------------|
| SSRF → Cloud → OAuth | ssrf/bypass + cloud-metadata + auth/oauth |
| Prototype Pollution → XSS | client-side/prototype-pollution + xss/dom |
| Prototype Pollution → RCE | chains/prototype-pollution-to-rce + child_process |
| Race → 2FA Bypass | chains/race-to-bypass + auth/2fa-bypass |
| Race → Double-Spend | chains/race-to-bypass + financial-logic |
| Race → Password Reset ATO | chains/race-to-bypass + auth/password-reset |
| Cache → CSPT → ATO | cache-poisoning + auth/session |
| CORS + Subdomain → Theft | cors + subdomain-takeover + session |
| Request Smuggling → Cache → XSS | request-smuggling + cache-poisoning + xss |
| SQLi → File Write → RCE | sql-injection + file-upload + webshell |
| SQLi → NTLM Theft → Relay | sql-injection + ntlm + lateral-movement |
| XXE → SSRF → Cloud Takeover | xxe + ssrf/bypass + cloud-metadata |

---
*See [Quick Payloads](../quick/index.md) for copy-paste ready exploits.*
