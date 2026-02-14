---
tags:
  - server-side
---

# Server-Side Vulnerabilities

Attacks targeting the server: injection, SSRF, file operations, and backend logic.

<div class="grid cards" markdown>

-   :material-database:{ .lg .middle } **SQL Injection**

    ---

    Extract data, bypass auth, escalate to RCE.

    [:octicons-arrow-right-24: SQLi Guide](../sqli/index.md)

-   :material-web:{ .lg .middle } **SSRF**

    ---

    Reach internal services, cloud metadata, pivot deeper.

    [:octicons-arrow-right-24: SSRF Guide](../ssrf/index.md)

-   :material-code-tags:{ .lg .middle } **Injection**

    ---

    Command, XXE, SSTI, NoSQL, GraphQL, gRPC...

    [:octicons-arrow-right-24: Injection Guide](../injection/index.md)

</div>

## Quick Wins

| Vuln | Test | Impact |
|------|------|--------|
| SQLi | `' OR 1=1--` in params | 🔴 Critical |
| SSRF | `url=http://169.254.169.254/` | 🔴 Critical |
| Command Inj | `; id` in filename params | 🔴 Critical |
| XXE | XML with DOCTYPE | 🔴 Critical |
| SSTI | `{{7*7}}` in templates | 🔴 Critical |
| Path Traversal | `../../../etc/passwd` | 🟠 High |

## Common Entry Points

- **URL parameters**: `url=`, `path=`, `file=`, `redirect=`
- **Headers**: `X-Forwarded-For`, `Host`, `Referer`
- **File uploads**: Filename, content-type, file content
- **API endpoints**: GraphQL queries, gRPC calls
- **Webhooks**: Callback URLs, payload parsing
