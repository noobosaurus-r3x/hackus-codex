# Vulnerabilities

Your attack surface breakdown. Each section covers finding, exploiting, bypassing, and escalating.

<div class="grid cards" markdown>

-   :material-server:{ .lg .middle } **Server-Side**

    ---

    SQLi, SSRF, Command Injection, XXE, SSTI, File Upload...

    [:octicons-arrow-right-24: Server-Side](server-side/index.md)

-   :material-monitor:{ .lg .middle } **Client-Side**

    ---

    XSS, CSRF, DOM attacks, postMessage, Prototype Pollution...

    [:octicons-arrow-right-24: Client-Side](client-side/index.md)

-   :material-account-key:{ .lg .middle } **Auth & Access**

    ---

    OAuth, JWT, IDOR, CORS, Sessions, 2FA bypass...

    [:octicons-arrow-right-24: Auth & Access](auth/index.md)

-   :material-brain:{ .lg .middle } **Logic**

    ---

    Race conditions, payment bypass, rate limits, captcha...

    [:octicons-arrow-right-24: Logic Flaws](logic/index.md)

-   :material-cloud:{ .lg .middle } **Infrastructure**

    ---

    Subdomain takeover, cache poisoning, request smuggling...

    [:octicons-arrow-right-24: Infrastructure](infrastructure/index.md)

-   :material-robot:{ .lg .middle } **AI Security**

    ---

    Prompt injection, agent hijacking, data poisoning...

    [:octicons-arrow-right-24: AI Security](ai-security/index.md)

</div>

## By Severity

| Severity | Typical Vulns |
|----------|---------------|
| 🔴 **Critical** | SQLi, SSRF, RCE, Auth Bypass |
| 🟠 **High** | XSS, IDOR, Priv Esc, CSRF |
| 🟡 **Medium** | Info Disclosure, Open Redirect |
| 🟢 **Low** | Verbose Errors, Missing Headers |

## Quick Start

New to a vuln class? Start with the **index** page of each section for:

- Overview of the vulnerability
- Common entry points
- Quick test payloads
- Links to detailed guides
