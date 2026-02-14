---
tags:
  - client-side
---

# Client-Side Vulnerabilities

Attacks executed in the victim's browser: XSS, DOM manipulation, and browser-based exploitation.

<div class="grid cards" markdown>

-   :material-script:{ .lg .middle } **XSS**

    ---

    Execute JavaScript in victim's browser. Steal sessions, deface, pivot.

    [:octicons-arrow-right-24: XSS Guide](../xss/index.md)

-   :material-shield-off:{ .lg .middle } **CSRF**

    ---

    Force authenticated actions. State-changing requests without consent.

    [:octicons-arrow-right-24: CSRF Guide](csrf.md)

-   :material-cursor-default-click:{ .lg .middle } **Clickjacking**

    ---

    UI redressing. Trick users into clicking hidden elements.

    [:octicons-arrow-right-24: Clickjacking](clickjacking.md)

-   :material-message-alert:{ .lg .middle } **postMessage**

    ---

    Cross-origin messaging vulnerabilities. Origin bypass, data theft.

    [:octicons-arrow-right-24: postMessage](postmessage.md)

-   :material-code-braces:{ .lg .middle } **Prototype Pollution**

    ---

    Pollute Object.prototype. Gadgets to XSS/RCE.

    [:octicons-arrow-right-24: Prototype Pollution](prototype-pollution.md)

-   :material-xml:{ .lg .middle } **DOM Clobbering**

    ---

    Override DOM properties with HTML. Break security checks.

    [:octicons-arrow-right-24: DOM Clobbering](dom-clobbering.md)

</div>

## Quick Tests

| Vuln | Test | Where |
|------|------|-------|
| XSS | `<img src=x onerror=alert(1)>` | Any input reflected |
| CSRF | Remove/modify CSRF token | State-changing forms |
| Clickjacking | `X-Frame-Options` missing | Sensitive pages |
| postMessage | `postMessage('test','*')` | Cross-origin frames |

## Entry Points

- **Reflected params**: URL params rendered in page
- **Stored inputs**: Comments, profiles, messages
- **DOM sinks**: `innerHTML`, `eval()`, `document.write()`
- **Event handlers**: `onclick`, `onerror`, `onload`
- **URL fragments**: `location.hash` processing
