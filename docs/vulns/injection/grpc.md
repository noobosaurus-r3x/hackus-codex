---
tags:
  - critical
  - server-side
---

# gRPC Security

## TL;DR

gRPC uses binary Protocol Buffers over HTTP/2. Harder to test than REST but same vulnerability classes apply.

**Key issues:** Plaintext communication, reflection enabled, injection via protobuf fields.

## Detection

### Check for Plaintext
```bash
grpcurl -plaintext target:50051 list
```

If it works → no TLS.

**Wireshark:** Capture port 50051, messages visible in clear.

### Common Ports
```
50051 (default)
443 (with TLS)
9090
```

## Service Reflection (Schema Leak)

Like GraphQL introspection:
```bash
# List all services
grpcurl -plaintext 127.0.0.1:50051 list

# List methods in a service
grpcurl -plaintext 127.0.0.1:50051 list blog.BlogService

# Describe a method
grpcurl -plaintext 127.0.0.1:50051 describe blog.BlogService.CreatePost
```

## Exploitation

### SQL Injection
```bash
# Via gRPC UI (proxies to Burp)
grpcui -plaintext 127.0.0.1:50051
```

Then inject in fields:
```
author_id: "1' OR 1=1 --"
```

### Call Methods
```bash
# Call a method with JSON input
grpcurl -plaintext -d '{"id": 1}' \
  127.0.0.1:50051 blog.BlogService.GetPost

# Stream
grpcurl -plaintext -d @ 127.0.0.1:50051 chat.ChatService.Stream
```

### Authorization Bypass

gRPC methods often lack per-method auth. Check:
- Admin methods callable without auth
- Cross-tenant data access
- Internal methods exposed

## Protobuf Issues

### Insecure Definitions
- Services expose more data than needed
- Sensitive fields in responses
- Streaming misconfigured

### Unknown Fields
Protobuf silently ignores unknown fields. Inject extra fields:
```json
{"id": 1, "isAdmin": true}
```

Backend might process `isAdmin` if it exists in the actual proto.

## Tools

| Tool | Usage |
|------|-------|
| **grpcurl** | CLI for gRPC interaction |
| **grpcui** | Web UI for testing gRPC |
| **Burp + grpcui** | Intercept via grpcui proxy |
| **protoc** | Compile/decompile protobuf |

### Setup grpcui with Burp
```bash
# Start grpcui with proxy
HTTP_PROXY=http://127.0.0.1:8080 grpcui -plaintext target:50051
```

## CVEs

| CVE | Impact |
|-----|--------|
| CVE-2024-37168 | gRPC-js DoS via memory allocation |
| CVE-2024-* | gRPC-C++ data corruption (zero-copy) |

## Checklist

- [ ] Plaintext enabled?
- [ ] Reflection enabled?
- [ ] Injection in fields?
- [ ] Auth on each method?
- [ ] Cross-tenant access?
- [ ] Admin methods exposed?

## References

- [IBM: gRPC Security Series](https://medium.com/@ibm_ptc_security/grpc-security-series-part-3-c92f3b687dd9)
- [grpcurl GitHub](https://github.com/fullstorydev/grpcurl)
- [grpcui GitHub](https://github.com/fullstorydev/grpcui)
