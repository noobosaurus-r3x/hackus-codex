# Quick Reference

Copy-paste ready payloads and one-liners. No explanation, just the goods.

## Payloads

| Cheatsheet | What's inside |
|------------|---------------|
| [XSS Payloads](xss.md) | Payloads by context (HTML, JS, attributes) |
| [SSRF Payloads](ssrf.md) | Protocols, bypasses, cloud metadata |
| [SQLi Payloads](sqli.md) | By database type |
| [IDOR Payloads](idor.md) | ID manipulation, UUID attacks, parameter pollution |
| [Auth Payloads](auth.md) | OAuth, JWT, 2FA/MFA bypasses |
| [LLM Payloads](llm.md) | Prompt injection, jailbreaks, AI bypasses |
| [Bypasses](bypasses.md) | WAF bypasses, filter evasion |

## One-Liners

### Recon

```bash
# Subdomain enumeration
subfinder -d target.com -silent | httpx -silent

# Find parameters
echo "https://target.com" | gau | grep "=" | qsreplace "FUZZ"

# JS files
echo "https://target.com" | gau | grep -E "\.js$" | httpx -silent

# Find endpoints in JS
cat urls.txt | xargs -I{} curl -s {} | grep -oE "(\/[a-zA-Z0-9_\-\/]+)" | sort -u
```

### Quick Tests

```bash
# XSS reflection test
echo "https://target.com/search?q=xss123test" | httpx -match-string "xss123test"

# Open redirect
curl -I "https://target.com/redirect?url=https://evil.com" 2>/dev/null | grep -i location

# SSRF with collaborator
curl "https://target.com/fetch?url=http://YOUR-ID.oast.fun"
```

### Headers to Test

```bash
# Host header injection
curl -H "Host: evil.com" https://target.com
curl -H "X-Forwarded-Host: evil.com" https://target.com

# CORS check
curl -H "Origin: https://evil.com" -I https://target.com/api/data
```

---

!!! tip "Looking for methodology?"
    These are just payloads. For full guides, check [Vulnerabilities](../vulns/index.md).
