---
tags:
  - high
  - infra
---

# Misconfiguration & Information Disclosure

Misconfigurations expose sensitive data through debug endpoints, backup files, admin panels, and CORS issues.

## Common Sensitive Paths

```
# Debug/Info
/phpinfo.php, /info.php
/elmah.axd, /elmah.axd/download
/debug/pprof/, /debug/pprof/heap
/crx/de, /crxde/index.jsp
/status, /health, /metrics

# Source Control
/.git/, /.svn/, /.env

# Backups
/backup/, /backups/, /db/
/backup.sql, /db.sql, /site_backup.tar.gz

# Admin
/admin/, /administrator/, /wp-admin/
```

## Attack Vectors

### PHP Information Disclosure

```
/phpinfo.php
/info.php
/phpinfo
/test.php
/php-fpm-status
```

Reveals: PHP version, OS, config, extensions, environment variables.

### ELMAH Error Logging (ASP.NET)

```
/elmah.axd                    # List all errors
/elmah.axd/download           # Download full log
/elmah.axd/detail?id={ID}     # Specific error
```

Leaks: Cookies, IP addresses, file paths, stack traces, verification tokens.

### Golang pprof Debugger

```
/debug/pprof/
/debug/pprof/profile
/debug/pprof/heap
/debug/pprof/goroutine
```

Exposes: Memory dumps, goroutines, profiling data.

### Adobe Experience Manager (AEM)

```
/crx/de
/crxde/index.jsp
/bin/querybuilder.json?path=/content&p.hits=full
```

### Admin Panel Discovery

```
/admin/
/administrator/
/admin.php
/wp-admin/
```

**Auto-authentication bug:** Navigate to `/admin/` and check for "log out" option.

### Backup File Locations

**Database:**
```
/backup.sql, /db.sql, /database.sql
/backup.zip, /site_backup.tar.gz
/.sql, /.db, /.bak, /.dump
```

**Configuration:**
```
/.env, /.env.local, /.env.production
/config.php, /settings.ini, /database.yml
/.htaccess, /web.config, /nginx.conf
```

### S3 Bucket Misconfigurations

```bash
aws s3 ls s3://{bucket}/
aws s3 ls s3://{bucket}/admin/
aws s3 ls s3://{bucket}/production/
aws s3 ls s3://{bucket}/backup/
```

### API Key Leaks

**JavaScript source:**
```javascript
apiKey: "sk-xxxxxxxx"
clientId: "xxxxx.apps.googleusercontent.com"
secretKey: "xxxxxxxx"
```

Check: `*.js`, bundles, configuration files.

### CORS Misconfigurations

```http
GET /api/user HTTP/1.1
Origin: http://evil.com
```

Vulnerable response:
```http
Access-Control-Allow-Origin: http://evil.com
Access-Control-Allow-Credentials: true
```

### Subdomain Takeover

**Indicators:**
- CNAME pointing to unclaimed service
- "There isn't a GitHub Pages site here"
- "NoSuchBucket" (AWS S3)
- 404 from third-party service

**Common services:** AWS S3, GitHub Pages, Heroku, Azure, Fastly

## Bypasses

**Admin panel:**
```
/admin → 403
/admin/ → 200
/ADMIN → 200
/admin;/ → 200
/admin/. → 200
```

**Rate limiting:**
```http
X-Forwarded-For: 127.0.0.1
X-Real-IP: 1.2.3.4
X-Originating-IP: 127.0.0.1
```

## Real Examples

| Target | Finding | Impact |
|--------|---------|--------|
| HackerOne #1050912 | /phpinfo exposed | Config leak |
| HackerOne #1139340 | ELMAH leaked cookies | Session theft |
| Uber #1385906 | /debug/pprof/ exposed | Runtime profiling |
| HackerOne #1095830 | AEM CRXDE unauth | Admin access |
| DoD #1062803 | S3 bucket public | Data exposure |

## Tools

**Directory discovery:**
```bash
# Dirsearch
dirsearch -u https://target.com -e php,asp,aspx,jsp,html,txt,bak

# ffuf
ffuf -u https://target.com/FUZZ -w wordlist.txt

# nuclei
nuclei -u https://target.com -t misconfigurations/
```

**S3 tools:**
```bash
s3scanner scan --bucket bucket-name
aws s3 ls s3://bucket-name --no-sign-request
```

**Subdomain takeover:**
- **subjack** — Scanner
- **can-i-take-over-xyz** — Fingerprint database
- **nuclei** — Takeover templates

## Wordlist

```
.env, .env.local, .env.production, .env.backup
config.php, config.yml, config.json, settings.py
database.yml, db.sqlite, db.sql
backup.zip, backup.tar.gz, site.zip
.git/config, .svn/entries, .DS_Store
phpinfo.php, info.php, test.php
elmah.axd, trace.axd, debug.aspx
```
