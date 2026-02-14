# Contributing

Hackus Codex is community-driven. Found something missing? Have a better technique?

## How to Contribute

### 1. Fork the Repository

```bash
gh repo fork Nooboclawdus/hackus-codex
```

### 2. Make Your Changes

Follow the existing structure and style.

### 3. Submit a Pull Request

```bash
git checkout -b feature/new-technique
git add .
git commit -m "Add: [description]"
git push origin feature/new-technique
gh pr create
```

## Content Guidelines

### Structure

- **Quick Reference** (`/quick/`) — Payloads only, no explanation
- **Vulnerabilities** (`/vulns/`) — Full methodology with consistent sections
- **Tech Stack** (`/tech/`) — Stack-specific techniques
- **Chains** (`/chains/`) — Documented exploit chains

### Style

- **Concise** — No fluff, get to the point
- **Practical** — Real payloads, real techniques
- **Tested** — Only include things that work
- **Formatted** — Use proper markdown, code blocks with language tags

### Page Structure for Vulns

Each vulnerability should have:

```
vulns/[vuln-name]/
├── index.md      # Overview, quick links, impact table
├── find.md       # Where and how to find it
├── exploit.md    # Confirming and weaponizing
├── bypasses.md   # Filter and WAF evasion
└── escalate.md   # Maximizing impact
```

### Code Blocks

Always specify the language:

````markdown
```html
<script>alert(1)</script>
```

```bash
curl -X POST ...
```

```json
{"key": "value"}
```
````

## What We Need

### High Priority

- [ ] SQL Injection full methodology
- [ ] Authentication bypass techniques
- [ ] Race condition exploitation
- [ ] File upload bypass techniques
- [ ] GraphQL-specific attacks
- [ ] OAuth/OIDC misconfigurations

### Tech Stacks

- [ ] PHP common vulns
- [ ] Node.js/Express security
- [ ] AWS misconfigurations
- [ ] Kubernetes security
- [ ] GraphQL attacks

### Chains

- [ ] OAuth token theft chains
- [ ] Cache poisoning to XSS
- [ ] CORS misconfiguration exploitation

## Quality Standards

Before submitting:

- [ ] Tested the technique yourself
- [ ] Payloads are functional
- [ ] No sensitive/private information
- [ ] Follows existing structure
- [ ] Spelling and grammar checked

## Code of Conduct

- Be respectful
- Focus on educational content
- No illegal content (only legal security research)
- Credit original researchers when applicable

---

Questions? Open an issue on GitHub.
