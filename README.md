# Hackus Codex

> A clean, practical knowledge base for bug bounty hunters and pentesters.

No fluff. No endless nesting. Just what you need, where you need it.

🌐 **Live site:** [hackus-codex.online](https://hackus-codex.online)

## Features

- **Quick Reference** — Copy-paste ready payloads (XSS, SQLi, SSRF, SSTI, LFI, NoSQL, IDOR, Deserialization, LLM)
- **Vulnerability Guides** — Full methodology (Find → Exploit → Bypass → Escalate)
- **Attack Chains** — Combine vulns for maximum impact (SSRF→RCE, XSS→ATO, Self-XSS escalation)
- **Framework Guides** — Stack-specific techniques (FastAPI, Next.js, BaaS)

## Philosophy

- **Payload-dense** — Less prose, more payloads
- **Copy-paste ready** — Tested, working techniques
- **Chain-focused** — Escalate everything
- **2 clicks max** to any content

## Local Development

```bash
pip install mkdocs-material
mkdocs serve
```

## Structure

```
docs/
├── quick/          # Cheatsheets, payloads
├── vulns/          # Methodology by vuln type
├── chains/         # Attack chains
└── frameworks/     # Stack-specific guides
```

## Credits

Built on knowledge from:
- [PortSwigger Web Security Academy](https://portswigger.net/web-security)
- [HackTricks](https://book.hacktricks.xyz/)
- [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings)
- The bug bounty community

## License

MIT
