# WebShield AI — Advanced Website Security Checker for Termux

> A defensive, accurate, and lightweight website security assessment engine engineered to run seamlessly on Android devices via **Termux** and standard Linux environments without root access.

---

## Key Features

- **Interactive Terminal UI**: Built with `Rich` for color-coded status tables, animated progress indicators, and intuitive menus.
- **HTTP Security Header Audit**: Analyzes HSTS, Content-Security-Policy (CSP), X-Content-Type-Options, X-Frame-Options, Referrer-Policy, and Permissions-Policy with exact remediation guidance.
- **TLS/SSL Handshake Inspector**: Validates certificate chains, expiration countdowns, modern cipher suites, and flags obsolete SSLv3/TLSv1.0/1.1 protocols.
- **DNS & Domain Hygiene**: Safe queries for A, AAAA (IPv6 readiness), MX, NS, TXT, SPF (`v=spf1`), and DMARC (`v=DMARC1`).
- **Safe Configuration Checks**: Verifies automated HTTP-to-HTTPS redirects, safe robots.txt hygiene, and RFC 9116 `security.txt` vulnerability disclosure contacts.
- **Anti-SSRF & Scope Enforcement**: Strictly blocks attempts to probe private subnets (RFC 1918), loopback (`127.0.0.1`), or link-local endpoints.
- **Explainable Scoring Engine (0-100)**: Transparent, deterministic scoring with explicit formula audit trails.
- **Multi-Format Deliverables**: Generates interactive HTML, machine-readable JSON, and clean ASCII TXT reports.
- **SQLite History**: Stores past scan logs locally on device for offline review.
- **Bilingual Documentation**: Complete technical guides in both **English** and **বাংলা (Bengali)**.

---

## Termux Quickstart (Android)

```bash
# 1. Update Termux packages
pkg update -y && pkg install -y python git openssl

# 2. Clone repository
git clone https://github.com/webshield-ai/webshield-ai.git
cd webshield-ai

# 3. Install & Self-Check
chmod +x install.sh run.sh
./install.sh

# 4. Launch Assessment
python3 main.py --target https://your-authorized-domain.example --authorized
```

---

## Example Commands

```bash
# Check installed dependencies and Termux environment
python3 main.py --check-config

# Run security scan on an authorized domain
python3 main.py --target https://example.com --authorized

# Get results formatted as JSON
python3 main.py --target https://example.com --authorized --json

# View past assessment history stored in SQLite
python3 main.py --history

# Launch interactive menu
python3 main.py
```

---

## Repository Structure

```
webshield-ai/
├── main.py                 # CLI entry point with Rich terminal UI
├── requirements.txt        # Python dependency manifest
├── install.sh              # Termux/Linux automated installer
├── run.sh                  # Quick executable runner
├── README.md               # GitHub documentation
├── .gitignore              # Git ignore rules
├── .env.example            # Environment sample
├── src/
│   ├── scanner.py          # Core scanning orchestrator
│   ├── headers.py          # HTTP security header analyzer
│   ├── tls_checker.py      # Cryptographic TLS/SSL validator
│   ├── dns_checker.py      # DNS record & SPF/DMARC auditor
│   ├── safety.py           # Authorization & anti-SSRF guardrails
│   ├── scoring.py          # 0-100 explainable security score
│   ├── reports.py          # HTML, JSON, TXT generator
│   └── database.py         # SQLite persistence engine
├── tests/                  # Pytest automated test suite
├── reports/                # Generated audit reports
└── docs/                   # Full documentation (English & বাংলা)
```

---

## Running Automated Tests

```bash
pytest tests/
```

All 14 unit and integration tests execute entirely with mock fixtures and local test sockets without making external unauthorized network calls.

---

## Defensive Scope & Safety Policy

WebShield AI is developed exclusively for authorized security verification and defensive posture hardening:
- Does not contain DDoS, brute-forcing, password spraying, or unauthorized exploitation mechanisms.
- Requires explicit user consent before scanning.
- Keeps all audit results private to your device.
