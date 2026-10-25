# WebShield AI — User Guide & Technical Documentation (English)

WebShield AI is a lightweight, defensive website security auditing tool crafted specifically for Android devices running **Termux** and standard Linux environments. It allows website owners, system administrators, and authorized ethical security testers to inspect website security configurations, identify common misconfigurations, analyze cryptographic parameters, and generate structured security reports without requiring root access.

---

## 1. Quick Installation in Termux

Open your Termux app on Android and run:

```bash
# Update Termux packages
pkg update -y && pkg upgrade -y

# Install Python 3, Git, and OpenSSL
pkg install -y python git openssl

# Clone repository
git clone https://github.com/webshield-ai/webshield-ai.git
cd webshield-ai

# Run automated installer
chmod +x install.sh run.sh
./install.sh
```

*(No root access required at any step!)*

---

## 2. CLI Command Reference

### Verify Setup & Dependencies
```bash
python3 main.py --check-config
```

### Run Full Security Audit on Authorized Target
```bash
python3 main.py --target https://your-authorized-domain.example --authorized
```
*(The `--authorized` flag is a mandatory safety safeguard confirming you own or have explicit written permission to assess the target).*

### Output Machine-Readable JSON
```bash
python3 main.py --target https://your-authorized-domain.example --authorized --json
```

### View Historical Scan Audits
```bash
python3 main.py --history
```

### Interactive Menu Mode
Simply run without arguments:
```bash
python3 main.py
```
Or:
```bash
./run.sh
```

---

## 3. Core Checks Performed

| Category | Checks Evaluated | Defensive Importance |
| :--- | :--- | :--- |
| **Safety & Anti-SSRF** | Authorization check, URL normalization, Private IP / Loopback filter | Blocks unintended scanning of local network, loopback (127.0.0.1), or cloud metadata services. |
| **TLS / SSL Cryptography** | Certificate validity, Expiry days countdown, CA trust chain, TLS protocol (TLS 1.2/1.3), Cipher suites | Prevents visitors from encountering scary browser warnings or falling victim to downgrade attacks. |
| **HTTP Security Headers** | HSTS, CSP, X-Content-Type-Options, X-Frame-Options, Referrer-Policy, Permissions-Policy | Primary defense against Cross-Site Scripting (XSS), Clickjacking, MIME sniffing, and credential leakage. |
| **DNS & Domain Hygiene** | A, AAAA, MX, NS, TXT, SPF (`v=spf1`), DMARC (`v=DMARC1`) | Validates global availability, IPv6 readiness, and email sender anti-spoofing protection. |
| **Configuration Hygiene** | HTTP-to-HTTPS automatic redirect, Server version banner disclosure, `security.txt` (RFC 9116), `robots.txt` path leakage | Eliminates easy reconnaissance leaks and ensures modern vulnerability disclosure channels. |

---

## 4. Scoring Engine (0 - 100)

WebShield AI computes a transparent, explainable security score:

$$\text{Final Score} = \max\left(0, 100 - \sum (\text{Base Penalty} \times \text{Confidence Multiplier})\right)$$

### Penalty Table:
- **Critical Risk (-25 pts)**: Expired TLS certificate, invalid root trust chain, obsolete SSLv3/TLSv1.0 protocol.
- **High Risk (-15 pts)**: Plaintext HTTP allowed without HTTPS redirect, missing HSTS on HTTPS, missing Content-Security-Policy (CSP), permissive SPF `+all`.
- **Medium Risk (-8 pts)**: Missing clickjacking protection (`X-Frame-Options` / `frame-ancestors`), missing `X-Content-Type-Options: nosniff`, permissive CSP directives (`'unsafe-inline'`), missing SPF/DMARC on mail-enabled domains.
- **Low Risk (-3 pts)**: Missing `Permissions-Policy`, missing `Referrer-Policy`, detailed web server version banner leakage.
- **Informational (0 pts)**: Verified active defensive controls, informational notes.

### Grade Thresholds:
- **A+**: 95 – 100
- **A**: 90 – 94
- **B**: 80 – 89
- **C**: 70 – 79
- **D**: 60 – 69 (or any unresolved Critical finding)
- **F**: < 60

---

## 5. Report Formats

Every scan produces three artifacts in the `reports/` folder:
1. **Interactive HTML (`.html`)**: Beautiful, self-contained dashboard report with color-coded severity badges, remediation code blocks, and verification commands.
2. **Standard JSON (`.json`)**: Machine-readable structured payload suitable for CI/CD pipelines, SIEM ingest, or custom automation.
3. **Plain Text (`.txt`)**: Terminal-friendly, ASCII-formatted audit report easy to view with `cat` or `less` in Termux.

---

## 6. Defensive Limitations & Boundaries

WebShield AI is engineered strictly for **defensive posture evaluation**:
- It **does not** perform denial-of-service (DDoS) tests.
- It **does not** execute exploits, injection payloads, or fuzzing loops.
- It **does not** attempt password guessing or credential stuffing.
- It **does not** bypass authentication barriers.
- It **does not** store or transmit scan results to external third parties. All data remains inside your local Termux SQLite database.
