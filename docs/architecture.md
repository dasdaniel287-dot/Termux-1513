# WebShield AI — System Architecture & Flow

```
+--------------------------------------------------------------------------+
|                          WebShield AI Engine                             |
+--------------------------------------------------------------------------+
                                    |
            +-----------------------+-----------------------+
            |                                               |
            v                                               v
  [ Termux / Bash CLI ]                           [ Web Dashboard UI ]
 (main.py / install.sh)                        (React / Tailwind / Node API)
            |                                               |
            +-----------------------+-----------------------+
                                    |
                                    v
                    [ SafetyManager (src/safety.py) ]
                     - Explicit Authorization Check
                     - URL Normalization & Port Whitelist
                     - Anti-SSRF Resolution & CIDR Filter
                                    |
                                    v
            +-----------------------------------------------+
            |           WebShieldScanner Orchestrator       |
            +-----------------------------------------------+
               |               |               |          |
               v               v               v          v
          [ DNSChecker ] [ TLSChecker ] [ HeaderAnalyzer ] [ ConfigAuditor ]
          - A/AAAA/MX/NS - Valid Dates  - HSTS / CSP     - HTTP -> HTTPS
          - SPF / DMARC  - Trust Chain  - XCTO / XFO     - security.txt
                         - TLS 1.2/1.3  - Ref / Perm     - robots.txt
                                    |
                                    v
                    [ ScoringEngine (src/scoring.py) ]
                     - Documented Deductions & Weights
                     - Mathematical Formula Audit Trail
                     - Confidence Multiplication
                                    |
            +-----------------------+-----------------------+
            |                                               |
            v                                               v
[ ReportGenerator (src/reports.py) ]       [ ScanDatabase (src/database.py) ]
 - HTML Interactive Report                  - SQLite Persistence (webshield.db)
 - JSON Standard Payload                    - History Queries & Export
 - Plain TXT Terminal Report
```

## Security Design Principles
1. **Zero Exploitation**: The scanner exclusively performs passive and non-destructive active probes (HEAD/GET baseline and TLS handshakes). No attack payloads, fuzzing strings, or brute force loops.
2. **SSRF Guard**: Resolves DNS beforehand; immediately rejects loopback (127.0.0.1, ::1), private subnets (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16), and link-local (169.254.0.0/16) IPs.
3. **Graceful Failures**: Network timeouts and socket errors are cleanly caught and translated into actionable findings instead of stack traces.
