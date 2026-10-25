#!/usr/bin/env python3
"""
WebShield AI — Advanced Website Security Checker for Termux & Linux
Author: WebShield AI Team
License: Apache-2.0
"""

import sys
import os
import argparse
import json
import time

# Ensure src package is in path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from src.scanner import WebShieldScanner
from src.safety import SafetyViolation
from src.database import ScanDatabase

VERSION = "1.0.0"

BANNER = r"""
 [1;36m__        __   _     ____  _     _      _     _       _    ___ [0m
 [1;36m\ \      / /__| |__ / ___|| |__ (_) ___| | __| |     / \  |_ _|[0m
 [1;36m \ \ /\ / / _ \ '_ \\___ \| '_ \| |/ _ \ |/ _` |    / _ \  | | [0m
 [1;36m  \ V  V /  __/ |_) |___) | | | | |  __/ | (_| |   / ___ \ | | [0m
 [1;36m   \_/\_/ \___|_.__/|____/|_| |_|_|\___|_|\__,_|  /_/   \_\___|[0m
 [1;32m   Advanced Website Security Configuration Checker for Termux [0m
 [1;33m                      Version 1.0.0 (Defensive Edition)        [0m
"""

def print_banner():
    print(BANNER)

def check_system_configuration():
    """Validates Termux / Linux local environment for WebShield AI."""
    print("\n🔍 Checking WebShield AI Local Configuration & Termux Environment:")
    print("  • Python Version      : " + sys.version.split()[0] + " (Compatible)")
    print("  • Operating System    : " + sys.platform)
    is_termux = "com.termux" in os.environ.get("PREFIX", "") or "termux" in os.environ.get("PATH", "")
    print("  • Android / Termux    : " + ("Detected [Android Termux]" if is_termux else "Standard Linux/POSIX"))
    print("  • Root Access Required: No (Safe non-root operations)")

    # Test libraries
    for mod, name in [
        ("requests", "Requests (HTTP Client)"),
        ("rich", "Rich (Terminal UI)"),
        ("dns.resolver", "dnspython (DNS Resolver)"),
        ("sqlite3", "SQLite3 (Audit History)"),
        ("ssl", "Python SSL (TLS Handshake)"),
    ]:
        try:
            __import__(mod)
            print(f"  • {name:<26}: [OK] Available")
        except ImportError:
            print(f"  • {name:<26}: [WARN] Not installed (Run: pip install -r requirements.txt)")

    # Check directories
    base_dir = os.path.dirname(os.path.abspath(__file__))
    data_dir = os.path.join(base_dir, "data")
    reports_dir = os.path.join(base_dir, "reports")
    os.makedirs(data_dir, exist_ok=True)
    os.makedirs(reports_dir, exist_ok=True)
    print(f"  • Storage Directories : [OK] Initialized ({data_dir}, {reports_dir})")
    print("\n✅ System configuration check passed! Ready to audit authorized targets.\n")

def run_cli_scan(target_url: str, authorized: bool, output_json: bool = False):
    """Executes scan from command line."""
    scanner = WebShieldScanner()

    if not output_json:
        print_banner()
        print(f"\n🎯 Target URL: {target_url}")
        print("🔒 Authorization Mode: Explicit Permission Confirmed")
        print("⏳ Initiating safe non-destructive assessment...\n")

    def cli_progress(step: str, pct: int, msg: str):
        if not output_json:
            bar_length = 25
            filled = int(bar_length * pct // 100)
            bar = "█" * filled + "░" * (bar_length - filled)
            sys.stdout.write(f"\r  [{bar}] {pct:>3}% | {step:<16} : {msg[:40]:<40}")
            sys.stdout.flush()

    try:
        result = scanner.run_scan(
            target_url=target_url,
            user_confirmed_authorization=authorized,
            progress_callback=cli_progress if not output_json else None,
        )
        if not output_json:
            sys.stdout.write("\n\n")
            _display_results_terminal(result)
        else:
            print(json.dumps(result, indent=2))
    except SafetyViolation as sv:
        if output_json:
            print(json.dumps({"error": "SafetyViolation", "message": str(sv)}))
        else:
            print(f"\n\n❌ [SAFETY ABORT] {sv}\n")
        sys.exit(1)
    except Exception as e:
        if output_json:
            print(json.dumps({"error": "ScanError", "message": str(e)}))
        else:
            print(f"\n\n❌ [EXECUTION ERROR] {e}\n")
        sys.exit(1)

def _display_results_terminal(result: dict):
    """Renders formatted results in terminal."""
    score_data = result.get("score_data", {})
    score = score_data.get("score", 0)
    grade = score_data.get("grade", "N/A")
    counts = score_data.get("counts", {})
    findings = result.get("findings", [])

    print("=" * 76)
    print(f"  ASSESSMENT COMPLETE: {result.get('domain')}")
    print(f"  Security Score: {score} / 100   Grade: {grade}   Time: {result.get('duration_seconds')}s")
    print(f"  Findings: Critical: {counts.get('Critical', 0)} | High: {counts.get('High', 0)} | "
          f"Med: {counts.get('Medium', 0)} | Low: {counts.get('Low', 0)} | Info: {counts.get('Informational', 0)}")
    print("=" * 76)
    print(f"\n{score_data.get('explanation')}\n")

    print("📋 SUMMARY OF KEY FINDINGS:")
    print("-" * 76)
    if not findings:
        print("  🎉 No security misconfigurations identified.")
    else:
        for idx, f in enumerate(findings, 1):
            sev = f.get("severity", "Info")
            color = (
                "\033[91m" if sev == "Critical" else
                "\033[31m" if sev == "High" else
                "\033[33m" if sev == "Medium" else
                "\033[34m" if sev == "Low" else "\033[90m"
            )
            reset = "\033[0m"
            print(f"  [{idx}] {color}[{sev.upper():<8}]{reset} {f.get('check_name')}")
            print(f"      Component : {f.get('affected_component')}")
            print(f"      Evidence  : {f.get('evidence')}")
            print(f"      Fix       : {f.get('recommended_fix')}\n")

    report_paths = result.get("report_paths", {})
    print("-" * 76)
    print("📁 GENERATED REPORTS:")
    print(f"  • HTML Report : {report_paths.get('html')}")
    print(f"  • JSON Report : {report_paths.get('json')}")
    print(f"  • TXT Report  : {report_paths.get('txt')}")
    print("=" * 76 + "\n")

def list_history():
    """Lists past scans from SQLite database."""
    db = ScanDatabase()
    scans = db.get_all_scans(limit=20)
    print_banner()
    print("\n📜 RECENT SCAN HISTORY (SQLite):")
    print("-" * 76)
    if not scans:
        print("  No previous scan records found. Run a new scan using --target <url>.")
    else:
        print(f"  {'ID':<16} {'DATE':<20} {'DOMAIN':<22} {'SCORE':<7} {'GRADE':<5}")
        print("  " + "-" * 72)
        for s in scans:
            score = str(s.get("score") or "N/A")
            print(f"  {s.get('id'):<16} {s.get('timestamp')[:19]:<20} {s.get('domain')[:20]:<22} {score:<7} {s.get('grade') or 'N/A':<5}")
    print("-" * 76 + "\n")

def interactive_menu():
    """Interactive command menu for Termux users."""
    print_banner()
    print("  [1] Scan an Authorized Website")
    print("  [2] View Recent Scan History")
    print("  [3] Check Termux Environment & Dependencies")
    print("  [4] Read Documentation (English)")
    print("  [5] Read Documentation (বাংলা / Bengali)")
    print("  [6] Exit")
    print("-" * 55)

    try:
        choice = input("Select an option [1-6]: ").strip()
    except (KeyboardInterrupt, EOFError):
        print("\nExiting.")
        sys.exit(0)

    if choice == "1":
        print("\n⚠️  LEGAL & AUTHORIZATION NOTICE:")
        print("You must have explicit authorization or ownership to scan the target.")
        try:
            target = input("Enter target website URL (e.g. https://example.com): ").strip()
            confirm = input("Do you confirm authorized testing permission? (y/n): ").strip().lower()
        except (KeyboardInterrupt, EOFError):
            print("\nCancelled.")
            sys.exit(0)

        if confirm != "y":
            print("Scan aborted: Authorization not confirmed.")
            sys.exit(1)
        run_cli_scan(target, authorized=True)
    elif choice == "2":
        list_history()
    elif choice == "3":
        check_system_configuration()
    elif choice == "4":
        doc_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "docs", "en.md")
        if os.path.exists(doc_path):
            with open(doc_path, "r", encoding="utf-8") as f:
                print(f.read())
        else:
            print("English documentation located in docs/en.md")
    elif choice == "5":
        doc_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "docs", "bn.md")
        if os.path.exists(doc_path):
            with open(doc_path, "r", encoding="utf-8") as f:
                print(f.read())
        else:
            print("Bengali documentation located in docs/bn.md")
    else:
        print("Goodbye!")
        sys.exit(0)

def main():
    parser = argparse.ArgumentParser(
        description="WebShield AI — Advanced Website Security Checker for Termux",
        epilog="Example: python3 main.py --target https://your-domain.example --authorized"
    )
    parser.add_argument("--target", "-t", type=str, help="Target website URL to assess")
    parser.add_argument("--authorized", "-a", action="store_true", help="Confirm ownership or explicit testing authorization")
    parser.add_argument("--check-config", action="store_true", help="Verify Termux / Python environment dependencies")
    parser.add_argument("--history", action="store_true", help="Display scan history from SQLite database")
    parser.add_argument("--json", action="store_true", help="Output machine-readable JSON results")
    parser.add_argument("--version", "-v", action="version", version=f"WebShield AI v{VERSION}")

    args = parser.parse_args()

    if args.check_config:
        check_system_configuration()
    elif args.history:
        list_history()
    elif args.target:
        if not args.authorized:
            print("❌ Error: Missing --authorized flag. You must certify testing permission before scanning.")
            sys.exit(1)
        run_cli_scan(args.target, authorized=True, output_json=args.json)
    else:
        # If no arguments provided, launch interactive menu
        interactive_menu()

if __name__ == "__main__":
    main()
