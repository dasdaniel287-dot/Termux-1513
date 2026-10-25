#!/usr/bin/env bash
# WebShield AI — Automated Installation Script for Termux & Linux
# License: Apache-2.0
# Root Access: NOT REQUIRED

set -e

echo "============================================================"
echo "    WebShield AI — Automated Termux / Linux Installer"
echo "============================================================"

# Detect Termux or Standard Linux
IS_TERMUX=false
if [ -n "$PREFIX" ] && echo "$PREFIX" | grep -q "com.termux"; then
    IS_TERMUX=true
fi

echo "[*] Detecting execution environment..."
if [ "$IS_TERMUX" = true ]; then
    echo "    -> Environment: Android Termux detected ($PREFIX)"
    echo "[*] Updating package repositories..."
    pkg update -y || apt-get update -y
    echo "[*] Installing core dependencies (Python 3, Git, OpenSSL, libffi)..."
    pkg install -y python git openssl || true
else
    echo "    -> Environment: Standard Linux/Unix environment"
fi

# Step 1: Verify Python 3
echo "[*] Checking Python 3..."
if command -v python3 &>/dev/null; then
    PY_VER=$(python3 --version)
    echo "    -> Found $PY_VER"
else
    echo "[-] Error: Python 3 not found. Please install Python 3 first."
    exit 1
fi

# Step 2: Verify Git
echo "[*] Checking Git..."
if command -v git &>/dev/null; then
    echo "    -> Git is available."
else
    echo "[!] Notice: Git is not installed. You can still run WebShield AI locally."
fi

# Step 3: Install Python requirements
echo "[*] Installing Python packages (requests, rich, dnspython, pytest)..."
if [ "$IS_TERMUX" = true ]; then
    # Termux pip install
    pip install --upgrade pip || true
    pip install -r requirements.txt || pip install requests rich dnspython pytest --break-system-packages || true
else
    python3 -m pip install -r requirements.txt --break-system-packages 2>/dev/null || python3 -m pip install -r requirements.txt || true
fi

# Step 4: Create required directories
echo "[*] Creating application directories (data, reports)..."
mkdir -p data reports docs

# Step 5: Set permissions
chmod +x main.py run.sh install.sh 2>/dev/null || true

# Step 6: Run self-test verification
echo "[*] Running installation test..."
python3 main.py --check-config

echo "============================================================"
echo "  WebShield AI successfully installed on your device!"
echo "============================================================"
echo ""
echo "How to launch:"
echo "  1. Quick run:      ./run.sh"
echo "  2. Interactive:    python3 main.py"
echo "  3. Fast scan:      python3 main.py --target https://example.com --authorized"
echo "  4. View history:   python3 main.py --history"
echo "  5. Self-check:     python3 main.py --check-config"
echo ""
echo "Note: No root access is required for standard operations."
echo "============================================================"
